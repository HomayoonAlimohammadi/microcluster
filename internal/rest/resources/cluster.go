package resources

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	dqliteClient "github.com/canonical/go-dqlite/v3/client"
	"github.com/canonical/lxd/shared"
	"github.com/canonical/lxd/shared/api"
	"github.com/gorilla/mux"
	"golang.org/x/sys/unix"

	"github.com/canonical/microcluster/v3/internal/cluster"
	"github.com/canonical/microcluster/v3/internal/log"
	"github.com/canonical/microcluster/v3/internal/rest/access"
	internalClient "github.com/canonical/microcluster/v3/internal/rest/client"
	internalState "github.com/canonical/microcluster/v3/internal/state"
	"github.com/canonical/microcluster/v3/internal/utils"
	"github.com/canonical/microcluster/v3/microcluster/types"
)

var clusterCmd = types.Endpoint{
	Path: "cluster",

	Get: types.EndpointAction{Handler: clusterGet, AccessHandler: access.AllowAuthenticated},
}

var clusterInternalCmd = types.Endpoint{
	Path: "cluster",

	Post: types.EndpointAction{Handler: clusterPost, AllowUntrusted: true},
}

var clusterMemberCmd = types.Endpoint{
	Path: "cluster/{name}",

	Delete: types.EndpointAction{Handler: clusterMemberDelete, AccessHandler: access.AllowAuthenticated},
}

var clusterMemberInternalCmd = types.Endpoint{
	Path: "cluster/{name}",

	Put: types.EndpointAction{Handler: clusterMemberPut, AccessHandler: access.AllowAuthenticated},
}

func clusterPost(s types.State, r *http.Request) types.Response {
	err := s.Database().IsOpen(r.Context())
	if err != nil {
		return types.SmartError(err)
	}

	req := types.ClusterMember{}

	// Parse the request.
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return types.BadRequest(err)
	}

	ctx := r.Context()

	leaderClient, err := s.Database().Leader(ctx)
	if err != nil {
		return types.SmartError(err)
	}

	leaderInfo, err := leaderClient.Leader(ctx)
	if err != nil {
		return types.SmartError(err)
	}

	err = utils.ValidateFQDN(req.Name)
	if err != nil {
		return types.SmartError(fmt.Errorf("Cluster member name %q is not a valid FQDN: %w", req.Name, err))
	}

	// Check if any of the remote's addresses are currently in use.
	existingRemote := s.Truststore().RemoteByAddress(req.Address)
	if existingRemote != nil {
		return types.SmartError(fmt.Errorf("Remote with address %q exists", req.Address.String()))
	}

	// Check cluster membership consistency before allowing joins
	// This ensures core_cluster_members, truststore, and dqlite are all in sync
	intState, err := internalState.ToInternal(s)
	if err != nil {
		return types.SmartError(err)
	}

	err = intState.CheckMembershipConsistency(ctx)
	if err != nil {
		return types.SmartError(err)
	}

	// Forward request to leader.
	if leaderInfo.Address != s.Address().Host {
		client, err := s.Connect().Leader(false)
		if err != nil {
			return types.SmartError(err)
		}

		tokenResponse, err := internalClient.AddClusterMember(ctx, client, req)
		if err != nil {
			return types.SmartError(err)
		}

		return types.SyncResponse(true, tokenResponse)
	}

	// Check if the joining node's extensions are compatible with the leader's.
	err = intState.Extensions.IsSameVersion(req.Extensions)
	if err != nil {
		return types.SmartError(err)
	}

	err = s.Database().Transaction(r.Context(), func(ctx context.Context, tx *sql.Tx) error {
		dbClusterMember := cluster.CoreClusterMember{
			Name:           req.Name,
			Address:        req.Address.String(),
			Certificate:    req.Certificate.String(),
			SchemaInternal: req.SchemaInternalVersion,
			SchemaExternal: req.SchemaExternalVersion,
			APIExtensions:  req.Extensions,
			Heartbeat:      time.Time{},
			Role:           cluster.Pending,
		}

		record, err := cluster.GetCoreTokenRecord(ctx, tx, req.Secret)
		if err != nil {
			return err
		}

		if record.Expired() {
			return fmt.Errorf("Token expired")
		}

		if !slices.Contains(req.Certificate.DNSNames, record.Name) {
			return fmt.Errorf("Joining server certificate SAN does not contain join token name")
		}

		_, err = cluster.CreateCoreClusterMember(ctx, tx, dbClusterMember)
		if err != nil {
			return err
		}

		return cluster.DeleteCoreTokenRecord(ctx, tx, record.Name)
	})
	if err != nil {
		return types.SmartError(err)
	}

	remotes := s.Truststore()
	clusterMembers := make([]types.ClusterMemberLocal, 0, remotes.Count())
	for _, clusterMember := range remotes.RemotesByName() {
		clusterMember := types.ClusterMemberLocal{
			Name:        clusterMember.Name,
			Address:     clusterMember.Address,
			Certificate: clusterMember.Certificate,
		}

		clusterMembers = append(clusterMembers, clusterMember)
	}

	clusterCert, err := s.ClusterCert().PublicKeyX509()
	if err != nil {
		return types.SmartError(err)
	}

	localRemote := remotes.RemotesByName()[s.Name()]
	tokenResponse := types.TokenResponse{
		ClusterCert: types.X509Certificate{Certificate: clusterCert},
		ClusterKey:  string(s.ClusterCert().PrivateKey()),

		TrustedMember:  types.ClusterMemberLocal{Name: s.Name(), Address: localRemote.Address, Certificate: localRemote.Certificate},
		ClusterMembers: clusterMembers,
	}

	newRemote := types.Remote{
		Location:    types.Location{Name: req.Name, Address: req.Address},
		Certificate: req.Certificate,
	}

	// Add the cluster member to our local store for authentication.
	err = s.Truststore().Add(s.FileSystem().TrustDir(), newRemote)
	if err != nil {
		return types.SmartError(err)
	}

	tokenResponse.ClusterAdditionalCerts = make(map[string]types.KeyPair)

	// Load the list of custom certificates from its state directory.
	err = filepath.WalkDir(s.FileSystem().CertificatesDir(), func(path string, d fs.DirEntry, err error) error {
		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Find all .crt files to create a list of custom certificates.
		splittedPath := strings.Split(filepath.Base(path), ".")
		if len(splittedPath) == 2 && splittedPath[1] == "crt" {
			// Load the certificate
			cert, err := shared.KeyPairAndCA(s.FileSystem().CertificatesDir(), splittedPath[0], shared.CertServer, shared.CertOptions{})
			if err != nil {
				return fmt.Errorf("Failed to load certificate for additional server %q: %w", splittedPath[0], err)
			}

			additionalCertificate := types.KeyPair{
				Cert: string(cert.PublicKey()),
				Key:  string(cert.PrivateKey()),
			}

			if cert.CA() != nil {
				additionalCertificate.CA = string(cert.CA().Raw)
			}

			tokenResponse.ClusterAdditionalCerts[splittedPath[0]] = additionalCertificate
		}

		return nil
	})
	if err != nil {
		return types.SmartError(err)
	}

	return types.SyncResponse(true, tokenResponse)
}

func clusterGet(s types.State, r *http.Request) types.Response {
	status := s.Database().Status()

	// If the database is not in a ready or waiting state, we can't be sure it's available for use.
	if status != types.DatabaseReady && status != types.DatabaseWaiting {
		return types.SmartError(api.StatusErrorf(http.StatusServiceUnavailable, "%s", string(status)))
	}

	var apiClusterMembers []types.ClusterMember
	err := s.Database().Transaction(r.Context(), func(ctx context.Context, tx *sql.Tx) error {
		var err error
		var clusterMembers []cluster.CoreClusterMember
		var awaitingUpgrade map[string]bool
		if status == types.DatabaseReady {
			clusterMembers, err = cluster.GetCoreClusterMembers(ctx, tx)
		} else {
			schemaInternal, schemaExternal, apiExtensions := s.Database().SchemaVersion()
			clusterMembers, awaitingUpgrade, err = cluster.GetUpgradingClusterMembers(ctx, tx, schemaInternal, schemaExternal, apiExtensions)
		}

		if err != nil {
			return err
		}

		apiClusterMembers = make([]types.ClusterMember, 0, len(clusterMembers))
		for _, clusterMember := range clusterMembers {
			apiClusterMember, err := clusterMember.ToAPI()
			if err != nil {
				return err
			}

			// Assign an upgrade status if the cluster member is awaiting an upgrade.
			if awaitingUpgrade != nil {
				if awaitingUpgrade[apiClusterMember.Name] {
					apiClusterMember.Status = types.MemberNeedsUpgrade
				} else {
					apiClusterMember.Status = types.MemberUpgrading
				}
			}

			apiClusterMembers = append(apiClusterMembers, *apiClusterMember)
		}

		return nil
	})
	if err != nil {
		return types.SmartError(fmt.Errorf("Failed to get cluster members: %w", err))
	}

	// Send a small request to each node to ensure they are reachable if the database is fully online.
	if status == types.DatabaseReady {
		clusterCert, err := s.ClusterCert().PublicKeyX509()
		if err != nil {
			return types.SmartError(err)
		}

		for i, clusterMember := range apiClusterMembers {
			addr := &api.NewURL().Scheme("https").Host(clusterMember.Address.String()).URL
			d, err := internalClient.New(addr, s.ServerCert(), clusterCert, false)
			if err != nil {
				return types.SmartError(fmt.Errorf("Failed to create HTTPS client for cluster member with address %q: %w", addr.String(), err))
			}

			err = internalClient.CheckReady(r.Context(), d)
			if err == nil {
				apiClusterMembers[i].Status = types.MemberOnline
			} else {
				logger, logErr := log.LoggerFromContext(r.Context())
				if logErr != nil {
					return types.InternalError(err)
				}

				logger.Warn(fmt.Sprintf("Failed to get status of cluster member with address %q: %v", addr.String(), err))
			}
		}
	}

	return types.SyncResponse(true, apiClusterMembers)
}

// clusterDisableMu is used to prevent the daemon process from being replaced/stopped during removal from the
// cluster until such time as the request that initiated the removal has finished. This allows for self removal
// from the cluster when not the leader.
var clusterDisableMu sync.Mutex

func clusterMemberPut(s types.State, r *http.Request) types.Response {
	force := r.URL.Query().Get("force") == "1"
	reExec, err := resetClusterMember(r.Context(), s, force)
	if err != nil {
		return types.SmartError(err)
	}

	go reExec()

	return types.ManualResponse(func(w http.ResponseWriter) error {
		err := types.EmptySyncResponse.Render(w, r)
		if err != nil {
			return err
		}

		// Send the response before replacing the LXD daemon process.
		f, ok := w.(http.Flusher)
		if !ok {
			return fmt.Errorf("ResponseWriter is not type http.Flusher")
		}

		f.Flush()
		return nil
	})
}

// resetClusterMember clears the daemon state, closing the database and stopping all listeners.
// Returns a function that can be used to re-exec the daemon, forcibly reloading its state.
func resetClusterMember(ctx context.Context, s types.State, force bool) (reExec func(), err error) {
	intState, err := internalState.ToInternal(s)
	if err != nil {
		return nil, err
	}

	logger, err := log.LoggerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	reExec = func() {
		<-ctx.Done() // Wait until request has finished.

		// NOTE(claudiub): In the case we fail to bootstrap / join the cluster, or if we remove the node
		// from the cluster, we'll be resetting the node's cluster membership. This includes closing the
		// HTTPS and unix socket servers we have open.
		// However, we cannot gracefully shutdown the servers, as there's at least one connection that is
		// still open: the bootstrap / join request. Forcing the connection to close before we're able
		// to write the request response will result in the client getting an EOF error, and no information
		// regarding the failure.
		// Gracefully shutting down the servers in a goroutine will address this issue: while this action
		// happens, we'll be able to write the HTTP response and then close the connection, finally
		// allowing the servers to gracefully shutdown, and the clients to be happy.
		// As the daemon gets re-executed the returned exit function can be ignored as it used to signal
		// a complete shutdown.
		_, err := intState.Stop()
		if err != nil && !force {
			logger.Error("Failed shutting down", slog.String("error", err.Error()))
		}

		err = os.RemoveAll(s.FileSystem().StateDir())
		if err != nil && !force {
			logger.Error("Failed to remove the state directory", slog.String("error", err.Error()))
		}

		// Wait until we can acquire the lock. This way if another request is holding the lock we won't
		// replace/stop the LXD daemon until that request has finished.
		clusterDisableMu.Lock()
		defer clusterDisableMu.Unlock()
		execPath, err := os.Readlink("/proc/self/exe")
		if err != nil {
			execPath = "bad-exec-path"
		}

		// The execPath from /proc/self/exe can end with " (deleted)" if the lxd binary has been removed/changed
		// since the lxd process was started, strip this so that we only return a valid path.
		logger.Info("Restarting daemon following removal from cluster")
		execPath = strings.TrimSuffix(execPath, " (deleted)")
		err = unix.Exec(execPath, os.Args, os.Environ())
		if err != nil {
			logger.Error("Failed restarting daemon", slog.String("error", err.Error()))
		}
	}

	return reExec, nil
}

// clusterMemberDelete Removes a cluster member from dqlite and re-execs its daemon.
func clusterMemberDelete(s types.State, r *http.Request) types.Response {
	force := r.URL.Query().Get("force") == "1"
	addr := r.URL.Query().Get("address")
	name, err := url.PathUnescape(mux.Vars(r)["name"])
	if err != nil {
		slog.Error("[clusterMemberDelete] Failed to unescape member name from URL path", slog.String("error", err.Error()))
		return types.SmartError(fmt.Errorf("Failed to unescape member name: %w", err))
	}

	ctx := r.Context()

	// Use a fallback logger so logging always works even if context has no logger.
	logger, err := log.LoggerFromContext(ctx)
	if err != nil {
		logger = slog.Default()
		logger.Warn("[clusterMemberDelete] Could not extract logger from context, using default logger", slog.String("error", err.Error()))
	}

	logger.Info("[clusterMemberDelete] START", slog.String("member", name), slog.String("addr_param", addr), slog.Bool("force", force), slog.String("self_address", s.Address().Host))

	if ctx.Err() != nil {
		logger.Error("[clusterMemberDelete] Context already cancelled at entry", slog.String("ctx_err", ctx.Err().Error()))
	}

	allRemotes := s.Truststore().RemotesByName()
	remote, remotePresent := allRemotes[name]
	logger.Info("[clusterMemberDelete] Truststore lookup done", slog.String("member", name), slog.Bool("remotePresent", remotePresent), slog.Int("total_remotes", len(allRemotes)))

	// Determine the address to use for dqlite removal:
	// - If remote exists in truststore and no address provided, use the truststore address.
	// - If remote missing and no address provided, require explicit address.
	// - If address provided, it must match the truststore address (if remote exists) or be valid (if not).
	if remotePresent && addr == "" {
		addr = remote.Address.String()
		logger.Info("[clusterMemberDelete] Using truststore address for remote", slog.String("member", name), slog.String("addr", addr))
	} else if !remotePresent && addr == "" {
		// If the remote is not present in the truststore and no address is provided, we cannot proceed.
		logger.Error("[clusterMemberDelete] Remote not in truststore and no address provided", slog.String("member", name))
		return types.SmartError(fmt.Errorf("Cluster member %q not found in truststore; please provide a node address", name))
	} else if remotePresent && addr != "" && remote.Address.String() != addr {
		// Reject if provided address doesn't match the truststore address for this remote name.
		logger.Error("[clusterMemberDelete] Provided address mismatch with truststore", slog.String("member", name), slog.String("provided", addr), slog.String("truststore", remote.Address.String()))
		return types.SmartError(fmt.Errorf("Provided address %q does not match the address %q of the remote with name %q", addr, remote.Address.String(), name))
	} else if !remotePresent && addr != "" {
		logger.Info("[clusterMemberDelete] Remote not in truststore, validating fallback address", slog.String("member", name), slog.String("addr", addr))
		// Remote missing from truststore; validate the fallback address format.
		addrPort, err := types.ParseAddrPort(addr)
		if err != nil {
			logger.Error("[clusterMemberDelete] Invalid fallback address", slog.String("addr", addr), slog.String("error", err.Error()))
			return types.SmartError(fmt.Errorf("Invalid address %q: %w", addr, err))
		}

		// Ensure the fallback address isn't claimed by another remote in the truststore.
		existingRemote := s.Truststore().RemoteByAddress(addrPort)
		if existingRemote != nil {
			logger.Error("[clusterMemberDelete] Fallback address already claimed by another remote", slog.String("addr", addr), slog.String("existing_remote", existingRemote.Name))
			return types.SmartError(fmt.Errorf("Address %q is already used by remote %q (address %q); address is only a fallback for %q when it is missing from the truststore", addr, existingRemote.Name, existingRemote.Address.String(), name))
		}

		logger.Warn("[clusterMemberDelete] Cluster member not found in truststore; proceeding with provided fallback address", slog.String("member", name), slog.String("address", addr))
	}

	logger.Info("[clusterMemberDelete] Resolved address for member", slog.String("member", name), slog.String("addr", addr))

	// Check cluster membership consistency before allowing removals (unless forced)
	// This ensures core_cluster_members, truststore, and dqlite are all in sync
	if !force {
		logger.Info("[clusterMemberDelete] Checking membership consistency (not forced)")
		intState, err := internalState.ToInternal(s)
		if err != nil {
			logger.Error("[clusterMemberDelete] Failed to get internal state for consistency check", slog.String("error", err.Error()))
			return types.SmartError(fmt.Errorf("Failed to get internal state for consistency check: %w", err))
		}

		err = intState.CheckMembershipConsistency(ctx)
		if err != nil {
			logger.Error("[clusterMemberDelete] Membership consistency check failed", slog.String("error", err.Error()))
			return types.SmartError(fmt.Errorf("Membership consistency check failed: %w", err))
		}

		logger.Info("[clusterMemberDelete] Membership consistency check passed")
	} else {
		logger.Info("[clusterMemberDelete] Skipping membership consistency check (forced)")
	}

	if ctx.Err() != nil {
		logger.Error("[clusterMemberDelete] Context cancelled after consistency check", slog.String("ctx_err", ctx.Err().Error()))
	}

	logger.Info("[clusterMemberDelete] Getting database leader")
	leader, err := s.Database().Leader(ctx)
	if err != nil {
		logger.Error("[clusterMemberDelete] Failed to get database leader", slog.String("error", err.Error()))
		return types.SmartError(fmt.Errorf("Failed to get database leader: %w", err))
	}

	logger.Info("[clusterMemberDelete] Getting leader info")
	leaderInfo, err := leader.Leader(ctx)
	if err != nil {
		logger.Error("[clusterMemberDelete] Failed to get leader info", slog.String("error", err.Error()))
		return types.SmartError(fmt.Errorf("Failed to get leader info: %w", err))
	}

	logger.Info("[clusterMemberDelete] Leader info retrieved", slog.String("leader_address", leaderInfo.Address), slog.String("self_address", s.Address().Host))

	// If we are not the leader, just forward the request.
	if leaderInfo.Address != s.Address().Host {
		logger.Info("[clusterMemberDelete] We are NOT the leader, forwarding request", slog.String("leader_address", leaderInfo.Address), slog.String("self_address", s.Address().Host))

		if addr == s.Address().Host {
			// If the member being removed is ourselves and we are not the leader, then lock the
			// clusterPutDisableMu before we forward the request to the leader, so that when the leader
			// goes on to request clusterPutDisable back to ourselves it won't be actioned until we
			// have returned this request back to the original client.
			logger.Info("[clusterMemberDelete] Member being removed is self (non-leader), acquiring self removal lock", slog.String("member", name))
			clusterDisableMu.Lock()
			logger.Info("[clusterMemberDelete] Acquired cluster self removal lock", slog.String("member", name))

			go func() {
				<-r.Context().Done() // Wait until request is finished.

				logger.Info("[clusterMemberDelete] Request context done, releasing cluster self removal lock", slog.String("member", name), slog.String("ctx_err", r.Context().Err().Error()))
				clusterDisableMu.Unlock()
			}()
		}

		logger.Info("[clusterMemberDelete] Connecting to leader to forward delete request")
		client, err := s.Connect().Leader(false)
		if err != nil {
			logger.Error("[clusterMemberDelete] Failed to connect to leader for forwarding", slog.String("error", err.Error()))
			return types.SmartError(fmt.Errorf("Failed to connect to leader for forwarding: %w", err))
		}

		logger.Info("[clusterMemberDelete] Forwarding DeleteClusterMember to leader", slog.String("member", name), slog.String("addr", addr), slog.Bool("force", force))
		if ctx.Err() != nil {
			logger.Error("[clusterMemberDelete] Context cancelled BEFORE forwarding to leader", slog.String("ctx_err", ctx.Err().Error()))
		}

		err = internalClient.DeleteClusterMember(ctx, client, name, addr, force)
		if err != nil {
			logger.Error("[clusterMemberDelete] Failed forwarding DeleteClusterMember to leader", slog.String("member", name), slog.String("error", err.Error()))
			if ctx.Err() != nil {
				logger.Error("[clusterMemberDelete] Context state after forward failure", slog.String("ctx_err", ctx.Err().Error()))
			}

			return types.SmartError(fmt.Errorf("Failed forwarding DeleteClusterMember to leader: %w", err))
		}

		logger.Info("[clusterMemberDelete] Successfully forwarded DeleteClusterMember to leader, returning response", slog.String("member", name))
		return types.ManualResponse(func(w http.ResponseWriter) error {
			err := types.EmptySyncResponse.Render(w, r)
			if err != nil {
				return fmt.Errorf("Failed rendering empty sync response after forward: %w", err)
			}

			// Send the response before replacing the LXD daemon process.
			f, ok := w.(http.Flusher)
			if !ok {
				return fmt.Errorf("ResponseWriter is not type http.Flusher")
			}

			f.Flush()
			return nil
		})
	}

	logger.Info("[clusterMemberDelete] We ARE the leader, processing delete locally", slog.String("member", name), slog.String("addr", addr))

	logger.Info("[clusterMemberDelete] Getting dqlite cluster info")
	info, err := leader.Cluster(ctx)
	if err != nil {
		logger.Error("[clusterMemberDelete] Failed to get dqlite cluster info", slog.String("error", err.Error()))
		return types.SmartError(fmt.Errorf("Failed to get dqlite cluster info: %w", err))
	}

	logger.Info("[clusterMemberDelete] Dqlite cluster info retrieved", slog.Int("node_count", len(info)))
	for i, node := range info {
		logger.Info("[clusterMemberDelete] Dqlite node", slog.Int("index", i), slog.Uint64("id", node.ID), slog.String("address", node.Address), slog.Int("role", int(node.Role)))
	}

	index := -1
	for i, node := range info {
		if node.Address == addr {
			index = i
			break
		}
	}

	logger.Info("[clusterMemberDelete] Dqlite node lookup result", slog.String("member", name), slog.String("addr", addr), slog.Int("dqlite_index", index))

	// If we can't find the node in dqlite, that means it failed to fully initialize. It still might have a record in our database so continue along anyway.
	if index < 0 {
		logger.Error("[clusterMemberDelete] No dqlite record exists for the member", slog.String("member", name), slog.String("addr", addr))
	}

	if ctx.Err() != nil {
		logger.Error("[clusterMemberDelete] Context cancelled before DB transaction to get cluster members", slog.String("ctx_err", ctx.Err().Error()))
	}

	logger.Info("[clusterMemberDelete] Getting cluster members from database")
	var clusterMembers []cluster.CoreClusterMember
	err = s.Database().Transaction(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		clusterMembers, err = cluster.GetCoreClusterMembers(ctx, tx)

		return err
	})
	if err != nil {
		logger.Error("[clusterMemberDelete] Failed to get cluster members from DB", slog.String("error", err.Error()))
		return types.SmartError(fmt.Errorf("Failed to get cluster members from DB: %w", err))
	}

	logger.Info("[clusterMemberDelete] Retrieved cluster members from DB", slog.Int("count", len(clusterMembers)))
	for _, m := range clusterMembers {
		logger.Info("[clusterMemberDelete] DB cluster member", slog.String("name", m.Name), slog.String("address", m.Address), slog.String("role", string(m.Role)))
	}

	// Check if member exists in the database.
	memberInDB := false
	for _, m := range clusterMembers {
		if m.Address == addr {
			memberInDB = true
			break
		}
	}

	logger.Info("[clusterMemberDelete] Member DB lookup result", slog.String("member", name), slog.String("addr", addr), slog.Bool("memberInDB", memberInDB))

	// If member not found in dqlite and not in database, return error.
	if index < 0 && !memberInDB {
		logger.Error("[clusterMemberDelete] Member not found in dqlite or database", slog.String("member", name), slog.String("addr", addr))
		return types.SmartError(fmt.Errorf("Cluster member %q with address %q not found in dqlite or database", name, addr))
	}

	numPending := 0
	for _, clusterMember := range clusterMembers {
		if clusterMember.Role == cluster.Pending {
			numPending++
		}
	}

	logger.Info("[clusterMemberDelete] Cluster member counts", slog.Int("total", len(clusterMembers)), slog.Int("pending", numPending), slog.Int("non_pending", len(clusterMembers)-numPending))

	if len(clusterMembers)-numPending < 1 {
		logger.Error("[clusterMemberDelete] No remaining non-pending members")
		return types.SmartError(fmt.Errorf("Cannot remove cluster members, there are no remaining non-pending members"))
	}

	if len(info) < 2 {
		logger.Error("[clusterMemberDelete] Cannot leave cluster with fewer than 2 dqlite members", slog.Int("dqlite_members", len(info)))
		return types.SmartError(fmt.Errorf("Cannot leave a cluster with %d members", len(info)))
	}

	// If we are removing the leader of a 2-node cluster, ensure the remaining node is a voter.
	if len(info) == 2 && addr == leaderInfo.Address {
		logger.Info("[clusterMemberDelete] Removing leader in 2-node cluster, ensuring remaining node is a voter")
		for _, node := range info {
			if node.Address != leaderInfo.Address && node.Role != dqliteClient.Voter {
				logger.Info("[clusterMemberDelete] Assigning voter role to remaining node", slog.Uint64("node_id", node.ID), slog.String("node_address", node.Address))
				err = leader.Assign(ctx, node.ID, dqliteClient.Voter)
				if err != nil {
					logger.Error("[clusterMemberDelete] Failed to assign voter role", slog.Uint64("node_id", node.ID), slog.String("error", err.Error()))
					return types.SmartError(fmt.Errorf("Failed to assign voter role to node %d: %w", node.ID, err))
				}

				logger.Info("[clusterMemberDelete] Successfully assigned voter role", slog.Uint64("node_id", node.ID))
			}
		}
	}

	// Refresh members information since we may have changed roles.
	logger.Info("[clusterMemberDelete] Refreshing dqlite cluster info after potential role changes")
	info, err = leader.Cluster(ctx)
	if err != nil {
		logger.Error("[clusterMemberDelete] Failed to refresh dqlite cluster info", slog.String("error", err.Error()))
		return types.SmartError(fmt.Errorf("Failed to refresh dqlite cluster info: %w", err))
	}

	logger.Info("[clusterMemberDelete] Refreshed dqlite cluster info", slog.Int("node_count", len(info)))

	// If we are the leader and removing ourselves, reassign the leader role and perform the removal from there.
	if remotePresent && addr == leaderInfo.Address {
		logger.Info("[clusterMemberDelete] We are the leader and removing ourselves, need to transfer leadership", slog.String("member", name), slog.String("addr", addr))

		otherNodes := []uint64{}
		for _, node := range info {
			if node.Address != addr && node.Role == dqliteClient.Voter {
				otherNodes = append(otherNodes, node.ID)
			}
		}

		logger.Info("[clusterMemberDelete] Available voters for leadership transfer", slog.Int("count", len(otherNodes)))

		if len(otherNodes) == 0 {
			logger.Error("[clusterMemberDelete] No voters available for leadership transfer")
			return types.SmartError(fmt.Errorf("Found no voters to transfer leadership to"))
		}

		randomID := otherNodes[rand.Intn(len(otherNodes))]
		logger.Info("[clusterMemberDelete] Transferring leadership", slog.Uint64("target_node_id", randomID))
		err = leader.Transfer(ctx, randomID)
		if err != nil {
			logger.Error("[clusterMemberDelete] Failed to transfer leadership", slog.Uint64("target_node_id", randomID), slog.String("error", err.Error()))
			return types.SmartError(fmt.Errorf("Failed to transfer leadership to node %d: %w", randomID, err))
		}

		logger.Info("[clusterMemberDelete] Leadership transferred, connecting to new leader")
		client, err := s.Connect().Leader(false)
		if err != nil {
			logger.Error("[clusterMemberDelete] Failed to connect to new leader after transfer", slog.String("error", err.Error()))
			return types.SmartError(fmt.Errorf("Failed to connect to new leader after transfer: %w", err))
		}

		logger.Info("[clusterMemberDelete] Acquiring self removal lock (leader self-remove path)", slog.String("member", name))
		clusterDisableMu.Lock()
		logger.Info("[clusterMemberDelete] Acquired cluster self removal lock (leader self-remove path)", slog.String("member", name))

		go func() {
			<-r.Context().Done() // Wait until request is finished.

			logger.Info("[clusterMemberDelete] Request context done (leader self-remove path), releasing lock", slog.String("member", name), slog.String("ctx_err", r.Context().Err().Error()))
			clusterDisableMu.Unlock()
		}()

		logger.Info("[clusterMemberDelete] Forwarding DeleteClusterMember to new leader (self-remove path)", slog.String("member", name), slog.String("addr", addr), slog.Bool("force", force))
		if ctx.Err() != nil {
			logger.Error("[clusterMemberDelete] Context cancelled BEFORE forwarding to new leader (self-remove)", slog.String("ctx_err", ctx.Err().Error()))
		}

		err = internalClient.DeleteClusterMember(ctx, client, name, addr, force)
		if err != nil {
			logger.Error("[clusterMemberDelete] Failed forwarding DeleteClusterMember to new leader (self-remove path)", slog.String("member", name), slog.String("error", err.Error()))
			if ctx.Err() != nil {
				logger.Error("[clusterMemberDelete] Context state after self-remove forward failure", slog.String("ctx_err", ctx.Err().Error()))
			}

			return types.SmartError(fmt.Errorf("Failed forwarding DeleteClusterMember to new leader (self-remove): %w", err))
		}

		logger.Info("[clusterMemberDelete] Successfully forwarded delete to new leader (self-remove path), returning response")
		return types.ManualResponse(func(w http.ResponseWriter) error {
			err := types.EmptySyncResponse.Render(w, r)
			if err != nil {
				return fmt.Errorf("Failed rendering empty sync response after self-remove forward: %w", err)
			}

			// Send the response before replacing the LXD daemon process.
			f, ok := w.(http.Flusher)
			if !ok {
				return fmt.Errorf("ResponseWriter is not type http.Flusher")
			}

			f.Flush()
			return nil
		})
	}

	logger.Info("[clusterMemberDelete] Proceeding with standard member removal (we are leader, not self-removing)")

	logger.Info("[clusterMemberDelete] Getting cluster public key")
	publicKey, err := s.ClusterCert().PublicKeyX509()
	if err != nil {
		logger.Error("[clusterMemberDelete] Failed to get cluster public key", slog.String("error", err.Error()))
		return types.SmartError(fmt.Errorf("Failed to get cluster public key: %w", err))
	}

	var memberURL *url.URL
	if !remotePresent {
		logger.Info("[clusterMemberDelete] Remote not in truststore, constructing URL from address", slog.String("addr", addr))
		memberURL, err = url.Parse("https://" + addr)
		if err != nil {
			logger.Error("[clusterMemberDelete] Failed to parse member URL from address", slog.String("addr", addr), slog.String("error", err.Error()))
			return types.SmartError(fmt.Errorf("Failed to parse member URL from address %q: %w", addr, err))
		}
	} else {
		memberURL = remote.URL()
		logger.Info("[clusterMemberDelete] Using remote URL from truststore", slog.String("member_url", memberURL.String()))
	}

	if ctx.Err() != nil {
		logger.Error("[clusterMemberDelete] Context cancelled before PreRemove hook", slog.String("ctx_err", ctx.Err().Error()))
	}

	// Tell the cluster member to run its PreRemove hook and return.
	// Set the forwarded flag so that the system to be removed knows the removal is in progress.
	logger.Info("[clusterMemberDelete] Creating client for PreRemove hook", slog.String("member_url", memberURL.String()))
	c, err := internalClient.New(memberURL, s.ServerCert(), publicKey, true)
	if err != nil {
		if !force {
			logger.Error("[clusterMemberDelete] Failed creating client for PreRemove hook (not forced)", slog.String("error", err.Error()))
			return types.SmartError(fmt.Errorf("Failed creating client for PreRemove hook: %w", err))
		}

		logger.Warn("[clusterMemberDelete] Failed creating client for remote PreRemove (forcing)", slog.String("error", err.Error()))
	} else {
		logger.Info("[clusterMemberDelete] Running PreRemove hook on member", slog.String("member", name), slog.Bool("force", force))
		err = internalClient.RunPreRemoveHook(ctx, c.UseTarget(name), types.HookRemoveMemberOptions{Force: force})
		if err != nil {
			logger.Error("[clusterMemberDelete] PreRemove hook failed", slog.String("member", name), slog.String("error", err.Error()), slog.Bool("force", force))
			if ctx.Err() != nil {
				logger.Error("[clusterMemberDelete] Context state after PreRemove failure", slog.String("ctx_err", ctx.Err().Error()))
			}

			if !force {
				return types.SmartError(fmt.Errorf("PreRemove hook failed for member %q: %w", name, err))
			}
		} else {
			logger.Info("[clusterMemberDelete] PreRemove hook completed successfully", slog.String("member", name))
		}
	}

	if ctx.Err() != nil {
		logger.Error("[clusterMemberDelete] Context cancelled before DB delete of cluster member", slog.String("ctx_err", ctx.Err().Error()))
	}

	// Remove the cluster member from the database using its address if available; otherwise
	// return an error indicating that no address was provided or found.
	logger.Info("[clusterMemberDelete] Deleting cluster member from database", slog.String("member", name), slog.String("addr", addr))
	err = s.Database().Transaction(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return cluster.DeleteCoreClusterMember(ctx, tx, addr)
	})

	if err != nil {
		logger.Error("[clusterMemberDelete] Failed to delete cluster member from DB", slog.String("member", name), slog.String("addr", addr), slog.String("error", err.Error()), slog.Bool("force", force))
		if ctx.Err() != nil {
			logger.Error("[clusterMemberDelete] Context state after DB delete failure", slog.String("ctx_err", ctx.Err().Error()))
		}

		if !force {
			return types.SmartError(fmt.Errorf("Failed to delete cluster member %q from DB: %w", name, err))
		}
	} else {
		logger.Info("[clusterMemberDelete] Successfully deleted cluster member from DB", slog.String("member", name), slog.String("addr", addr))
	}

	// Remove the node from dqlite, if it has a record there.
	if index >= 0 {
		logger.Info("[clusterMemberDelete] Removing node from dqlite", slog.Uint64("node_id", info[index].ID), slog.String("node_address", info[index].Address))
		if ctx.Err() != nil {
			logger.Error("[clusterMemberDelete] Context cancelled before dqlite remove", slog.String("ctx_err", ctx.Err().Error()))
		}

		err = leader.Remove(ctx, info[index].ID)
		if err != nil {
			logger.Error("[clusterMemberDelete] Failed to remove node from dqlite", slog.Uint64("node_id", info[index].ID), slog.String("error", err.Error()))
			if ctx.Err() != nil {
				logger.Error("[clusterMemberDelete] Context state after dqlite remove failure", slog.String("ctx_err", ctx.Err().Error()))
			}

			return types.SmartError(fmt.Errorf("Failed to remove node %d from dqlite: %w", info[index].ID, err))
		}

		logger.Info("[clusterMemberDelete] Successfully removed node from dqlite", slog.Uint64("node_id", info[index].ID))
	} else {
		logger.Info("[clusterMemberDelete] Skipping dqlite removal (no dqlite record)", slog.String("member", name))
	}

	logger.Info("[clusterMemberDelete] Creating local client for truststore entry deletion")
	u := api.NewURL()
	u.URL = *s.FileSystem().ControlSocket()

	localClient, err := s.Connect().Member(&u.URL, false, nil)
	if err != nil {
		logger.Error("[clusterMemberDelete] Failed to create local client for truststore deletion", slog.String("error", err.Error()))
		return types.SmartError(fmt.Errorf("Failed to create local client for truststore deletion: %w", err))
	}

	logger.Info("[clusterMemberDelete] Deleting truststore entry", slog.String("member", name))
	err = internalClient.DeleteTrustStoreEntry(ctx, localClient, name)
	if err != nil {
		logger.Error("[clusterMemberDelete] Failed to delete truststore entry", slog.String("member", name), slog.String("error", err.Error()), slog.Bool("force", force))
		if !force {
			return types.SmartError(fmt.Errorf("Failed to delete truststore entry for %q: %w", name, err))
		}
	} else {
		logger.Info("[clusterMemberDelete] Successfully deleted truststore entry", slog.String("member", name))
	}

	if ctx.Err() != nil {
		logger.Error("[clusterMemberDelete] Context cancelled before resetting cluster member", slog.String("ctx_err", ctx.Err().Error()))
	}

	logger.Info("[clusterMemberDelete] Connecting to member to reset it", slog.String("member_url", memberURL.String()))
	client, err := s.Connect().Member(memberURL, false, publicKey)
	if err != nil {
		if !force {
			logger.Error("[clusterMemberDelete] Failed to connect to cluster member for reset (not forced)", slog.String("error", err.Error()))
			return types.SmartError(fmt.Errorf("Failed to connect to cluster member %q for reset: %w", name, err))
		}

		logger.Warn("[clusterMemberDelete] Failed connecting to cluster member to perform a node reset (forcing)", slog.String("error", err.Error()), slog.Bool("force", force))
	} else {
		logger.Info("[clusterMemberDelete] Resetting cluster member", slog.String("member", name), slog.Bool("force", force))
		err = internalClient.ResetClusterMember(ctx, client, name, force)
		if err != nil {
			logger.Error("[clusterMemberDelete] Failed to reset cluster member", slog.String("member", name), slog.String("error", err.Error()), slog.Bool("force", force))
			if ctx.Err() != nil {
				logger.Error("[clusterMemberDelete] Context state after reset failure", slog.String("ctx_err", ctx.Err().Error()))
			}

			if !force {
				return types.SmartError(fmt.Errorf("Failed to reset cluster member %q: %w", name, err))
			}
		} else {
			logger.Info("[clusterMemberDelete] Successfully reset cluster member", slog.String("member", name))
		}
	}

	logger.Info("[clusterMemberDelete] Getting internal state for PostRemove hook")
	intState, err := internalState.ToInternal(s)
	if err != nil {
		logger.Error("[clusterMemberDelete] Failed to get internal state for PostRemove hook", slog.String("error", err.Error()))
		return types.SmartError(fmt.Errorf("Failed to get internal state for PostRemove hook: %w", err))
	}

	if ctx.Err() != nil {
		logger.Error("[clusterMemberDelete] Context cancelled before PostRemove hook", slog.String("ctx_err", ctx.Err().Error()))
	}

	// Run the PostRemove hook locally.
	logger.Info("[clusterMemberDelete] Running PostRemove hook locally", slog.Bool("force", force))
	hookCtx, hookCancel := context.WithCancel(ctx)
	err = intState.Hooks.PostRemove(hookCtx, s, force)
	hookCancel()
	if err != nil {
		logger.Error("[clusterMemberDelete] PostRemove hook failed locally", slog.String("error", err.Error()))
		return types.SmartError(fmt.Errorf("PostRemove hook failed locally: %w", err))
	}

	logger.Info("[clusterMemberDelete] PostRemove hook completed locally")

	logger.Info("[clusterMemberDelete] Getting cluster clients for remote PostRemove hooks")
	clients, err := s.Connect().Cluster(false)
	if err != nil {
		logger.Error("[clusterMemberDelete] Failed to get cluster clients", slog.String("error", err.Error()))
		return types.SmartError(fmt.Errorf("Failed to get cluster clients for PostRemove: %w", err))
	}

	if ctx.Err() != nil {
		logger.Error("[clusterMemberDelete] Context cancelled before running PostRemove on other members", slog.String("ctx_err", ctx.Err().Error()))
	}

	// Run the PostRemove hook on all other members.
	logger.Info("[clusterMemberDelete] Running PostRemove hook on all other members")
	remotes := s.Truststore()
	err = clients.Query(ctx, true, func(ctx context.Context, c types.Client) error {
		c.SetClusterNotification()
		addrPort, err := types.ParseAddrPort(c.URL().Host)
		if err != nil {
			logger.Error("[clusterMemberDelete] Failed to parse address for PostRemove target", slog.String("host", c.URL().Host), slog.String("error", err.Error()))
			return fmt.Errorf("Failed to parse address %q for PostRemove: %w", c.URL().Host, err)
		}

		remote := remotes.RemoteByAddress(addrPort)
		if remote == nil {
			logger.Error("[clusterMemberDelete] No remote found for PostRemove hook target", slog.String("host", c.URL().Host))
			return fmt.Errorf("No remote found at address %q to run the post-remove hook", c.URL().Host)
		}

		logger.Info("[clusterMemberDelete] Running PostRemove hook on remote member", slog.String("remote_name", remote.Name), slog.String("remote_address", c.URL().Host))
		err = internalClient.RunPostRemoveHook(ctx, c.UseTarget(remote.Name), types.HookRemoveMemberOptions{Force: force})
		if err != nil {
			logger.Error("[clusterMemberDelete] PostRemove hook failed on remote member", slog.String("remote_name", remote.Name), slog.String("error", err.Error()))
		} else {
			logger.Info("[clusterMemberDelete] PostRemove hook completed on remote member", slog.String("remote_name", remote.Name))
		}

		return err
	})
	if err != nil {
		logger.Error("[clusterMemberDelete] Failed running PostRemove hooks on cluster members", slog.String("error", err.Error()))
		return types.SmartError(fmt.Errorf("Failed running PostRemove hooks on cluster members: %w", err))
	}

	logger.Info("[clusterMemberDelete] END - Successfully completed member deletion", slog.String("member", name), slog.String("addr", addr))
	return types.EmptySyncResponse
}
