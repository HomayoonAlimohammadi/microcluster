package cluster

// The code below was generated by lxd-generate - DO NOT EDIT!

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"

	"github.com/lxc/lxd/lxd/db/query"
	"github.com/lxc/lxd/shared/api"
)

var _ = api.ServerEnvironment{}

var internalClusterMemberObjects = RegisterStmt(`
SELECT internal_cluster_members.id, internal_cluster_members.name, internal_cluster_members.address, internal_cluster_members.certificate, internal_cluster_members.schema, internal_cluster_members.heartbeat, internal_cluster_members.role
  FROM internal_cluster_members
  ORDER BY internal_cluster_members.address
`)

var internalClusterMemberObjectsByAddress = RegisterStmt(`
SELECT internal_cluster_members.id, internal_cluster_members.name, internal_cluster_members.address, internal_cluster_members.certificate, internal_cluster_members.schema, internal_cluster_members.heartbeat, internal_cluster_members.role
  FROM internal_cluster_members
  WHERE internal_cluster_members.address = ? ORDER BY internal_cluster_members.address
`)

var internalClusterMemberID = RegisterStmt(`
SELECT internal_cluster_members.id FROM internal_cluster_members
  WHERE internal_cluster_members.address = ?
`)

var internalClusterMemberCreate = RegisterStmt(`
INSERT INTO internal_cluster_members (name, address, certificate, schema, heartbeat, role)
  VALUES (?, ?, ?, ?, ?, ?)
`)

var internalClusterMemberDeleteByAddress = RegisterStmt(`
DELETE FROM internal_cluster_members WHERE address = ?
`)

var internalClusterMemberUpdate = RegisterStmt(`
UPDATE internal_cluster_members
  SET name = ?, address = ?, certificate = ?, schema = ?, heartbeat = ?, role = ?
 WHERE id = ?
`)

// GetInternalClusterMembers returns all available internal_cluster_members.
// generator: internal_cluster_member GetMany
func GetInternalClusterMembers(ctx context.Context, tx *sql.Tx, filter InternalClusterMemberFilter) ([]InternalClusterMember, error) {
	var err error

	// Result slice.
	objects := make([]InternalClusterMember, 0)

	// Pick the prepared statement and arguments to use based on active criteria.
	var sqlStmt *sql.Stmt
	var args []any

	if filter.Address != nil {
		sqlStmt, err = Stmt(tx, internalClusterMemberObjectsByAddress)
		if err != nil {
			return nil, fmt.Errorf("Failed to get \"internalClusterMemberObjectsByAddress\" prepared statement: %w", err)
		}

		args = []any{
			filter.Address,
		}
	} else if filter.Address == nil {
		sqlStmt, err = Stmt(tx, internalClusterMemberObjects)
		if err != nil {
			return nil, fmt.Errorf("Failed to get \"internalClusterMemberObjects\" prepared statement: %w", err)
		}

		args = []any{}
	} else {
		return nil, fmt.Errorf("No statement exists for the given Filter")
	}

	// Dest function for scanning a row.
	dest := func(scan func(dest ...any) error) error {
		i := InternalClusterMember{}
		err := scan(&i.ID, &i.Name, &i.Address, &i.Certificate, &i.Schema, &i.Heartbeat, &i.Role)
		if err != nil {
			return err
		}

		objects = append(objects, i)

		return nil
	}

	// Select.
	err = query.SelectObjects(sqlStmt, dest, args...)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch from \"internals_clusters_members\" table: %w", err)
	}

	return objects, nil
}

// GetInternalClusterMember returns the internal_cluster_member with the given key.
// generator: internal_cluster_member GetOne
func GetInternalClusterMember(ctx context.Context, tx *sql.Tx, address string) (*InternalClusterMember, error) {
	filter := InternalClusterMemberFilter{}
	filter.Address = &address

	objects, err := GetInternalClusterMembers(ctx, tx, filter)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch from \"internals_clusters_members\" table: %w", err)
	}

	switch len(objects) {
	case 0:
		return nil, api.StatusErrorf(http.StatusNotFound, "InternalClusterMember not found")
	case 1:
		return &objects[0], nil
	default:
		return nil, fmt.Errorf("More than one \"internals_clusters_members\" entry matches")
	}
}

// GetInternalClusterMemberID return the ID of the internal_cluster_member with the given key.
// generator: internal_cluster_member ID
func GetInternalClusterMemberID(ctx context.Context, tx *sql.Tx, address string) (int64, error) {
	stmt, err := Stmt(tx, internalClusterMemberID)
	if err != nil {
		return -1, fmt.Errorf("Failed to get \"internalClusterMemberID\" prepared statement: %w", err)
	}

	rows, err := stmt.Query(address)
	if err != nil {
		return -1, fmt.Errorf("Failed to get \"internals_clusters_members\" ID: %w", err)
	}

	defer func() { _ = rows.Close() }()

	// Ensure we read one and only one row.
	if !rows.Next() {
		return -1, api.StatusErrorf(http.StatusNotFound, "InternalClusterMember not found")
	}

	var id int64
	err = rows.Scan(&id)
	if err != nil {
		return -1, fmt.Errorf("Failed to scan ID: %w", err)
	}

	if rows.Next() {
		return -1, fmt.Errorf("More than one row returned")
	}

	err = rows.Err()
	if err != nil {
		return -1, fmt.Errorf("Result set failure: %w", err)
	}

	return id, nil
}

// InternalClusterMemberExists checks if a internal_cluster_member with the given key exists.
// generator: internal_cluster_member Exists
func InternalClusterMemberExists(ctx context.Context, tx *sql.Tx, address string) (bool, error) {
	_, err := GetInternalClusterMemberID(ctx, tx, address)
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

// CreateInternalClusterMember adds a new internal_cluster_member to the database.
// generator: internal_cluster_member Create
func CreateInternalClusterMember(ctx context.Context, tx *sql.Tx, object InternalClusterMember) (int64, error) {
	// Check if a internal_cluster_member with the same key exists.
	exists, err := InternalClusterMemberExists(ctx, tx, object.Address)
	if err != nil {
		return -1, fmt.Errorf("Failed to check for duplicates: %w", err)
	}

	if exists {
		return -1, api.StatusErrorf(http.StatusConflict, "This \"internals_clusters_members\" entry already exists")
	}

	args := make([]any, 6)

	// Populate the statement arguments.
	args[0] = object.Name
	args[1] = object.Address
	args[2] = object.Certificate
	args[3] = object.Schema
	args[4] = object.Heartbeat
	args[5] = object.Role

	// Prepared statement to use.
	stmt, err := Stmt(tx, internalClusterMemberCreate)
	if err != nil {
		return -1, fmt.Errorf("Failed to get \"internalClusterMemberCreate\" prepared statement: %w", err)
	}

	// Execute the statement.
	result, err := stmt.Exec(args...)
	if err != nil {
		return -1, fmt.Errorf("Failed to create \"internals_clusters_members\" entry: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return -1, fmt.Errorf("Failed to fetch \"internals_clusters_members\" entry ID: %w", err)
	}

	return id, nil
}

// DeleteInternalClusterMember deletes the internal_cluster_member matching the given key parameters.
// generator: internal_cluster_member DeleteOne-by-Address
func DeleteInternalClusterMember(ctx context.Context, tx *sql.Tx, address string) error {
	stmt, err := Stmt(tx, internalClusterMemberDeleteByAddress)
	if err != nil {
		return fmt.Errorf("Failed to get \"internalClusterMemberDeleteByAddress\" prepared statement: %w", err)
	}

	result, err := stmt.Exec(address)
	if err != nil {
		return fmt.Errorf("Delete \"internals_clusters_members\": %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("Fetch affected rows: %w", err)
	}

	if n == 0 {
		return api.StatusErrorf(http.StatusNotFound, "InternalClusterMember not found")
	} else if n > 1 {
		return fmt.Errorf("Query deleted %d InternalClusterMember rows instead of 1", n)
	}

	return nil
}

// UpdateInternalClusterMember updates the internal_cluster_member matching the given key parameters.
// generator: internal_cluster_member Update
func UpdateInternalClusterMember(ctx context.Context, tx *sql.Tx, address string, object InternalClusterMember) error {
	id, err := GetInternalClusterMemberID(ctx, tx, address)
	if err != nil {
		return err
	}

	stmt, err := Stmt(tx, internalClusterMemberUpdate)
	if err != nil {
		return fmt.Errorf("Failed to get \"internalClusterMemberUpdate\" prepared statement: %w", err)
	}

	result, err := stmt.Exec(object.Name, object.Address, object.Certificate, object.Schema, object.Heartbeat, object.Role, id)
	if err != nil {
		return fmt.Errorf("Update \"internals_clusters_members\" entry failed: %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("Fetch affected rows: %w", err)
	}

	if n != 1 {
		return fmt.Errorf("Query updated %d rows instead of 1", n)
	}

	return nil
}