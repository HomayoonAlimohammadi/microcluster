// Package api provides a slice of Servers
package api

import (
	"github.com/canonical/microcluster/example/api/types"
	"github.com/canonical/microcluster/rest"
)

// Servers represents the list of listeners that the daemon will start
// Each Server has pre-defined endpoints that will be added to the listener
// If the Server is marked as CoreAPI, its endpoints will be added to the core listener of Microcluster.
var Servers = []rest.Server{
	{
		CoreAPI: true,
		Resources: []rest.Resources{
			{
				PathPrefix: types.ExtendedPathPrefix,
				Endpoints: []rest.Endpoint{
					extendedCmd,
				},
			},
		},
	},
}
