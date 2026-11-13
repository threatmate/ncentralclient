package ncentralclient

import (
	"context"
	"net/http"
)

// ServerInfo is what N-central says about itself.
//
// Observed on a live N-central 2026.4.1.26 on 2026-11-12:
//
//	{"jvmVersion":"21.0.13","startTime":"2026-11-10T20:30:57.514095249","version":"1.3.23","ncentral":"2026.4.1.26"}
//
// NCentral is the server's release. Version is the REST API's own version, not
// the server's: do not read a release from it.
type ServerInfo struct {
	NCentral   string `json:"ncentral"`
	Version    string `json:"version"`
	JVMVersion string `json:"jvmVersion"`
	StartTime  string `json:"startTime"`
}

// GetServerInfo returns the server's release and API version.
//
// It needs an access token: the same server answers 401 without one.
//
// See: https://developer.n-able.com/n-central/reference/apiroot_1 (its documented
// example shows "ncentral": null; a live server fills it in).
func (c *Client) GetServerInfo(ctx context.Context) (ServerInfo, error) {
	var output ServerInfo
	err := c.Do(ctx, http.MethodGet, "/api/server-info", nil, &output)
	if err != nil {
		return ServerInfo{}, err
	}
	return output, nil
}
