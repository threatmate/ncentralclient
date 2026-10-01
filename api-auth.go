package ncentralclient

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/threatmate/restapiclient"
)

// GetAuthResponse is the response from the auth endpoint.
type GetAuthResponse struct {
	Refresh      string `json:"refresh"`
	Validate     string `json:"validate"`
	Authenticate string `json:"authenticate"`
}

// GetAuth returns the auth endpoints.
//
// See: https://developer.n-able.com/n-central/reference/authroot
func (c *Client) GetAuth(ctx context.Context) (output GetAuthResponse, err error) {
	// Note: Use the raw client directly.
	err = c.client.Do(ctx, http.MethodGet, "/api/auth", nil, &output)
	if err != nil {
		return output, fmt.Errorf("getauth: %w", err)
	}

	return output, nil
}

// PostAuthAuthenticateResponse is the response from the authenticate endpoint.
type PostAuthAuthenticateResponse struct {
	Tokens struct {
		Access  PostAuthAuthenticateResponseToken `json:"access"`
		Refresh PostAuthAuthenticateResponseToken `json:"refresh"`
	} `json:"tokens"`
	Refresh  string `json:"refresh"`
	Validate string `json:"validate"`
}

// PostAuthAuthenticateResponseToken is a token from the authenticate endpoint.
type PostAuthAuthenticateResponseToken struct {
	Token         string `json:"token"`
	Type          string `json:"type"`
	ExpirySeconds int    `json:"expirySeconds"`
}

// Authenticate exchanges the user API token for an access token, which Do then
// presents on every request and renews before it expires.
func (c *Client) Authenticate(ctx context.Context, apiKey string) error {
	requested := time.Now()

	var output PostAuthAuthenticateResponse
	// Note: Use the raw client directly.
	err := c.client.Do(ctx, http.MethodPost, "/api/auth/authenticate", nil, &output,
		restapiclient.OptionHeader("Authorization", "Bearer "+apiKey),
	)
	if err != nil {
		c.lock.Lock()
		c.accessToken = "" // Zero out the access token on failure.
		c.lock.Unlock()
		return fmt.Errorf("authenticate: %w", err)
	}

	c.lock.Lock()
	c.accessToken = output.Tokens.Access.Token
	c.apiKey = apiKey
	c.renewAt = renewalTime(requested, output.Tokens.Access.ExpirySeconds)
	c.lock.Unlock()

	return nil
}
