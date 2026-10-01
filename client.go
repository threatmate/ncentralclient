package ncentralclient

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/threatmate/restapiclient"
)

// ClientOption is a function that configures the client.
type ClientOption func(*Config)

// Config is the configuration for the client.
type Config struct {
	BaseURL    string
	HTTPClient *http.Client
}

// Client is the client for the n-able REST API.
type Client struct {
	client      *restapiclient.Client
	lock        sync.Mutex
	accessToken string

	// apiKey is the user API token that Authenticate exchanged for the access
	// token. It is kept so the access token can be renewed: N-central honours
	// an access token for a limited time, an hour by default, and a client
	// that outlives it would otherwise be refused on every call from then on.
	apiKey string
	// renewAt is when Do stops presenting the access token and authenticates
	// again. Zero means the server did not say when the token expires.
	renewAt time.Time
}

// New creates a new client for the n-able REST API.
//
// The default HTTP client under the hood will have a 1-minute timeout.
func New(baseURL string, opts ...ClientOption) *Client {
	config := Config{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 1 * time.Minute,
		},
	}

	for _, opt := range opts {
		opt(&config)
	}

	if !strings.Contains(config.BaseURL, "://") {
		config.BaseURL = "https://" + config.BaseURL
	}

	client := restapiclient.New(config.BaseURL)
	if config.HTTPClient != nil {
		httpClient := client.HTTPClient()
		*httpClient = *config.HTTPClient
	}

	return &Client{
		client: client,
	}
}

// GetClient returns the underlying REST API client.
func (c *Client) HTTPClient() *http.Client {
	if c.client == nil {
		return nil
	}
	return c.client.HTTPClient()
}

// Do performs a request to the n-able REST API.
func (c *Client) Do(ctx context.Context, method string, path string, input any, output any, options ...restapiclient.Option) error {
	err := c.renewAccessTokenIfDue(ctx)
	if err != nil {
		return err
	}

	var accessToken string
	c.lock.Lock()
	accessToken = c.accessToken
	c.lock.Unlock()

	var newOptions []restapiclient.Option
	if accessToken != "" {
		newOptions = append(newOptions, restapiclient.OptionHeader("Authorization", "Bearer "+accessToken))
	}
	newOptions = append(newOptions, options...)

	return c.client.Do(ctx, method, path, input, output, newOptions...)
}

// renewAccessTokenIfDue authenticates again with the API key once the access
// token is due for renewal.
//
// This re-runs the authenticate exchange rather than calling /api/auth/refresh,
// so renewing needs nothing the first authentication did not: the same API key
// and the same exchange.
//
// Renewals are not serialized. Callers that find the token due at the same
// moment each renew it, and the last to finish wins, failure included: a
// failed renewal clears the token, and if it finishes after one that succeeded
// (which moved the next renewal out by the token's lifetime), requests go out
// with no token until that renewal is due. Callers that need renewal to
// recover at once should not share a client between goroutines.
func (c *Client) renewAccessTokenIfDue(ctx context.Context) error {
	apiKey, due := c.accessTokenDue()
	if !due {
		return nil
	}

	err := c.Authenticate(ctx, apiKey)
	if err != nil {
		return fmt.Errorf("could not renew the access token: %w", err)
	}
	return nil
}

// accessTokenDue reports whether the access token is due for renewal, and the
// API key to renew it with.
func (c *Client) accessTokenDue() (apiKey string, due bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.apiKey == "" || c.renewAt.IsZero() {
		return "", false
	}
	return c.apiKey, !time.Now().Before(c.renewAt)
}

// renewalTime is when an access token should stop being presented, given when
// the request that obtained it was sent and the lifetime N-central gave it.
//
// The lifetime runs from when the request was sent rather than when the answer
// arrived, which errs early by the round trip, and a tenth of it (at most a
// minute) is held back so that a request sent just before the renewal is still
// honoured when it arrives.
func renewalTime(requested time.Time, expirySeconds int) time.Time {
	if expirySeconds <= 0 {
		return time.Time{}
	}
	lifetime := time.Duration(expirySeconds) * time.Second
	return requested.Add(lifetime - min(lifetime/10, time.Minute))
}
