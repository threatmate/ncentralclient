package ncentralclient

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRenewalTime(t *testing.T) {
	requested := time.Date(2026, 10, 1, 7, 0, 0, 0, time.UTC)

	// N-central's default lifetime: renewed a minute early.
	assert.Equal(t, requested.Add(59*time.Minute), renewalTime(requested, 3600))
	// A short lifetime: renewed a tenth early, so the token is still used for
	// most of its life rather than renewed before every request.
	assert.Equal(t, requested.Add(900*time.Millisecond), renewalTime(requested, 1))
	assert.Equal(t, requested.Add(9*time.Minute), renewalTime(requested, 600))
	// No lifetime given: never renewed, which is what the client did before it
	// renewed at all.
	assert.True(t, renewalTime(requested, 0).IsZero())
	assert.True(t, renewalTime(requested, -1).IsZero())
}

func TestAccessTokenDue(t *testing.T) {
	past := time.Now().Add(-time.Second)
	future := time.Now().Add(time.Hour)

	cases := []struct {
		name   string
		client *Client
		due    bool
	}{
		{name: "Never authenticated", client: &Client{}, due: false},
		{name: "No lifetime given", client: &Client{apiKey: "key"}, due: false},
		{name: "Not yet due", client: &Client{apiKey: "key", renewAt: future}, due: false},
		{name: "Due", client: &Client{apiKey: "key", renewAt: past}, due: true},
		{name: "Due but nothing to renew with", client: &Client{renewAt: past}, due: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			apiKey, due := c.client.accessTokenDue()
			assert.Equal(t, c.due, due)
			if due {
				assert.Equal(t, "key", apiKey)
			}
		})
	}
}
