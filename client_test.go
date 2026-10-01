package ncentralclient_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/threatmate/ncentralclient"
	"github.com/threatmate/ncentralclient/simulator"
)

// TestAccessTokenRenewal holds one client past the lifetime of the access token
// it authenticated with. A sync of a large N-central fleet does exactly that:
// its per-device assets calls can take longer than the hour an access token
// lives by default.
func TestAccessTokenRenewal(t *testing.T) {
	ctx := t.Context()

	const accessTokenTTL = 2 * time.Second

	sim := simulator.New(ctx)
	defer sim.Close()

	apiUser := &simulator.APIUser{
		Username:       "admin@example.com",
		APIKey:         "admin-key-1",
		AccessTokenTTL: accessTokenTTL,
	}
	sim.Universe().APIUsers = []*simulator.APIUser{apiUser}
	sim.Universe().ServiceOrgs = []*ncentralclient.ServiceOrg{
		{
			SOID:   "1",
			SOName: "Service Org 1",
		},
	}

	client := ncentralclient.New(sim.URL())
	err := client.Authenticate(ctx, "admin-key-1")
	require.NoError(t, err)

	_, err = client.GetServiceOrgs(ctx)
	require.NoError(t, err, "sanity: the first access token works")

	time.Sleep(accessTokenTTL + 500*time.Millisecond)

	serviceOrgs, err := client.GetServiceOrgs(ctx)
	require.NoError(t, err, "a client that outlives its access token must renew it, not answer 401 to every call from then on")
	assert.Len(t, serviceOrgs, 1)
	assert.Equal(t, 2, apiUser.IssuedAccessTokens(), "the token must be renewed once, when it was due")

	_, err = client.GetServiceOrgs(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, apiUser.IssuedAccessTokens(), "a token that is not yet due must be reused, not renewed on every call")
}

// TestSimulatorRefusesExpiredAccessTokens is the control for
// TestAccessTokenRenewal: the simulator really does refuse an access token past
// its lifetime, so it is the renewal that keeps the client working.
func TestSimulatorRefusesExpiredAccessTokens(t *testing.T) {
	apiUser := &simulator.APIUser{
		Username:       "admin@example.com",
		APIKey:         "admin-key-1",
		AccessTokenTTL: time.Second,
	}
	output, err := apiUser.AuthenticateAPIKey("admin-key-1")
	require.NoError(t, err)
	assert.Equal(t, 1, output.Tokens.Access.ExpirySeconds)
	assert.True(t, apiUser.CheckAccessToken(output.Tokens.Access.Token))

	time.Sleep(1500 * time.Millisecond)
	assert.False(t, apiUser.CheckAccessToken(output.Tokens.Access.Token), "an access token past its lifetime must be refused")
}

func TestDateTimeUnmarshalJSON(t *testing.T) {
	cases := map[string]time.Time{
		// No offset: the form N-central uses for most timestamps.
		`"2026-03-23T21:33:26.278"`: time.Date(2026, 3, 23, 21, 33, 26, 278000000, time.UTC),
		// A numeric offset.
		`"2026-03-23T17:33:26.278-04:00"`: time.Date(2026, 3, 23, 21, 33, 26, 278000000, time.UTC),
		// UTC with a trailing Z. One device in this form failed the whole
		// device list for an N-central integration on every sync.
		`"2026-03-23T21:33:26.278Z"`: time.Date(2026, 3, 23, 21, 33, 26, 278000000, time.UTC),
	}
	for input, expected := range cases {
		t.Run(input, func(t *testing.T) {
			var value ncentralclient.DateTime
			err := json.Unmarshal([]byte(input), &value)
			require.NoError(t, err)
			assert.True(t, expected.Equal(time.Time(value)), "expected %v, got %v", expected, time.Time(value))
		})
	}

	t.Run("Device", func(t *testing.T) {
		var device ncentralclient.Device
		err := json.Unmarshal([]byte(`{"deviceId":1,"longName":"Device 1","lastApplianceCheckinTime":"2026-03-23T21:33:26.278Z"}`), &device)
		require.NoError(t, err)
		require.NotNil(t, device.LastApplianceCheckinTime)
		assert.True(t, time.Date(2026, 3, 23, 21, 33, 26, 278000000, time.UTC).Equal(time.Time(*device.LastApplianceCheckinTime)))
	})

	t.Run("Garbage", func(t *testing.T) {
		var value ncentralclient.DateTime
		err := json.Unmarshal([]byte(`"yesterday"`), &value)
		require.Error(t, err)
	})
}
