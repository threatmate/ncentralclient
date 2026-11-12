package simulator_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tekkamanendless/httperror"
	"github.com/threatmate/ncentralclient"
	"github.com/threatmate/ncentralclient/simulator"
)

func TestSimulator(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	ctx := t.Context()

	sim := simulator.New(ctx)
	defer sim.Close()

	sim.Universe().APIUsers = []*simulator.APIUser{
		{
			Username: "admin@example.com",
			APIKey:   "admin-key-1",
		},
	}
	sim.Universe().ServiceOrgs = []*ncentralclient.ServiceOrg{
		{
			SOID:   "1",
			SOName: "Service Org 1",
		},
	}
	sim.Universe().OrgUnits = []*simulator.OrgUnit{
		{
			OrgUnitID: "1",
			Users: []*ncentralclient.OrgUnitUser{
				{
					UserID:   1,
					UserName: "User 1",
				},
			},
		},
	}
	sim.Universe().Customers = []*ncentralclient.Customer{
		{
			CustomerID:   "1",
			CustomerName: "Customer 1",
		},
	}
	sim.Universe().Devices = []*simulator.Device{
		{
			Device: &ncentralclient.Device{
				DeviceID: 1,
				LongName: "Device 1",
			},
			Asset: &ncentralclient.DeviceAsset{},
		},
	}

	sim.Universe().ServerInfo = &ncentralclient.ServerInfo{
		NCentral: "2026.4.1.26",
		Version:  "1.3.23",
	}

	t.Run("server-info without a token", func(t *testing.T) {
		client := ncentralclient.New(sim.URL())

		_, err := client.GetServerInfo(ctx)
		require.ErrorIs(t, err, httperror.ErrStatusUnauthorized)
	})
	t.Run("auth", func(t *testing.T) {
		client := ncentralclient.New(sim.URL())

		output, err := client.GetAuth(ctx)
		require.NoError(t, err)
		assert.Equal(t, "/api/auth/refresh", output.Refresh)
		assert.Equal(t, "/api/auth/validate", output.Validate)
		assert.Equal(t, "/api/auth/authenticate", output.Authenticate)
	})
	t.Run("auth/authenticate", func(t *testing.T) {
		t.Run("Bogus API key", func(t *testing.T) {
			client := ncentralclient.New(sim.URL())

			err := client.Authenticate(ctx, "bogus")
			require.ErrorIs(t, err, httperror.ErrStatusUnauthorized)
		})
		t.Run("Valid API key", func(t *testing.T) {
			client := ncentralclient.New(sim.URL())

			err := client.Authenticate(ctx, "admin-key-1")
			require.NoError(t, err)
		})
	})
	t.Run("Authenticated", func(t *testing.T) {
		client := ncentralclient.New(sim.URL())
		err := client.Authenticate(ctx, "admin-key-1")
		require.NoError(t, err)

		t.Run("service-orgs", func(t *testing.T) {
			serviceOrgs, err := client.GetServiceOrgs(ctx)
			require.NoError(t, err)
			if assert.Equal(t, 1, len(serviceOrgs)) {
				assert.Equal(t, "1", serviceOrgs[0].SOID)
				assert.Equal(t, "Service Org 1", serviceOrgs[0].SOName)

				t.Run("service-orgs", func(t *testing.T) {
					users, err := client.GetOrgUnitsIDUsers(ctx, serviceOrgs[0].SOID)
					require.NoError(t, err)
					if assert.Equal(t, 1, len(users)) {
						assert.Equal(t, 1, users[0].UserID)
						assert.Equal(t, "User 1", users[0].UserName)
					}
				})
			}
		})
		t.Run("server-info", func(t *testing.T) {
			info, err := client.GetServerInfo(ctx)
			require.NoError(t, err)
			assert.Equal(t, "2026.4.1.26", info.NCentral)
			assert.Equal(t, "1.3.23", info.Version)
		})
		t.Run("customers", func(t *testing.T) {
			customers, err := client.GetCustomers(ctx)
			require.NoError(t, err)
			if assert.Equal(t, 1, len(customers)) {
				assert.Equal(t, "1", customers[0].CustomerID)
				assert.Equal(t, "Customer 1", customers[0].CustomerName)
			}
		})
		t.Run("devices", func(t *testing.T) {
			devices, err := client.GetDevices(ctx)
			require.NoError(t, err)
			if assert.Equal(t, 1, len(devices)) {
				assert.Equal(t, 1, devices[0].DeviceID)
				assert.Equal(t, "Device 1", devices[0].LongName)

				t.Run("assets", func(t *testing.T) {
					assets, err := client.GetDevicesIDAssets(ctx, devices[0].DeviceID)
					require.NoError(t, err)
					_ = assets
				})
			}
		})
	})
}
