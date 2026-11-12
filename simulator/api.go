package simulator

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/threatmate/ncentralclient"
	"github.com/threatmate/restfulwrapper"
)

type API struct {
	universe *Universe
}

type GetAuthMetadata struct {
	restfulwrapper.HTTPMethodGET
	_ string `api:"httppath:/auth"`
}

func (a *API) GetAuth(ctx context.Context, meta GetAuthMetadata) (output ncentralclient.GetAuthResponse, err error) {
	output.Refresh = "/api/auth/refresh"
	output.Validate = "/api/auth/validate"
	output.Authenticate = "/api/auth/authenticate"
	return output, nil
}

type PostAuthAuthenticateMetadata struct {
	restfulwrapper.HTTPMethodPOST
	_             string `api:"httppath:/auth/authenticate"`
	Authorization string `api:"header:Authorization"`
	Body          string `api:"body:consumes:*/*;empty"`
}

func (a *API) PostAuthAuthenticate(ctx context.Context, meta PostAuthAuthenticateMetadata) (output ncentralclient.PostAuthAuthenticateResponse, err error) {
	if meta.Authorization == "" {
		return output, &APIError{code: http.StatusBadRequest, message: "[ID=4c141324-b42d-4103-9812-02c9c34b73a2] BAD REQUEST: MissingRequestHeaderException: Required request header 'Authorization' for method parameter type String is not present"}
	}
	if !strings.HasPrefix(meta.Authorization, "Bearer ") {
		return output, &APIError{code: http.StatusInternalServerError, message: "[ID=ef8c01bd-3b98-4b8c-9ccf-ef1e873c6954] INTERNAL SERVER ERROR: AuthException: Authentication header is malformed or unsupported."}
	}
	apiKey := strings.TrimPrefix(meta.Authorization, "Bearer ")

	for _, apiUser := range a.universe.APIUsers {
		response, err := apiUser.AuthenticateAPIKey(apiKey)
		if err == nil {
			return response, err
		}
	}

	return output, &APIError{code: http.StatusUnauthorized, message: "UNAUTHORIZED: DmsLoginException: Login failed. Unable to obtain the login sessionId. status=500 DMS=DmsProperties [protocol=http, host=localhost, dmsPort=8080, loginPort=81], request=DmsHttpRequest [method=POST, endpoint=dms/rest/login, contentType=null]"}
}

type requireAuthentication struct {
	CurrentUser CurrentUser `api:"custom.currentUser"`
}

type GetServiceOrgsMetadata struct {
	restfulwrapper.HTTPMethodGET
	requireAuthentication
	_ string `api:"httppath:/service-orgs"`
}

func (a *API) GetServiceOrgs(ctx context.Context, meta GetServiceOrgsMetadata) (output ncentralclient.GetServiceOrgsResponse, err error) {
	for _, serviceOrg := range a.universe.ServiceOrgs {
		output.Data = append(output.Data, *serviceOrg)
	}
	output.ItemCount = len(output.Data)
	output.TotalItems = len(output.Data)
	output.TotalPages = 1
	output.PageNumber = 1
	output.PageSize = len(output.Data)
	return output, nil
}

type GetCustomersMetadata struct {
	restfulwrapper.HTTPMethodGET
	requireAuthentication
	_ string `api:"httppath:/customers"`
}

func (a *API) GetCustomers(ctx context.Context, meta GetCustomersMetadata) (output ncentralclient.GetCustomersResponse, err error) {
	for _, customer := range a.universe.Customers {
		output.Data = append(output.Data, *customer)
	}
	output.ItemCount = len(output.Data)
	output.TotalItems = len(output.Data)
	output.TotalPages = 1
	output.PageNumber = 1
	output.PageSize = len(output.Data)
	return output, nil
}

type GetDevicesMetadata struct {
	restfulwrapper.HTTPMethodGET
	requireAuthentication
	_ string `api:"httppath:/devices"`
}

func (a *API) GetDevices(ctx context.Context, meta GetDevicesMetadata) (output ncentralclient.GetDevicesResponse, err error) {
	for _, device := range a.universe.Devices {
		output.Data = append(output.Data, *device.Device)
	}
	output.ItemCount = len(output.Data)
	output.TotalItems = len(output.Data)
	output.TotalPages = 1
	output.PageNumber = 1
	output.PageSize = len(output.Data)
	return output, nil
}

type GetDevicesIDAssetsMetadata struct {
	restfulwrapper.HTTPMethodGET
	requireAuthentication
	_        string `api:"httppath:/devices/{deviceID}/assets"`
	DeviceID string `api:"path:deviceID"`
}

func (a *API) GetDevicesIDAssets(ctx context.Context, meta GetDevicesIDAssetsMetadata) (output ncentralclient.GetDevicesIDAssetsResponse, err error) {
	for _, device := range a.universe.Devices {
		if fmt.Sprintf("%d", device.Device.DeviceID) != meta.DeviceID {
			continue
		}
		output.Data = *device.Asset
		break
	}
	return output, nil
}

type GetOrgUnitsIDUsersMetadata struct {
	restfulwrapper.HTTPMethodGET
	requireAuthentication
	_         string `api:"httppath:/org-units/{orgUnitID}/users"`
	OrgUnitID string `api:"path:orgUnitID"`
}

func (a *API) GetOrgUnitsIDUsers(ctx context.Context, meta GetOrgUnitsIDUsersMetadata) (output ncentralclient.GetOrgUnitsIDUsersResponse, err error) {
	for _, orgUnit := range a.universe.OrgUnits {
		if orgUnit.OrgUnitID != meta.OrgUnitID {
			continue
		}
		for _, user := range orgUnit.Users {
			output.Data = append(output.Data, *user)
		}
		break
	}
	output.ItemCount = len(output.Data)
	output.TotalItems = len(output.Data)
	output.TotalPages = 1
	output.PageNumber = 1
	output.PageSize = len(output.Data)
	return output, nil
}

type GetServerInfoMetadata struct {
	restfulwrapper.HTTPMethodGET
	requireAuthentication
	_ string `api:"httppath:/server-info"`
}

func (a *API) GetServerInfo(ctx context.Context, meta GetServerInfoMetadata) (output ncentralclient.ServerInfo, err error) {
	if a.universe.ServerInfo == nil {
		return output, &APIError{code: http.StatusNotFound, message: "NOT FOUND"}
	}
	return *a.universe.ServerInfo, nil
}
