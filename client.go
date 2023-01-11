package authutils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/casdoor/casdoor-go-sdk/casdoorsdk"
	"github.com/go-playground/validator"
	"github.com/savannahghi/firebasetools"
	"github.com/savannahghi/serverutils"
	"golang.org/x/oauth2"
)

// client bundles data needed by methods in order to interact with the casdoor API
type client struct {
	client         *http.Client
	configurations Config
}

// Config holds the necessary authentication configurations for interacting with the casdoor service
type Config struct {
	CasdoorEndpoint     string `json:"endpoint"`
	ClientID            string `json:"client_id"`
	ClientSecret        string `json:"client_secret"`
	CasdoorOrganization string `json:"organization"`
	CasdoorApplication  string `json:"application"`
	Certificate         string `json:"certificate"`
}

// Validate checks if all required configuration variables are present
func (c *Config) Validate() error {
	v := validator.New()

	err := v.Struct(c)

	return err
}

// NewClient creates a new authutils client
func NewClient(config Config) (*client, error) {
	err := config.Validate()
	if err != nil {
		fields := ""
		for _, i := range err.(validator.ValidationErrors) {
			fields += fmt.Sprintf("%s, ", i.Field())
		}
		err := fmt.Errorf("expected %s to be defined", fields)
		return nil, err
	}

	client := client{
		client: &http.Client{},
		configurations: Config{
			CasdoorEndpoint:     config.CasdoorEndpoint,
			ClientID:            config.ClientID,
			ClientSecret:        config.ClientSecret,
			CasdoorOrganization: config.CasdoorOrganization,
			CasdoorApplication:  config.CasdoorApplication,
		},
	}

	casdoorsdk.InitConfig(
		config.CasdoorEndpoint,
		config.ClientID,
		config.ClientSecret,
		config.Certificate,
		config.CasdoorOrganization,
		config.CasdoorApplication,
	)

	return &client, nil
}

// makeRequest is a helper function for making http requests
func (c *client) makeRequest(
	ctx context.Context,
	method string,
	path string,
	body interface{},
	isAuthorized bool,
	contentType string,
) (*http.Response, error) {
	client := http.Client{}

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	payload := bytes.NewBuffer(encoded)
	req, err := http.NewRequestWithContext(ctx, method, path, payload)
	if err != nil {
		return nil, err
	}

	if isAuthorized {
		req.SetBasicAuth(c.configurations.ClientID, c.configurations.ClientSecret)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", contentType)

	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("an error occurred while sending a HTTP request: %w", err)
	}

	return response, nil
}

// Login uses the "Resource Owner Password Credentials Grant" to authenticate a user and returns an
// access token in the response
func (c *client) Login(ctx context.Context, username, password string) (*LoginResponse, error) {
	loginEndpoint := fmt.Sprintf("%s/api/login/oauth/access_token", c.configurations.CasdoorEndpoint)
	payload := LoginPayload{
		GrantType:    "password",
		ClientID:     c.configurations.ClientID,
		ClientSecret: c.configurations.ClientSecret,
		Username:     username,
		Password:     password,
	}

	response, err := c.makeRequest(ctx, http.MethodPost, loginEndpoint, payload, false, "application/json")
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		var errorResponse *CasdoorErrorResponse
		err = json.Unmarshal(body, &errorResponse)
		if err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("expected status code %d but got %d with error: %v", http.StatusOK, response.StatusCode, errorResponse.ErrorDescription)
	}

	var loginResponse *LoginResponse
	err = json.Unmarshal(body, &loginResponse)
	if err != nil {
		return nil, err
	}

	return loginResponse, nil
}

// AddUser creates a user in casdoor
func (c *client) AddUser(ctx context.Context, user *casdoorsdk.User) (bool, error) {
	addUserEndpoint := fmt.Sprintf("%s/api/add-user", c.configurations.CasdoorEndpoint)
	response, err := c.makeRequest(ctx, http.MethodPost, addUserEndpoint, user, true, "application/json")
	if err != nil {
		return false, err
	}

	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("casdoor: AddUser error: status code: %d", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return false, err
	}
	var addUserResponse casdoorsdk.Response
	err = json.Unmarshal(body, &addUserResponse)
	if err != nil {
		return false, err
	}

	if addUserResponse.Status != "ok" {
		return false, fmt.Errorf("casdoor: failed to create user")
	}

	return true, nil
}

// VerifyAccessToken is used to introspect a token to determine the active state of the
// OAuth 2.0 access token and to determine meta-information about this token.
func (c *client) VerifyAccessToken(ctx context.Context, accessToken string) (*TokenIntrospectionResponse, error) {
	introspectionEndpoint := fmt.Sprintf("%s/api/login/oauth/introspect", c.configurations.CasdoorEndpoint)
	formData := url.Values{}
	formData.Add("token", accessToken)
	formData.Add("token_type_hint", "access_token")

	encodedData := formData.Encode()

	resp, err := casdoorsdk.DoPostBytesRaw(introspectionEndpoint, "application/x-www-form-urlencoded", bytes.NewBufferString(encodedData))
	if err != nil {
		return nil, err
	}

	var introspectionResponse *TokenIntrospectionResponse
	err = json.Unmarshal(resp, &introspectionResponse)
	if err != nil {
		return nil, err
	}

	if !introspectionResponse.Active {
		return nil, fmt.Errorf("the supplied access token is invalid")
	}

	return introspectionResponse, nil
}

// RefreshToken is used ti update an access token
func (c *client) RefreshToken(ctx context.Context, token string) (*oauth2.Token, error) {
	return casdoorsdk.RefreshOAuthToken(token)
}

// hasValidCasdoorBearerToken returns true with no errors if the request has a valid bearer token in the authorization header.
// Otherwise, it returns false and the error in a map with the key "error"
func (c *client) hasValidCasdoorBearerToken(ctx context.Context, r *http.Request) (bool, map[string]string, *TokenIntrospectionResponse) {
	bearerToken, err := firebasetools.ExtractBearerToken(r)
	if err != nil {
		// this error here will only be returned to the user if all the verification functions in the chain fail
		return false, serverutils.ErrorMap(err), nil
	}
	fmt.Println(bearerToken)

	validToken, err := c.VerifyAccessToken(ctx, bearerToken)
	if err != nil {
		return false, serverutils.ErrorMap(err), nil
	}

	return true, nil, validToken
}

// TODO: add update user, get user methods
