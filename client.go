package authutils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-playground/validator"
	"github.com/savannahghi/firebasetools"
	"github.com/savannahghi/serverutils"
	"moul.io/http2curl"
)

// Client bundles data needed by methods in order to interact with the slade360 auth server API
type Client struct {
	client         *http.Client
	configurations Config
}

// Config holds the necessary authentication configurations for interacting with the slade360 auth server service
type Config struct {
	AuthServerEndpoint string `json:"authServerEndpoint"`
	ClientID           string `json:"client_id"`
	ClientSecret       string `json:"client_secret"`
	GrantType          string `json:"grant_type"`
	Username           string `json:"username"`
	Password           string `json:"password"`
}

// Validate checks if all required configuration variables are present
func (c *Config) Validate() error {
	v := validator.New()

	err := v.Struct(c)

	return err
}

// NewClient creates a new authutils client
func NewClient(config Config) (*Client, error) {
	err := config.Validate()
	if err != nil {
		fields := ""
		for _, i := range err.(validator.ValidationErrors) {
			fields += fmt.Sprintf("%s, ", i.Field())
		}
		err := fmt.Errorf("expected %s to be defined", fields)
		return nil, err
	}

	client := Client{
		client: &http.Client{
			Timeout: time.Second * 60 * 30,
		},
		configurations: Config{
			AuthServerEndpoint: config.AuthServerEndpoint,
			ClientID:           config.ClientID,
			ClientSecret:       config.ClientSecret,
			GrantType:          config.GrantType,
			Username:           config.Username,
			Password:           config.Password,
		},
	}

	_, err = client.Authenticate()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize server client: %w", err)
	}

	return &client, nil
}

// Authenticate uses client credentials to log in to a slade360 authentication server
func (c *Client) Authenticate() (*LoginResponse, error) {
	apiTokenURL := fmt.Sprintf("%s/oauth2/token/", c.configurations.AuthServerEndpoint)
	credentials := url.Values{}
	credentials.Set("client_id", c.configurations.ClientID)
	credentials.Set("client_secret", c.configurations.ClientSecret)
	credentials.Set("grant_type", c.configurations.GrantType)
	credentials.Set("username", c.configurations.Username)
	credentials.Set("password", c.configurations.Password)

	encodedCredentials := strings.NewReader(credentials.Encode())

	response, err := c.client.Post(apiTokenURL, "application/x-www-form-urlencoded", encodedCredentials)
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var responseData LoginResponse
	err = json.Unmarshal(data, &responseData)
	if err != nil {
		return nil, err
	}

	return &responseData, nil
}

// CreateUser creates a user on slade360 auth server
func (c *Client) CreateUser(ctx context.Context, input *CreateUserPayload) (*CreateUserResponse, error) {
	createUserEndpoint := fmt.Sprintf("%s/v1/user/user_roles/", c.configurations.AuthServerEndpoint)
	response, err := c.makeRequest(ctx, http.MethodPost, createUserEndpoint, input, "application/json", true)
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode >= 300 || response.StatusCode < 200 {
		msg := fmt.Sprintf(
			"error from create user endpoint, status %d and error: %s",
			response.StatusCode, string(data),
		)
		return nil, fmt.Errorf(msg)
	}

	var dataResponse *CreateUserResponse
	err = json.Unmarshal(data, &dataResponse)
	if err != nil {
		return nil, err
	}

	return dataResponse, nil
}

// verifyAccessToken is used to introspect a token to determine the active state of the
// OAuth 2.0 access token and to determine meta-information about this token.
func (c *Client) verifyAccessToken(ctx context.Context, accessToken string) (*TokenIntrospectionResponse, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("unable to get access token from the input")
	}

	if len(accessToken) > 256 {
		return nil, fmt.Errorf("ensure the token has no more than 255 characters")
	}

	introspectionURL := fmt.Sprintf("%s/v1/app/introspect/", c.configurations.AuthServerEndpoint)
	payload := TokenIntrospectionPayload{
		TokenType: "access_token",
		Token:     accessToken,
	}

	response, err := c.makeRequest(ctx, http.MethodPost, introspectionURL, payload, "application/json", false)
	if err != nil {
		return nil, err
	}

	resp, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var introspectionResponse *TokenIntrospectionResponse
	err = json.Unmarshal(resp, &introspectionResponse)
	if err != nil {
		return nil, err
	}

	if !introspectionResponse.IsValid {
		return nil, fmt.Errorf("the supplied access token is invalid")
	}

	return introspectionResponse, nil
}

// hasValidSlade360BearerToken returns true with no errors if the request has a valid bearer token in the authorization header.
// Otherwise, it returns false and the error in a map with the key "error"
func (c *Client) hasValidSlade360BearerToken(ctx context.Context, r *http.Request) (bool, map[string]string, *TokenIntrospectionResponse) {
	bearerToken, err := firebasetools.ExtractBearerToken(r)
	if err != nil {
		// this error here will only be returned to the user if all the verification functions in the chain fail
		return false, serverutils.ErrorMap(err), nil
	}

	validToken, err := c.verifyAccessToken(ctx, bearerToken)
	if err != nil {
		return false, serverutils.ErrorMap(err), nil
	}

	return true, nil, validToken
}

// makeRequest is a helper function for making http requests
func (c *Client) makeRequest(
	ctx context.Context,
	method string,
	path string,
	body interface{},
	contentType string,
	isAuthenticated bool,
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

	if isAuthenticated {
		loginCreds, err := c.Authenticate()
		if err != nil {
			return nil, err
		}
		token := fmt.Sprintf("Bearer %s", loginCreds.AccessToken)

		req.Header.Set("Authorization", token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", contentType)

	command, _ := http2curl.GetCurlCommand(req)
	fmt.Println(command)

	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("an error occurred while sending a HTTP request: %w", err)
	}

	return response, nil
}
