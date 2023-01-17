package authutils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-playground/validator"
)

// Client bundles data needed by methods in order to interact with the casdoor API
type Client struct {
	client         *http.Client
	configurations Config
}

// Config holds the necessary authentication configurations for interacting with the casdoor service
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

	err = client.Authenticate()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize server client: %w", err)
	}

	return &client, nil
}

// Authenticate uses client credentials to log in to a slade360 authentication server
func (c *Client) Authenticate() error {
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
		return err
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	var responseData LoginResponse
	err = json.Unmarshal(data, &responseData)
	if err != nil {
		return err
	}

	return nil
}
