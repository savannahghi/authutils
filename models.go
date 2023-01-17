package authutils

import "time"

// LoginResponse defines the object returned when a user successfully logs in
type LoginResponse struct {
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// LoginPayload defines the payload passed when logging in to slade 360 auth server
type LoginPayload struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Username     string `json:"username"`
	Password     string `json:"password"`
}

// TokenIntrospectionResponse defines the JSON object returned by slade auth server service during token introspection
type TokenIntrospectionResponse struct {
	ClientID string    `json:"client_id"`
	Expires  time.Time `json:"expires"`
	IsValid  bool      `json:"is_valid"`
	Scope    string    `json:"scope"`
	Token    string    `json:"token"`
	UserGUID string    `json:"user_guid"`
}

// TokenIntrospectionPayload defines the json object passed when introspecting a token
type TokenIntrospectionPayload struct {
	TokenType string `json:"token_type"`
	Token     string `json:"token"`
}
