package authutils

// LoginResponse defines the object returned when a user successfully logs in
type LoginResponse struct {
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// LoginPayload defines the payload passed when logging in to casdoor
type LoginPayload struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Username     string `json:"username"`
	Password     string `json:"password"`
}

// CasdoorErrorResponse defines the object returned when casdoor encounters an error
type CasdoorErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// TokenIntrospectionResponse defines the JSON object returned by the CASDOOR service during token introspection
type TokenIntrospectionResponse struct {
	Active    bool     `json:"active"`
	ClientID  string   `json:"client_id"`
	Username  string   `json:"username"`
	TokenType string   `json:"token_type"`
	Exp       int      `json:"exp"`
	Iat       int      `json:"iat"`
	Nbf       int      `json:"nbf"`
	Sub       string   `json:"sub"`
	Aud       []string `json:"aud"`
	Iss       string   `json:"iss"`
	Jti       string   `json:"jti"`
}

// Response defines the JSON object returned by most casdoor APIs
type Response struct {
	Status string      `json:"status"`
	Msg    string      `json:"msg"`
	Sub    string      `json:"sub"`
	Name   string      `json:"name"`
	Data   interface{} `json:"data"`
	Data2  interface{} `json:"data2"`
}
