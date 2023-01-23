package authutils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ContextKey is used as a type for the UID key for the auth server token on context.Context.
type ContextKey string

const (
	// AuthTokenContextKey is used to add/retrieve the Firebase UID on the context
	AuthTokenContextKey = ContextKey("UID")
)

// GetLoggedInUserUID returns user information as part of OIDC protocol.
func GetLoggedInUserUID(ctx context.Context) (string, error) {
	authToken, err := GetUserTokenFromContext(ctx)
	if err != nil {
		return "", err
	}

	return authToken.UserGUID, nil
}

// GetUserTokenFromContext retrieves a slade360 token from the supplied context
func GetUserTokenFromContext(ctx context.Context) (*TokenIntrospectionResponse, error) {
	val := ctx.Value(AuthTokenContextKey)
	if val == nil {
		return nil, fmt.Errorf(
			"unable to get auth token from context with key %#v", AuthTokenContextKey)
	}

	token, ok := val.(*TokenIntrospectionResponse)
	if !ok {
		return nil, fmt.Errorf("wrong auth token type, got %#v, expected a slade 360 auth token", val)
	}
	return token, nil
}

// decodeOauthResponse extracts the OAUTH data from the passed response body. It is used when generating or refreshing an access token
func decodeOauthResponse(response *http.Response) (*OAUTHResponse, error) {
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode >= 300 || response.StatusCode < 200 {
		msg := fmt.Sprintf(
			"an error occurred while processing your request. detail: %v",
			string(data),
		)
		return nil, fmt.Errorf(msg)
	}

	var responseData OAUTHResponse
	err = json.Unmarshal(data, &responseData)
	if err != nil {
		return nil, err
	}

	return &responseData, nil
}
