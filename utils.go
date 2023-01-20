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
	val := ctx.Value("UID")
	if val == nil {
		return "", fmt.Errorf("unable to get auth token from context with key: %s", AuthTokenContextKey)
	}

	token, ok := val.(*TokenIntrospectionResponse)
	if !ok {
		return "", fmt.Errorf("wrong auth token type, got %v", token)
	}

	return token.UserGUID, nil
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
