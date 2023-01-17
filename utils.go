package authutils

import (
	"context"
	"fmt"
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
