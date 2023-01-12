package authutils

import (
	"context"
	"fmt"

	"github.com/savannahghi/firebasetools"
)

// GetLoggedInUserUID returns user information as part of OIDC protocol.
func GetLoggedInUserUID(ctx context.Context) (string, error) {
	val := ctx.Value(firebasetools.AuthTokenContextKey)
	if val == nil {
		return "", fmt.Errorf("unable to get auth token from context with key: %s", firebasetools.AuthTokenContextKey)
	}

	token, ok := val.(*TokenIntrospectionResponse)
	if !ok {
		return "", fmt.Errorf("wrong auth token type, got %v", token)
	}

	return token.Sub, nil
}
