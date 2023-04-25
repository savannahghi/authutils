package authutils

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/savannahghi/serverutils"
)

// authCheckFn is a function type for authorization and authentication checks
// there can be several e.g an authentication check runs first then an authorization
// check runs next if the authentication passes etc
type authCheckFn = func(
	ctx context.Context,
	r *http.Request,
) (bool, map[string]string, *TokenIntrospectionResponse)

// SladeAuthenticationMiddleware is responsible for validating user's authentication credentials before allowing access to protected routes.
// It uses the provided authentication service to check the user's token
// and ensure it is valid and has the necessary permissions for the requested resource
func SladeAuthenticationMiddleware(c Client) func(http.Handler) http.Handler {
	// multiple checks will be run in sequence (order matters)
	// the first check to succeed will call `c.Next()` and `return`
	// this means that more permissive checks (e.g exceptions) should come first
	checkFuncs := []authCheckFn{c.HasValidSlade360BearerToken}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				errs := []map[string]string{}
				// in case authorization does not succeed, accumulated errors
				// are returned to the client
				for _, checkFunc := range checkFuncs {
					shouldContinue, errMap, authToken := checkFunc(r.Context(), r)
					if shouldContinue {
						// put the auth token in the context
						ctx := context.WithValue(r.Context(), AuthTokenContextKey, authToken)

						// and call the next with our new context
						r = r.WithContext(ctx)
						next.ServeHTTP(w, r)
						return
					}
					errs = append(errs, errMap)
				}

				// if we got here, it is because we have errors.
				// write an error response)
				serverutils.WriteJSONResponse(w, errs, http.StatusUnauthorized)
			},
		)
	}
}

// SladeAuthenticationGinMiddleware is an authentication middleware for servers using Gin. It checks the user token and ensures
// that it is valid
func SladeAuthenticationGinMiddleware(cl Client) gin.HandlerFunc {
	checkFuncs := []authCheckFn{cl.HasValidSlade360BearerToken}
	return func(c *gin.Context) {
		errs := []map[string]string{}

		for _, checkFunc := range checkFuncs {
			shouldContinue, errMap, authToken := checkFunc(c.Request.Context(), c.Request)

			if shouldContinue {
				ctx := context.WithValue(c.Request.Context(), AuthTokenContextKey, authToken)
				c.Request = c.Request.WithContext(ctx)
				c.Next()
				return
			}

			errs = append(errs, errMap)
		}

		serverutils.WriteJSONResponse(c.Writer, errs, http.StatusUnauthorized)
		c.Abort()
	}
}
