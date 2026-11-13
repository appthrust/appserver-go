package identity

import (
	"context"
	"errors"
	"net/http"

	"github.com/appthrust/appserver-go/appserver/httpx"
)

type identityContextKey struct{}

// FromContext returns the identity established by Authenticator.Middleware.
func FromContext(ctx context.Context) (Identity, bool) {
	value, ok := ctx.Value(identityContextKey{}).(Identity)
	return value, ok
}

// Middleware authenticates a network bearer and makes its identity available
// through FromContext. AppAccessConfig.RequirePermissions enables the default
// declared-app guard for every authenticated request.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value, _, err := a.Authenticate(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			WriteError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityContextKey{}, value)))
	})
}

// RequireAppAccess is an opt-in guard inside Authenticator.Middleware. People
// with no scope are denied only when the installation declares roles. An absent
// exchange result fails closed; key principals retain their existing behavior.
// Endpoints must still check Principal.Has for their specific permission.
func RequireAppAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value, ok := FromContext(r.Context())
		if !ok {
			WriteError(w, httpx.Fail(http.StatusUnauthorized, "unauthenticated", "A valid bearer token is required"))
			return
		}
		if err := checkAppAccess(value); err != nil {
			WriteError(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func checkAppAccess(value Identity) error {
	if value.Principal.Kind == "key" {
		return nil
	}
	if value.Access == nil {
		return accessUnavailable("")
	}
	if value.Access.Declared && len(value.Principal.Scopes) == 0 {
		return httpx.Forbidden()
	}
	return nil
}

// WriteError writes an Authenticate error using the shared API envelope. Custom
// middleware should use this helper to preserve access_unavailable and retry hints.
func WriteError(w http.ResponseWriter, err error) {
	var apiError *httpx.Error
	switch {
	case errors.As(err, &apiError):
		// Exchange and authorization errors already have safe public messages.
	case errors.Is(err, ErrUnavailable):
		err = httpx.Fail(http.StatusServiceUnavailable, "identity_unavailable", "Identity verification is unavailable")
	case errors.Is(err, ErrRawKeyNotAccepted):
		err = httpx.Fail(http.StatusUnauthorized, "raw_key_not_accepted", "Exchange the access key for an assertion before calling this API")
	default:
		err = httpx.Fail(http.StatusUnauthorized, "unauthenticated", "A valid bearer token is required")
	}
	httpx.WriteError(w, err, "identity")
}
