package launcher

import (
	"context"
	"errors"
	"net/http"

	"github.com/appthrust/appserver-go/appserver/httpx"
	"github.com/appthrust/appserver-go/appserver/identity"
)

type AuthenticateFunc func(ctx context.Context, header string) (identity.Identity, string, error)

// NewHandler serves the shared GET /launcher endpoint.
func NewHandler(catalog *Catalog, authenticate AuthenticateFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			httpx.WriteError(w, httpx.Fail(http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is supported"), "launcher")
			return
		}
		header := r.Header.Get("Authorization")
		if header == "" {
			httpx.WriteError(w, httpx.Fail(http.StatusUnauthorized, "unauthenticated", "A bearer token is required"), "launcher")
			return
		}
		claims, bearer, err := authenticate(r.Context(), header)
		if err != nil {
			identity.WriteError(w, err)
			return
		}
		if claims.Principal.Kind == "key" {
			httpx.WriteError(w, httpx.Fail(http.StatusForbidden, "key_not_permitted", "Access keys cannot list the built-in app launcher"), "launcher")
			return
		}
		snapshot, err := catalog.Load(r.Context(), claims.Principal.Subject, bearer)
		if err != nil {
			var denied *DeniedError
			if errors.As(err, &denied) {
				httpx.WriteError(w, httpx.Fail(denied.Status, "forbidden", "You do not have permission to list this Project's app installations"), "launcher")
			} else {
				httpx.WriteError(w, httpx.Fail(http.StatusServiceUnavailable, "launcher_unavailable", "The built-in app launcher is unavailable"), "launcher")
			}
			return
		}
		httpx.WriteJSON(w, http.StatusOK, snapshot)
	})
}
