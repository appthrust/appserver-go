package launcher

import (
	"context"
	"encoding/json"
	"net/http"
	"unicode/utf8"

	"github.com/appthrust/appserver-go/appserver/httpx"
	"github.com/appthrust/appserver-go/appserver/identity"
	"github.com/appthrust/appserver-go/appserver/launcherentries"
)

// Principal carries the authenticated viewer and bearer to an entry provider.
type Principal struct {
	Subject, Bearer string
	Identity        identity.Identity
}

// Query contains search text whose meaning is owned by the provider.
type Query struct {
	Q string
}

// Source projects provider-owned data into entries visible to the viewer.
type Source interface {
	Entries(ctx context.Context, p Principal, q Query) ([]launcherentries.Entry, error)
}

// NewEntriesHandler serves the shared GET /launcher/entries capability endpoint.
// Providers own authorization and entry mapping; responses are never cacheable.
func NewEntriesHandler(source Source, authenticate AuthenticateFunc) http.Handler {
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
		query := Query{Q: r.URL.Query().Get("q")}
		if utf8.RuneCountInString(query.Q) > 128 {
			httpx.WriteError(w, httpx.Fail(http.StatusBadRequest, "invalid_query", "q must not exceed 128 characters"), "launcher")
			return
		}
		items, err := source.Entries(r.Context(), Principal{
			Subject:  claims.Principal.Subject,
			Bearer:   bearer,
			Identity: claims,
		}, query)
		if err != nil {
			httpx.WriteError(w, err, "launcher")
			return
		}
		if items == nil {
			items = []launcherentries.Entry{}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(launcherentries.EntryList{Items: items})
	})
}
