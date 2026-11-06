package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/appthrust/appserver-go/accesskey"
	"github.com/appthrust/appserver-go/appserver/httpx"
	"github.com/appthrust/appserver-go/appserver/identity"
	"github.com/appthrust/appserver-go/appserver/launcherentries"
)

type entriesSourceFunc func(context.Context, Principal, Query) ([]launcherentries.Entry, error)

func (f entriesSourceFunc) Entries(ctx context.Context, p Principal, q Query) ([]launcherentries.Entry, error) {
	return f(ctx, p, q)
}

func authenticateEntryViewer(_ context.Context, header string) (identity.Identity, string, error) {
	return identity.Identity{Principal: accesskey.Principal{Kind: "user", Subject: "viewer"}}, header, nil
}

func TestEntriesHandlerMissingAuthorization(t *testing.T) {
	response := httptest.NewRecorder()
	// Neither the authenticator nor source may be called without Authorization.
	NewEntriesHandler(nil, nil).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/launcher/entries", nil))
	assertErrorResponse(t, response, http.StatusUnauthorized, "unauthenticated")
}

func TestEntriesHandlerAuthenticationFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		kind   string
		status int
		code   string
	}{
		{"invalid bearer", errors.New("invalid token"), "", http.StatusUnauthorized, "unauthenticated"},
		{"identity unavailable", identity.ErrUnavailable, "", http.StatusServiceUnavailable, "identity_unavailable"},
		{"wrapped identity unavailable", fmt.Errorf("discovery: %w", identity.ErrUnavailable), "", http.StatusServiceUnavailable, "identity_unavailable"},
		{"raw access key", identity.ErrRawKeyNotAccepted, "", http.StatusUnauthorized, "raw_key_not_accepted"},
		{"wrapped raw access key", fmt.Errorf("bearer: %w", identity.ErrRawKeyNotAccepted), "", http.StatusUnauthorized, "raw_key_not_accepted"},
		{"access assertion", nil, "key", http.StatusForbidden, "key_not_permitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authenticate := func(_ context.Context, header string) (identity.Identity, string, error) {
				if header != "Bearer viewer-token" {
					t.Errorf("authenticate header = %q", header)
				}
				return identity.Identity{Principal: accesskey.Principal{Kind: tc.kind}}, header, tc.err
			}
			request := httptest.NewRequest(http.MethodGet, "/launcher/entries", nil)
			request.Header.Set("Authorization", "Bearer viewer-token")
			response := httptest.NewRecorder()
			NewEntriesHandler(nil, authenticate).ServeHTTP(response, request)
			assertErrorResponse(t, response, tc.status, tc.code)
		})
	}
}

func TestEntriesHandlerRejectsNonGET(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			response := httptest.NewRecorder()
			NewEntriesHandler(nil, nil).ServeHTTP(response, httptest.NewRequest(method, "/launcher/entries", nil))
			assertErrorResponse(t, response, http.StatusMethodNotAllowed, "method_not_allowed")
			if response.Header().Get("Allow") != http.MethodGet {
				t.Fatalf("Allow = %q; want GET", response.Header().Get("Allow"))
			}
		})
	}
}

func TestEntriesHandlerQueryRuneLimit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		q       string
		allowed bool
	}{
		{"empty", "", true},
		{"ASCII boundary", strings.Repeat("a", 128), true},
		{"Unicode boundary", strings.Repeat("界", 128), true},
		{"ASCII too long", strings.Repeat("a", 129), false},
		{"Unicode too long", strings.Repeat("界", 129), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			source := entriesSourceFunc(func(_ context.Context, _ Principal, q Query) ([]launcherentries.Entry, error) {
				called = true
				if q.Q != tc.q {
					t.Errorf("query changed: %q", q.Q)
				}
				return nil, nil
			})
			request := httptest.NewRequest(http.MethodGet, "/launcher/entries?q="+url.QueryEscape(tc.q), nil)
			request.Header.Set("Authorization", "Bearer viewer-token")
			response := httptest.NewRecorder()
			NewEntriesHandler(source, authenticateEntryViewer).ServeHTTP(response, request)
			if tc.allowed {
				if response.Code != http.StatusOK {
					t.Fatalf("response = %d %s", response.Code, response.Body.String())
				}
			} else {
				assertErrorResponse(t, response, http.StatusBadRequest, "invalid_query")
			}
			if called != tc.allowed {
				t.Fatalf("source called = %t; want %t", called, tc.allowed)
			}
		})
	}
}

func TestEntriesHandlerSourceErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"forbidden", httpx.Forbidden(), http.StatusForbidden, "forbidden"},
		{"wrapped forbidden", fmt.Errorf("provider: %w", httpx.Forbidden()), http.StatusForbidden, "forbidden"},
		{"unauthorized", httpx.Fail(http.StatusUnauthorized, "viewer_expired", "Viewer token expired"), http.StatusUnauthorized, "viewer_expired"},
		{"unavailable", httpx.Fail(http.StatusServiceUnavailable, "provider_unavailable", "Provider unavailable"), http.StatusServiceUnavailable, "provider_unavailable"},
		{"unexpected", errors.New("database failure"), http.StatusInternalServerError, "internal_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := entriesSourceFunc(func(context.Context, Principal, Query) ([]launcherentries.Entry, error) {
				return nil, tc.err
			})
			request := httptest.NewRequest(http.MethodGet, "/launcher/entries", nil)
			request.Header.Set("Authorization", "Bearer viewer-token")
			response := httptest.NewRecorder()
			NewEntriesHandler(source, authenticateEntryViewer).ServeHTTP(response, request)
			assertErrorResponse(t, response, tc.status, tc.code)
		})
	}
}

func TestEntriesHandlerSuccessWireShape(t *testing.T) {
	claims := identity.Identity{
		Principal: accesskey.Principal{Kind: "user", Subject: "viewer"},
		Email:     "viewer@example.test",
		Name:      "Viewer",
	}
	entries := []launcherentries.Entry{{
		ID:          "app-1",
		Name:        "Expenses",
		Description: "Submit expenses",
		Icon:        "receipt",
		URL:         "https://expenses.example.test",
		DetailURL:   "https://console.example.test/finance/expenses",
		State:       launcherentries.Ready,
		Relation:    launcherentries.Group,
		Group:       &launcherentries.GroupRef{ID: "finance", Name: "Finance", Path: "/finance"},
		Tags:        []string{"finance"},
	}, {
		ID:       "app-2",
		Name:     "Draft",
		State:    launcherentries.Preparing,
		Relation: launcherentries.Owner,
		Tags:     []string{},
	}}
	for _, tc := range []struct {
		name  string
		items []launcherentries.Entry
	}{
		{"populated", entries},
		{"empty", []launcherentries.Entry{}},
		{"nil", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/launcher/entries?q="+url.QueryEscape("  経費 + finance  "), nil)
			request.Header.Set("Authorization", "Bearer incoming-token")
			authenticate := func(ctx context.Context, header string) (identity.Identity, string, error) {
				if ctx != request.Context() || header != "Bearer incoming-token" {
					t.Fatal("authentication did not receive the request context and header")
				}
				return claims, "Bearer verified-token", nil
			}
			called := false
			source := entriesSourceFunc(func(ctx context.Context, p Principal, q Query) ([]launcherentries.Entry, error) {
				called = true
				if ctx != request.Context() || !reflect.DeepEqual(p, Principal{Subject: "viewer", Bearer: "Bearer verified-token", Identity: claims}) {
					t.Fatalf("source principal/context not preserved: %+v", p)
				}
				if q.Q != "  経費 + finance  " {
					t.Fatalf("query not preserved: %q", q.Q)
				}
				return tc.items, nil
			})
			response := httptest.NewRecorder()
			NewEntriesHandler(source, authenticate).ServeHTTP(response, request)
			if !called || response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "private, no-store" || response.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("response = %d %s, headers = %v, source called = %t", response.Code, response.Body.String(), response.Header(), called)
			}
			want := launcherentries.EntryList{Items: tc.items}
			if want.Items == nil {
				want.Items = []launcherentries.Entry{}
			}
			wantJSON, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(response.Body.String()) != string(wantJSON) {
				t.Fatalf("wire shape = %s; want %s", response.Body.String(), wantJSON)
			}
			var got launcherentries.EntryList
			if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip = %+v; want %+v", got, want)
			}
			if len(tc.items) == 0 && response.Body.String() != "{\"items\":[]}\n" {
				t.Fatalf("empty entries must be an array: %s", response.Body.String())
			}
		})
	}
}
