package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/appthrust/appserver-go/accesskey"
	"github.com/appthrust/appserver-go/appserver/identity"
	"github.com/appthrust/appserver-go/appserver/platformclient"
)

func assertErrorResponse(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != status || body.Error != code || body.Message == "" {
		t.Fatalf("response = %d %s; want %d error %q and shared httpx message", response.Code, response.Body.String(), status, code)
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("unexpected response headers: %v", response.Header())
	}
}

func TestHandlerMissingAuthorizationDoesNotAuthenticateOrLoadCatalog(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeList(w, []any{})
	}))
	defer server.Close()
	catalog := NewCatalog(platformclient.New(server.URL, "pj-test"), "portal")
	authenticate := func(context.Context, string) (identity.Identity, string, error) {
		t.Error("authentication called without Authorization")
		return identity.Identity{Principal: accesskey.Principal{Kind: "user", Subject: "viewer"}}, "Bearer token", nil
	}
	response := httptest.NewRecorder()
	NewHandler(catalog, authenticate).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/launcher", nil))
	assertErrorResponse(t, response, http.StatusUnauthorized, "unauthenticated")
	if calls.Load() != 0 {
		t.Fatalf("missing authorization reached catalog: %d upstream calls", calls.Load())
	}
}

func TestHandlerAuthenticationFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"invalid bearer", errors.New("invalid token"), http.StatusUnauthorized, "unauthenticated"},
		{"identity unavailable", identity.ErrUnavailable, http.StatusServiceUnavailable, "identity_unavailable"},
		{"wrapped identity unavailable", fmt.Errorf("discovery: %w", identity.ErrUnavailable), http.StatusServiceUnavailable, "identity_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authenticate := func(_ context.Context, header string) (identity.Identity, string, error) {
				if header != "Bearer token" {
					t.Errorf("authenticate header = %q", header)
				}
				return identity.Identity{}, "", tc.err
			}
			// A nil catalog makes any accidental call after auth failure fail immediately.
			handler := NewHandler(nil, authenticate)
			request := httptest.NewRequest(http.MethodGet, "/launcher", nil)
			request.Header.Set("Authorization", "Bearer token")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertErrorResponse(t, response, tc.status, tc.code)
		})
	}
}

func TestHandlerPlatformFailures(t *testing.T) {
	for _, path := range []string{projectPath, installationsPath, definitionsPath} {
		for _, tc := range []struct {
			upstream int
			status   int
			code     string
		}{
			{http.StatusUnauthorized, http.StatusUnauthorized, "forbidden"},
			{http.StatusForbidden, http.StatusForbidden, "forbidden"},
			{http.StatusNotFound, http.StatusServiceUnavailable, "launcher_unavailable"},
			{http.StatusInternalServerError, http.StatusServiceUnavailable, "launcher_unavailable"},
		} {
			t.Run(path+"/"+http.StatusText(tc.upstream), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == path {
						w.WriteHeader(tc.upstream)
						return
					}
					if r.URL.Path == projectPath {
						writeProject(w, "Project")
						return
					}
					writeList(w, []any{})
				}))
				defer server.Close()
				catalog := NewCatalog(platformclient.New(server.URL, "pj-test"), "portal")
				handler := NewHandler(catalog, func(context.Context, string) (identity.Identity, string, error) {
					return identity.Identity{Principal: accesskey.Principal{Kind: "user", Subject: "viewer"}}, "Bearer token", nil
				})
				request := httptest.NewRequest(http.MethodGet, "/launcher", nil)
				request.Header.Set("Authorization", "Bearer token")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				assertErrorResponse(t, response, tc.status, tc.code)
				if tc.code == "forbidden" && !strings.Contains(response.Body.String(), `"message":"You do not have permission to list this Project's app installations"`) {
					t.Fatalf("unexpected built-in app permission message: %s", response.Body.String())
				}
			})
		}
	}
}

func TestHandlerSuccessWireShape(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty=%t", empty), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer normalized" {
					t.Errorf("catalog did not use authenticator bearer: %q", r.Header.Get("Authorization"))
				}
				if r.URL.Path == projectPath {
					writeProject(w, "開発チーム")
					return
				}
				if empty {
					writeList(w, []any{})
					return
				}
				switch r.URL.Path {
				case installationsPath:
					writeList(w, []platformclient.AppInstallation{
						{DefinitionID: "portal", Phase: "Ready", URL: "https://custom.example/home", Display: platformclient.AppInstallationDisplay{Icon: "layout-dashboard"}},
						{DefinitionID: "directory", Dependents: []string{"builder-console"}, Phase: "Degraded", URL: "https://custom.example/people", Display: platformclient.AppInstallationDisplay{Icon: "directory"}},
					})
				case definitionsPath:
					writeList(w, []platformclient.ApplicationStackDefinition{
						{ID: "portal", Title: "Home", Description: "Every installed app"},
						{ID: "directory", Title: "Directory", Description: "People"},
					})
				default:
					t.Errorf("unexpected endpoint: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			catalog := NewCatalog(platformclient.New(server.URL, "pj-test"), "portal")
			handler := NewHandler(catalog, func(_ context.Context, header string) (identity.Identity, string, error) {
				return identity.Identity{Principal: accesskey.Principal{Kind: "user", Subject: strings.TrimPrefix(header, "Bearer ")}}, "Bearer normalized", nil
			})
			for _, subject := range []string{"A", "A", "B"} {
				request := httptest.NewRequest(http.MethodGet, "/launcher", nil)
				request.Header.Set("Authorization", "Bearer "+subject)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Type") != "application/json" {
					t.Fatalf("response = %d %s, headers = %v", response.Code, response.Body.String(), response.Header())
				}
				wantJSON := `{"project":{"id":"pj-test","name":"開発チーム"},"entries":[{"definitionId":"directory","name":"Directory","description":"People","icon":"directory","url":"https://custom.example/people","phase":"Degraded","current":false},{"definitionId":"portal","name":"Home","description":"Every installed app","icon":"layout-dashboard","url":"https://custom.example/home","phase":"Ready","current":true}]}`
				if empty {
					wantJSON = `{"project":{"id":"pj-test","name":"開発チーム"},"entries":[]}`
				}
				var got, want any
				if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal([]byte(wantJSON), &want); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("wire shape = %s; want %s", response.Body.String(), wantJSON)
				}
			}
			if calls.Load() != 6 {
				t.Fatalf("handler did not scope catalog calls by authenticated subject: %d calls", calls.Load())
			}
		})
	}
}

func TestHandlerRejectsNonGET(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions} {
		t.Run(method, func(t *testing.T) {
			// Method rejection precedes both authentication and catalog lookup.
			response := httptest.NewRecorder()
			NewHandler(nil, nil).ServeHTTP(response, httptest.NewRequest(method, "/launcher", nil))
			assertErrorResponse(t, response, http.StatusMethodNotAllowed, "method_not_allowed")
			if response.Header().Get("Allow") != http.MethodGet {
				t.Fatalf("Allow = %q; want GET", response.Header().Get("Allow"))
			}
		})
	}
}
