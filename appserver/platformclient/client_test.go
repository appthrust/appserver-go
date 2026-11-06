package platformclient

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWithHTTPClientTrustsPrivateCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer caller-token" {
			t.Error("request bearer was not forwarded")
		}
		switch r.URL.Path {
		case "/api/v1/projects/pj-test":
			_, _ = w.Write([]byte(`{"teamSlug":"project-team"}`))
		case "/api/v1/teams":
			_, _ = w.Write([]byte(`{"items":[{"id":"team-id","slug":"project-team","role":"Admin"}]}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	_, err := New(server.URL, "pj-test").Access(t.Context(), "subject", "Bearer caller-token")
	var certificateError x509.UnknownAuthorityError
	if !errors.As(err, &certificateError) {
		t.Fatalf("default client must reject the private CA, got %v", err)
	}
	caller := server.Client()
	client := New(server.URL, "pj-test", WithHTTPClient(caller))
	if client.http == caller || client.http.Transport != caller.Transport || client.http.Timeout != 10*time.Second {
		t.Fatal("client must reuse only the supplied transport and retain a 10s timeout")
	}
	access, err := client.Access(t.Context(), "subject", "Bearer caller-token")
	if err != nil || access.TeamID != "team-id" || !access.IsConsoleAdmin || !access.CanCreateApps {
		t.Fatalf("trusted access: %+v %v", access, err)
	}
}

func TestWithHTTPClientKeepsRedirectPolicy(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(w, r, "/redirected", http.StatusFound)
	}))
	defer server.Close()
	caller := &http.Client{Timeout: time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error {
		t.Error("caller redirect policy must not be used")
		return errors.New("caller redirect policy")
	}}
	client := New(server.URL, "pj-test", WithHTTPClient(caller))
	t.Cleanup(client.http.CloseIdleConnections)
	if client.http == caller || client.http.Timeout != 10*time.Second || caller.Transport != nil ||
		client.http.Transport == nil || client.http.Transport == http.DefaultTransport {
		t.Fatal("client must own its policy and clone the default transport when the caller has none")
	}
	_, err := client.Access(t.Context(), "subject", "Bearer caller-token")
	var responseError *HTTPError
	if !errors.As(err, &responseError) || responseError.StatusCode != http.StatusFound || requests.Load() != 1 {
		t.Fatalf("redirect must not be followed: requests=%d err=%v", requests.Load(), err)
	}
}

func TestRolesBearerCacheAndExpiry(t *testing.T) {
	var calls atomic.Int32
	var role atomic.Value
	role.Store("Admin")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer caller-token" {
			t.Error("request bearer was not forwarded")
		}
		switch r.URL.Path {
		case "/api/v1/projects/pj-test":
			_ = json.NewEncoder(w).Encode(map[string]string{"teamSlug": "project-team"})
		case "/api/v1/teams":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{
				map[string]string{"id": "unrelated", "slug": "other-team", "role": "Admin"},
				map[string]string{"id": "matching", "slug": "project-team", "role": role.Load().(string)},
			}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := New(server.URL, "pj-test")
	for range 2 {
		access, err := client.Access(context.Background(), "subject", "Bearer caller-token")
		if err != nil || !access.IsConsoleAdmin || !access.CanCreateApps || access.TeamID != "matching" {
			t.Fatalf("admin access: %+v %v", access, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("60s subject cache missed: %d calls", calls.Load())
	}
	for _, currentRole := range []string{"Editor", "Viewer"} {
		role.Store(currentRole)
		client.mu.Lock()
		client.cache["subject"] = cachedAccess{expires: time.Now().Add(-time.Second)}
		client.mu.Unlock()
		access, err := client.Access(context.Background(), "subject", "Bearer caller-token")
		if err != nil || access.IsConsoleAdmin || access.CanCreateApps != (currentRole == "Editor") {
			t.Fatalf("%s access: %+v %v", currentRole, access, err)
		}
	}
	if calls.Load() != 6 {
		t.Fatalf("expired access was not refreshed: %d", calls.Load())
	}
}

func TestUpstreamFailureIsNotCached(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := New(server.URL, "pj-test")
	for range 2 {
		access, err := client.Access(context.Background(), "subject", "Bearer token")
		if err == nil || access.IsConsoleAdmin || access.CanCreateApps {
			t.Fatalf("failed role lookup granted access: %+v %v", access, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream error cached: %d", calls.Load())
	}
}

func TestProjectDenialIsNotMembershipAndIsCached(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			var projectStatus atomic.Int32
			projectStatus.Store(int32(status))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				switch r.URL.Path {
				case "/api/v1/projects/pj-test":
					if current := int(projectStatus.Load()); current != http.StatusOK {
						w.WriteHeader(current)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"teamSlug": "project-team"})
				case "/api/v1/teams":
					_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{
						map[string]string{"id": "matching", "slug": "project-team", "role": "Editor"},
					}})
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			client := New(server.URL, "pj-test")
			start := time.Now()
			for range 2 {
				access, err := client.Access(context.Background(), "subject", "Bearer token")
				if err != nil || !access.NotMember || access.IsConsoleAdmin || access.CanCreateApps || access.TeamID != "" || access.TeamSlug != "" {
					t.Fatalf("non-member access: %+v %v", access, err)
				}
			}
			if calls.Load() != 1 {
				t.Fatalf("denial was not cached or queried teams: %d calls", calls.Load())
			}
			client.mu.Lock()
			expires := client.cache["subject"].expires
			client.mu.Unlock()
			if expires.Before(start.Add(60*time.Second)) || expires.After(time.Now().Add(60*time.Second)) {
				t.Fatalf("non-member cache lifetime is not 60s: %s", expires)
			}
			projectStatus.Store(http.StatusOK)
			client.mu.Lock()
			client.cache["subject"] = cachedAccess{expires: time.Now().Add(-time.Second)}
			client.mu.Unlock()
			access, err := client.Access(context.Background(), "subject", "Bearer token")
			if err != nil || access.NotMember || !access.CanCreateApps || access.TeamSlug != "project-team" {
				t.Fatalf("expired denial did not refresh membership: %+v %v", access, err)
			}
			if calls.Load() != 3 {
				t.Fatalf("expired denial did not refresh Project and teams: %d", calls.Load())
			}
			projectStatus.Store(int32(status))
			access, err = client.Access(context.Background(), "other-subject", "Bearer other-token")
			if err != nil || !access.NotMember || access.TeamSlug != "project-team" {
				t.Fatalf("non-member lost last known owning Team: %+v %v", access, err)
			}
		})
	}
}

func TestProjectServerFailureKeepsHTTPStatusAndIsNotCached(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	client := New(server.URL, "pj-test")
	for range 2 {
		access, err := client.Access(context.Background(), "subject", "Bearer token")
		var responseError *HTTPError
		if !errors.As(err, &responseError) || responseError.StatusCode != http.StatusInternalServerError ||
			responseError.Path != "/api/v1/projects/pj-test" || access.NotMember {
			t.Fatalf("expected typed Project outage, got %+v %v", access, err)
		}
		if err.Error() != "platform /api/v1/projects/pj-test: HTTP 500" {
			t.Fatalf("unexpected HTTP error: %v", err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("Project outage cached: %d calls", calls.Load())
	}
}

func TestTeamsDenialRemainsAnError(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/projects/pj-test" {
					_ = json.NewEncoder(w).Encode(map[string]string{"teamSlug": "project-team"})
					return
				}
				w.WriteHeader(status)
			}))
			defer server.Close()
			access, err := New(server.URL, "pj-test").Access(context.Background(), "subject", "Bearer token")
			var responseError *HTTPError
			if !errors.As(err, &responseError) || responseError.StatusCode != status ||
				responseError.Path != "/api/v1/teams" || access.NotMember {
				t.Fatalf("teams rejection must remain an error: %+v %v", access, err)
			}
		})
	}
}

func TestCachedNonMemberUsesLatestOwningTeam(t *testing.T) {
	var calls atomic.Int32
	var teamSlug atomic.Value
	teamSlug.Store("first-team")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == "Bearer outsider" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path == "/api/v1/projects/pj-test" {
			_ = json.NewEncoder(w).Encode(map[string]string{"teamSlug": teamSlug.Load().(string)})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{
			map[string]string{"id": "team-id", "slug": teamSlug.Load().(string), "role": "Viewer"},
		}})
	}))
	defer server.Close()
	client := New(server.URL, "pj-test")
	access, err := client.Access(context.Background(), "outsider", "Bearer outsider")
	if err != nil || !access.NotMember || access.TeamSlug != "" {
		t.Fatalf("unknown owning Team: %+v %v", access, err)
	}
	for _, slug := range []string{"first-team", "renamed-team"} {
		teamSlug.Store(slug)
		if _, err := client.Access(context.Background(), slug, "Bearer member"); err != nil {
			t.Fatal(err)
		}
		access, err := client.Access(context.Background(), "outsider", "Bearer outsider")
		if err != nil || !access.NotMember || access.TeamSlug != slug {
			t.Fatalf("cached non-member did not receive latest owning Team %q: %+v %v", slug, access, err)
		}
	}
	if calls.Load() != 5 {
		t.Fatalf("cached non-member performed another upstream read: %d", calls.Load())
	}
}

func TestProjectReadModel(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/projects/pj-test" ||
			r.Header.Get("Authorization") != "bearer caller-token" ||
			r.Header.Get("Accept") != "application/json" || r.Header.Get("Cookie") != "" {
			t.Errorf("unexpected Project request: %s %s %v", r.Method, r.URL.Path, r.Header)
		}
		_, _ = w.Write([]byte(`{"id":"pj-test","name":"開発チーム","teamSlug":"project-team","status":"Ready"}`))
	}))
	defer server.Close()
	client := New(server.URL, "pj-test")
	for range 2 {
		project, err := client.Project(context.Background(), "bearer caller-token")
		if err != nil || project != (Project{ID: "pj-test", Name: "開発チーム"}) {
			t.Fatalf("project = %#v, %v", project, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("Project read must not cache independently: %d calls", calls.Load())
	}
}

func TestProjectReadModelFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "unauthorized", status: http.StatusUnauthorized},
		{name: "forbidden", status: http.StatusForbidden},
		{name: "not found", status: http.StatusNotFound},
		{name: "unavailable", status: http.StatusServiceUnavailable},
		{name: "malformed", body: `{"id":"pj-test","name":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			project, err := New(server.URL, "pj-test").Project(context.Background(), "Bearer token")
			if err == nil || project != (Project{}) {
				t.Fatalf("failure returned Project data: %#v, %v", project, err)
			}
			if tc.status != 0 {
				var responseError *HTTPError
				if !errors.As(err, &responseError) || responseError.StatusCode != tc.status ||
					responseError.Path != "/api/v1/projects/pj-test" {
					t.Fatalf("lost HTTP error status/path: %v", err)
				}
			}
		})
	}
}

func TestAppInstallationReadModels(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "bearer caller-token" ||
			r.Header.Get("Accept") != "application/json" || r.Header.Get("Cookie") != "" {
			t.Errorf("unexpected read-model request: %s %v", r.Method, r.Header)
		}
		switch r.URL.Path {
		case "/api/v1/projects/pj-test/app-installations":
			_, _ = w.Write([]byte(`{"data":[{"id":"directory","projectId":"pj-test","definitionId":"directory","stackId":"directory","display":{"name":"Directory","description":"People","icon":"directory"},"version":"1.4.0","availableVersion":"1.5.0","updatePolicy":"pinned","phase":"UpdateAvailable","url":"https://custom.example/directory","dependencies":[{"definitionId":"database","installation":"database","resolved":true}],"dependents":["builder-console"],"links":[],"capabilities":["launcher.entries/v1"],"conditions":[]}],"meta":{"total":1,"nextCursor":""}}`))
		case "/api/v1/application-stack-definitions":
			_, _ = w.Write([]byte(`{"data":[{"id":"directory","title":"Directory","description":"People and groups","category":"productivity","components":[]}],"meta":{"total":1}}`))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := New(server.URL, "pj-test")
	for range 2 {
		installations, err := client.AppInstallations(context.Background(), "bearer caller-token")
		wantAppInstallations := []AppInstallation{{
			ID: "directory", ProjectID: "pj-test", DefinitionID: "directory", StackID: "directory",
			Display: AppInstallationDisplay{Name: "Directory", Description: "People", Icon: "directory"},
			Version: "1.4.0", AvailableVersion: "1.5.0", UpdatePolicy: "pinned",
			Phase: "UpdateAvailable", URL: "https://custom.example/directory",
			Dependencies: []AppInstallationDependency{{DefinitionID: "database", Installation: "database", Resolved: true}},
			Dependents: []string{"builder-console"}, Links: []AppInstallationLink{}, Capabilities: []string{"launcher.entries/v1"},
		}}
		if err != nil || !reflect.DeepEqual(installations, wantAppInstallations) {
			t.Fatalf("app installations = %#v, %v; want %#v", installations, err, wantAppInstallations)
		}
		definitions, err := client.ApplicationStackDefinitions(context.Background(), "bearer caller-token")
		wantDefinitions := []ApplicationStackDefinition{{
			ID: "directory", Title: "Directory", Description: "People and groups",
		}}
		if err != nil || !reflect.DeepEqual(definitions, wantDefinitions) {
			t.Fatalf("definitions = %#v, %v; want %#v", definitions, err, wantDefinitions)
		}
	}
	if calls.Load() != 4 {
		t.Fatalf("read-model methods must not cache: %d calls", calls.Load())
	}
}

func TestApplicationStacksReadModel(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.EscapedPath() != "/api/v1/projects/pj%2Ftest/application-stacks" ||
			r.Method != http.MethodGet || r.Header.Get("Authorization") != "opaque-viewer" ||
			r.Header.Get("Accept") != "application/json" || r.Header.Get("Cookie") != "" {
			t.Errorf("unexpected request %s %s %v", r.Method, r.URL, r.Header)
		}
		_, _ = w.Write([]byte(`{"data":[
			{"id":"stack-ready","applicationId":"app-one","branchId":"main","webComponentId":"web","state":"ready","publish":{"publicUrl":"https://custom.example/app","tailnetUrl":"https://app.private.example"}},
			{"id":"stack-pending","applicationId":"app-two","branchId":"preview","webComponentId":"frontend","state":"preparing","publish":null}
		],"meta":{"total":2,"nextCursor":""}}`))
	}))
	defer server.Close()
	client := New(server.URL, "pj/test")
	want := []ApplicationStack{
		{ID: "stack-ready", ApplicationID: "app-one", BranchID: "main", WebComponentID: "web", State: "ready",
			Publish: &ApplicationStackPublish{PublicURL: "https://custom.example/app", TailnetURL: "https://app.private.example"}},
		{ID: "stack-pending", ApplicationID: "app-two", BranchID: "preview", WebComponentID: "frontend", State: "preparing"},
	}
	for range 2 {
		stacks, err := client.ApplicationStacks(context.Background(), "opaque-viewer")
		if err != nil || !reflect.DeepEqual(stacks, want) {
			t.Fatalf("stacks=%+v error=%v; want %+v", stacks, err, want)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("stack read must not cache: %d calls", calls.Load())
	}
}

func TestListReadModelFailures(t *testing.T) {
	for _, endpoint := range []struct {
		name string
		path string
		read func(*Client) (int, error)
	}{
		{"app installations", "/api/v1/projects/pj-test/app-installations", func(c *Client) (int, error) {
			items, err := c.AppInstallations(context.Background(), "Bearer token")
			return len(items), err
		}},
		{"definitions", "/api/v1/application-stack-definitions", func(c *Client) (int, error) {
			items, err := c.ApplicationStackDefinitions(context.Background(), "Bearer token")
			return len(items), err
		}},
		{"application stacks", "/api/v1/projects/pj-test/application-stacks", func(c *Client) (int, error) {
			items, err := c.ApplicationStacks(context.Background(), "Bearer token")
			if err == nil && items == nil {
				t.Error("successful stack list is nil")
			}
			return len(items), err
		}},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				body   string
				status int
				want   int
				err    string
			}{
				{name: "empty", body: `{"data":[],"meta":{"total":0}}`},
				{name: "complete", body: `{"data":[{"id":"one"}],"meta":{"total":1}}`, want: 1},
				{name: "total truncated", body: `{"data":[{"id":"one"}],"meta":{"total":2}}`, err: "is truncated"},
				{name: "cursor truncated", body: `{"data":[],"meta":{"total":0,"nextCursor":"more"}}`, err: "is truncated"},
				{name: "missing data", body: `{"meta":{"total":0}}`, err: "has no data"},
				{name: "null data", body: `{"data":null}`, err: "has no data"},
				{name: "invalid JSON", body: `{`, err: "unexpected EOF"},
				{name: "unauthorized", status: http.StatusUnauthorized, err: "HTTP 401"},
				{name: "forbidden", status: http.StatusForbidden, err: "HTTP 403"},
				{name: "unavailable", status: http.StatusServiceUnavailable, err: "HTTP 503"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path != endpoint.path {
							t.Errorf("path = %q; want %q", r.URL.Path, endpoint.path)
						}
						if tc.status != 0 {
							w.WriteHeader(tc.status)
						}
						_, _ = w.Write([]byte(tc.body))
					}))
					defer server.Close()
					count, err := endpoint.read(New(server.URL, "pj-test"))
					if tc.err == "" {
						if err != nil || count != tc.want {
							t.Fatalf("read = %d, %v; want %d, nil", count, err, tc.want)
						}
						return
					}
					if err == nil || !strings.Contains(err.Error(), tc.err) || count != 0 {
						t.Fatalf("read = %d, %v; want no partial data and error containing %q", count, err, tc.err)
					}
					if tc.status != 0 {
						var responseError *HTTPError
						if !errors.As(err, &responseError) || responseError.StatusCode != tc.status || responseError.Path != endpoint.path {
							t.Fatalf("lost HTTP error status/path: %v", err)
						}
					}
				})
			}
		})
	}
}

func TestReadModelsDoNotFollowRedirects(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer server.Close()
	client := New(server.URL, "pj-test")
	if _, err := client.Project(context.Background(), "Bearer secret"); err == nil {
		t.Fatal("project redirect was accepted")
	}
	if _, err := client.AppInstallations(context.Background(), "Bearer secret"); err == nil {
		t.Fatal("app installations redirect was accepted")
	}
	if _, err := client.ApplicationStackDefinitions(context.Background(), "Bearer secret"); err == nil {
		t.Fatal("definitions redirect was accepted")
	}
	if _, err := client.ApplicationStacks(context.Background(), "Bearer secret"); err == nil {
		t.Fatal("application stacks redirect was accepted")
	}
	if redirected.Load() != 0 {
		t.Fatal("read-model request followed redirect")
	}
}
