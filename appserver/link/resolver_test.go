package link

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/appthrust/appserver-go/appserver/platformclient"
)

func TestRequiredEnvironmentShortCircuit(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(http.StatusInternalServerError) }))
	defer server.Close()
	env := map[string]string{"DIRECTORY_URL": "http://directory.internal", "DIRECTORY_PUBLIC_URL": "https://directory.example"}
	resolver := NewResolver(platformclient.New(server.URL, "pj-test"), "tool-builder", func(key string) (string, bool) { value, ok := env[key]; return value, ok }, map[string]Required{"directory": {"DIRECTORY_URL", "DIRECTORY_PUBLIC_URL"}})
	binding, err := resolver.Resolve(context.Background(), "Bearer viewer", "directory")
	if err != nil || binding.State != StateReady || !binding.Required || binding.InternalURL != env["DIRECTORY_URL"] || binding.PublicURL != env["DIRECTORY_PUBLIC_URL"] || calls != 0 {
		t.Fatalf("binding=%+v err=%v calls=%d", binding, err, calls)
	}
}

func TestBindingCacheStatesListExpiryAndInvalidation(t *testing.T) {
	calls := 0
	state := StateAbsent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v1/projects/pj-test/app-installations/tool-builder" || r.Header.Get("Authorization") != "Bearer viewer" {
			t.Errorf("unexpected request %s %v", r.URL.Path, r.Header)
		}
		fmt.Fprintf(w, `{"links":[{"definitionId":"knowledge","state":%q,"internalUrl":"http://knowledge.internal","publicUrl":"https://knowledge.example"},{"definitionId":"console","state":"Unsupported"},{"definitionId":"pending","state":"Installing"}]}`, state)
	}))
	defer server.Close()
	resolver := NewResolver(platformclient.New(server.URL, "pj-test"), "tool-builder", func(key string) (string, bool) { return "http://directory.internal", true }, map[string]Required{"directory": {"DIRECTORY_URL", ""}})
	now := time.Now()
	resolver.now = func() time.Time { return now }
	for range 2 {
		binding, err := resolver.Resolve(context.Background(), "Bearer viewer", "knowledge")
		if err != nil || binding.State != StateAbsent {
			t.Fatalf("absent=%+v %v", binding, err)
		}
	}
	if calls != 1 {
		t.Fatalf("absent not cached: %d", calls)
	}
	items, err := resolver.List(context.Background(), "Bearer viewer")
	if err != nil || len(items) != 4 || calls != 1 || items[0].State != StateUnsupported || items[1].State != StateReady || items[3].State != StateInstalling {
		t.Fatalf("list=%+v %v calls=%d", items, err, calls)
	}
	items[0].State = StateReady
	items, _ = resolver.List(context.Background(), "Bearer viewer")
	if items[0].State != StateUnsupported {
		t.Fatal("caller mutated cache")
	}
	state = StateReady
	now = now.Add(59 * time.Second)
	binding, _ := resolver.Resolve(context.Background(), "Bearer viewer", "knowledge")
	if binding.State != StateAbsent || calls != 1 {
		t.Fatal("cache expired early")
	}
	now = now.Add(time.Second)
	binding, err = resolver.Resolve(context.Background(), "Bearer viewer", "knowledge")
	if err != nil || binding.State != StateReady || calls != 2 {
		t.Fatalf("expired=%+v %v calls=%d", binding, err, calls)
	}
	resolver.Invalidate("knowledge")
	_, err = resolver.Resolve(context.Background(), "Bearer viewer", "knowledge")
	if err != nil || calls != 3 {
		t.Fatalf("invalidation: %v %d", err, calls)
	}
	for range 2 {
		binding, err = resolver.Resolve(context.Background(), "Bearer viewer", "not-declared")
		if err != nil || binding.State != StateAbsent {
			t.Fatalf("undeclared=%+v %v", binding, err)
		}
	}
	if calls != 4 {
		t.Fatalf("missing binding not cached: %d", calls)
	}
}

func TestByCapabilityFiltersSortsAndClonesBindings(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v1/projects/pj-test/app-installations/portal" || r.Header.Get("Authorization") != "opaque-viewer" {
			t.Errorf("unexpected request %s %v", r.URL, r.Header)
		}
		fmt.Fprint(w, `{"links":[
			{"definitionId":"z-ready","state":"Ready","internalUrl":"http://provider.internal","capabilities":["search.entries/v1","launcher.entries/v1"]},
			{"definitionId":"unrelated","state":"Ready","capabilities":["search.entries/v1"]},
			{"definitionId":"b-absent","state":"Absent","capabilities":["launcher.entries/v1"]},
			{"definitionId":"directory","required":true,"state":"Ready","capabilities":["launcher.entries/v1"]},
			{"definitionId":"a-unsupported","state":"Unsupported","capabilities":["launcher.entries/v1"]},
			{"definitionId":"c-installing","state":"Installing","capabilities":["launcher.entries/v1"]}
		]}`)
	}))
	defer server.Close()
	resolver := NewResolver(platformclient.New(server.URL, "pj-test"), "portal",
		func(string) (string, bool) { return "http://directory.internal", true },
		map[string]Required{"directory": {URLEnv: "DIRECTORY_URL"}})
	now := time.Now()
	resolver.now = func() time.Time { return now }
	for _, tc := range []struct {
		capability string
		want       []Binding
	}{
		{"launcher.entries/v1", []Binding{
			{Definition: "a-unsupported", State: StateUnsupported, Capabilities: []string{"launcher.entries/v1"}},
			{Definition: "b-absent", State: StateAbsent, Capabilities: []string{"launcher.entries/v1"}},
			{Definition: "c-installing", State: StateInstalling, Capabilities: []string{"launcher.entries/v1"}},
			{Definition: "z-ready", State: StateReady, InternalURL: "http://provider.internal", Capabilities: []string{"launcher.entries/v1", "search.entries/v1"}},
		}},
		{"search.entries/v1", []Binding{
			{Definition: "unrelated", State: StateReady, Capabilities: []string{"search.entries/v1"}},
			{Definition: "z-ready", State: StateReady, InternalURL: "http://provider.internal", Capabilities: []string{"launcher.entries/v1", "search.entries/v1"}},
		}},
		{"missing/v1", []Binding{}},
		{"", []Binding{}},
	} {
		t.Run(tc.capability, func(t *testing.T) {
			for range 2 {
				bindings, err := resolver.ByCapability(context.Background(), "opaque-viewer", tc.capability)
				if err != nil || !reflect.DeepEqual(bindings, tc.want) || calls != 1 {
					t.Fatalf("bindings=%+v error=%v calls=%d; want %+v", bindings, err, calls, tc.want)
				}
				if len(bindings) > 0 {
					bindings[0].State = StateAbsent
					bindings[0].Capabilities[0] = "mutated/v1"
				}
			}
		})
	}
	// The same cached capability slices must also be isolated from List and
	// Resolve callers, not just capability-filtered callers.
	bindings, err := resolver.List(context.Background(), "opaque-viewer")
	if err != nil || len(bindings) != 6 || len(bindings[3].Capabilities) != 0 {
		t.Fatalf("list=%+v error=%v", bindings, err)
	}
	bindings[0].Capabilities[0] = "mutated/v1"
	for range 2 {
		binding, err := resolver.Resolve(context.Background(), "opaque-viewer", "a-unsupported")
		if err != nil || !reflect.DeepEqual(binding.Capabilities, []string{"launcher.entries/v1"}) {
			t.Fatalf("resolve=%+v error=%v", binding, err)
		}
		binding.Capabilities[0] = "mutated/v1"
	}
	now = now.Add(cacheTTL)
	if _, err := resolver.ByCapability(context.Background(), "opaque-viewer", "launcher.entries/v1"); err != nil || calls != 2 {
		t.Fatalf("expiry error=%v calls=%d", err, calls)
	}
	resolver.Invalidate("z-ready")
	if _, err := resolver.ByCapability(context.Background(), "opaque-viewer", "launcher.entries/v1"); err != nil || calls != 3 {
		t.Fatalf("invalidation error=%v calls=%d", err, calls)
	}
}

func TestResolverErrorClassification(t *testing.T) {
	for _, status := range []int{401, 403, 404, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(status) }))
			defer server.Close()
			resolver := NewResolver(platformclient.New(server.URL, "pj-test"), "tool-builder", nil, nil)
			for range 2 {
				_, err := resolver.Resolve(context.Background(), "Bearer viewer", "knowledge")
				var denied *DeniedError
				var rejected *RejectedError
				switch {
				case status == 401 || status == 403:
					if !errors.As(err, &denied) || denied.Status != status {
						t.Fatalf("denied: %v", err)
					}
				case status == 404:
					if !errors.As(err, &rejected) || rejected.Status != status {
						t.Fatalf("rejected: %v", err)
					}
				default:
					if !errors.Is(err, ErrUnavailable) {
						t.Fatalf("unavailable: %v", err)
					}
				}
			}
			if calls != 2 {
				t.Fatal("failure cached")
			}
			server.Close()
			if _, err := resolver.List(context.Background(), "Bearer viewer"); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("transport: %v", err)
			}
		})
	}
}
