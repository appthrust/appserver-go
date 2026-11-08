package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/appthrust/appserver-go/appserver/platformclient"
)

const (
	projectPath       = "/api/v1/projects/pj-test"
	installationsPath = "/api/v1/projects/pj-test/app-installations"
	definitionsPath   = "/api/v1/application-stack-definitions"
)

func writeList(w http.ResponseWriter, data any) {
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func writeProject(w http.ResponseWriter, name string) {
	_ = json.NewEncoder(w).Encode(platformclient.Project{ID: "pj-test", Name: name})
}

func TestCatalogJoinCurrentAndSort(t *testing.T) {
	installations := []platformclient.AppInstallation{
		{ID: "tool-builder", DefinitionID: "tool-builder", Phase: "UpdateAvailable", URL: "https://custom.example/tools", Display: platformclient.AppInstallationDisplay{Icon: "wrench"}},
		{ID: "missing", DefinitionID: "missing", Phase: "Degraded", URL: ""},
		{ID: "knowledge", DefinitionID: "knowledge", Phase: "Pending", URL: "https://custom.example/knowledge", Display: platformclient.AppInstallationDisplay{Icon: "book"}},
		{ID: "portal", DefinitionID: "portal", Phase: "Ready", URL: "https://custom.example/home", Display: platformclient.AppInstallationDisplay{Name: "Home", Description: "Every installed app", Icon: "layout-dashboard"}},
		{ID: "directory", DefinitionID: "directory", Dependents: []string{"builder-console"}, Phase: "Degraded", URL: "https://custom.example/people", Display: platformclient.AppInstallationDisplay{Icon: "directory"}},
	}
	definitions := []platformclient.ApplicationStackDefinition{
		{ID: "portal", Title: "Catalog Home", Description: "The installation display takes precedence", Locales: map[string]platformclient.DefinitionLocale{"ja": {Title: "ホーム", Tagline: "インストール済みのアプリ"}}},
		{ID: "tool-builder", Title: "Shared", Description: "Tools"},
		{ID: "knowledge", Title: "Shared", Description: "Knowledge"},
		{ID: "directory", Title: "Directory", Description: "People"},
		{ID: "not-installed", Title: "Not installed"},
	}
	for _, self := range []string{"portal", "directory", "not-installed"} {
		t.Run(self, func(t *testing.T) {
			var paths []string
			var mu sync.Mutex
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				paths = append(paths, r.URL.Path)
				mu.Unlock()
				if r.Header.Get("Authorization") != "bearer viewer" {
					t.Error("viewer bearer was not forwarded verbatim")
				}
				switch r.URL.Path {
				case projectPath:
					writeProject(w, "開発チーム")
				case installationsPath:
					writeList(w, installations)
				case definitionsPath:
					writeList(w, definitions)
				default:
					t.Errorf("unexpected endpoint %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			catalog := NewCatalog(platformclient.New(server.URL, "pj-test"), self)
			snapshot, err := catalog.Load(context.Background(), "viewer", "bearer viewer")
			want := []Entry{
				{DefinitionID: "directory", Name: "Directory", Description: "People", Icon: "directory", URL: "https://custom.example/people", Phase: "Degraded", Current: self == "directory"},
				{DefinitionID: "portal", Name: "Home", Description: "Every installed app", Icon: "layout-dashboard", URL: "https://custom.example/home", Phase: "Ready", Current: self == "portal", Locales: map[string]EntryLocale{"ja": {Title: "ホーム", Tagline: "インストール済みのアプリ"}}},
				{DefinitionID: "knowledge", Name: "Shared", Description: "Knowledge", Icon: "book", URL: "https://custom.example/knowledge", Phase: "Pending"},
				{DefinitionID: "tool-builder", Name: "Shared", Description: "Tools", Icon: "wrench", URL: "https://custom.example/tools", Phase: "UpdateAvailable"},
				{DefinitionID: "missing", Name: "missing", Phase: "Degraded"},
			}
			if err != nil || snapshot.Project != (Project{ID: "pj-test", Name: "開発チーム"}) || !reflect.DeepEqual(snapshot.Entries, want) {
				t.Fatalf("snapshot = %#v, %v; want project and entries %#v", snapshot, err, want)
			}
			encoded, err := json.Marshal(snapshot.Entries)
			if err != nil {
				t.Fatal(err)
			}
			var entries []map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &entries); err != nil {
				t.Fatal(err)
			}
			for i, entry := range entries {
				locales, found := entry["locales"]
				if snapshot.Entries[i].DefinitionID != "portal" {
					if found {
						t.Fatalf("entry without localized copy includes locales: %s", locales)
					}
					continue
				}
				var got map[string]EntryLocale
				if err := json.Unmarshal(locales, &got); err != nil || !reflect.DeepEqual(got, want[i].Locales) {
					t.Fatalf("localized JSON = %s, %v; want %#v", locales, err, want[i].Locales)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if !reflect.DeepEqual(paths, []string{projectPath, installationsPath, definitionsPath}) {
				t.Fatalf("request order = %v", paths)
			}
		})
	}
}

func TestCatalogSubjectCacheAndInvalidation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == projectPath {
			writeProject(w, r.Header.Get("Authorization"))
			return
		}
		if r.URL.Path == installationsPath {
			writeList(w, []platformclient.AppInstallation{{DefinitionID: r.Header.Get("Authorization"), Phase: "Ready"}})
			return
		}
		writeList(w, []platformclient.ApplicationStackDefinition{{
			ID:      r.Header.Get("Authorization"),
			Locales: map[string]platformclient.DefinitionLocale{"ja": {Title: "アプリ", Tagline: "説明"}},
		}})
	}))
	defer server.Close()
	catalog := NewCatalog(platformclient.New(server.URL, "pj-test"), "portal")
	for _, tc := range []struct {
		subject string
		bearer  string
		want    string
		calls   int32
	}{
		{"A", "Bearer A", "Bearer A", 3},
		{"B", "Bearer B", "Bearer B", 6},
		{"A", "Bearer refreshed-A", "Bearer A", 6},
		{"B", "Bearer refreshed-B", "Bearer B", 6},
	} {
		snapshot, err := catalog.Load(context.Background(), tc.subject, tc.bearer)
		if err != nil || len(snapshot.Entries) != 1 || snapshot.Entries[0].DefinitionID != tc.want ||
			snapshot.Project != (Project{ID: "pj-test", Name: tc.want}) || calls.Load() != tc.calls {
			t.Fatalf("subject %s: snapshot = %#v, %v, calls = %d", tc.subject, snapshot, err, calls.Load())
		}
		if got := snapshot.Entries[0].Locales["ja"]; len(snapshot.Entries[0].Locales) != 1 || got != (EntryLocale{Title: "アプリ", Tagline: "説明"}) {
			t.Fatalf("subject %s: localized copy = %#v", tc.subject, got)
		}
		// Both cache hits and misses must return caller-owned snapshots.
		snapshot.Entries[0].DefinitionID = "caller mutation"
		snapshot.Project.Name = "caller mutation"
		snapshot.Entries[0].Locales["ja"] = EntryLocale{Title: "caller mutation"}
		delete(snapshot.Entries[0].Locales, "ja")
		snapshot.Entries[0].Locales["en"] = EntryLocale{Title: "caller addition"}
	}
	catalog.Invalidate("absent")
	catalog.Invalidate("A")
	snapshot, err := catalog.Load(context.Background(), "A", "Bearer refreshed-A")
	if err != nil || len(snapshot.Entries) != 1 || snapshot.Entries[0].DefinitionID != "Bearer refreshed-A" ||
		snapshot.Project.Name != "Bearer refreshed-A" || calls.Load() != 9 {
		t.Fatalf("invalidate A: snapshot = %#v, %v, calls = %d", snapshot, err, calls.Load())
	}
	snapshot, err = catalog.Load(context.Background(), "B", "Bearer refreshed-B")
	if err != nil || len(snapshot.Entries) != 1 || snapshot.Entries[0].DefinitionID != "Bearer B" ||
		snapshot.Project.Name != "Bearer B" || calls.Load() != 9 {
		t.Fatalf("invalidate A affected B: snapshot = %#v, %v, calls = %d", snapshot, err, calls.Load())
	}
}

func TestCatalogTTLAndEmptyCache(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty=%t", empty), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path == projectPath {
					writeProject(w, fmt.Sprintf("Project %d", calls.Load()))
					return
				}
				if r.URL.Path == installationsPath && !empty {
					writeList(w, []platformclient.AppInstallation{{DefinitionID: "directory", Phase: "Ready"}})
					return
				}
				writeList(w, []any{})
			}))
			defer server.Close()
			catalog := NewCatalog(platformclient.New(server.URL, "pj-test"), "portal")
			start := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
			now := start
			catalog.now = func() time.Time { return now }
			for _, tc := range []struct {
				elapsed time.Duration
				calls   int32
			}{
				{0, 3},
				{60*time.Second - time.Nanosecond, 3},
				{60 * time.Second, 6},
				{120*time.Second - time.Nanosecond, 6},
				{120 * time.Second, 9},
			} {
				now = start.Add(tc.elapsed)
				snapshot, err := catalog.Load(context.Background(), "viewer", "Bearer token")
				if err != nil || snapshot.Entries == nil || (len(snapshot.Entries) == 0) != empty ||
					snapshot.Project.Name != fmt.Sprintf("Project %d", tc.calls-2) || calls.Load() != tc.calls {
					t.Fatalf("at %s: snapshot = %#v, %v, calls = %d; want %d calls", tc.elapsed, snapshot, err, calls.Load(), tc.calls)
				}
			}
		})
	}
}

func TestCatalogProjectNameFallsBackToID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == projectPath {
			writeProject(w, "")
			return
		}
		writeList(w, []any{})
	}))
	defer server.Close()
	catalog := NewCatalog(platformclient.New(server.URL, "pj-test"), "portal")
	for range 2 {
		snapshot, err := catalog.Load(context.Background(), "viewer", "Bearer token")
		if err != nil || snapshot.Project != (Project{ID: "pj-test", Name: "pj-test"}) || snapshot.Entries == nil {
			t.Fatalf("Project name fallback = %#v, %v", snapshot, err)
		}
	}
}

func TestCatalogEvictsOldestExpiryAt1024Subjects(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == projectPath {
			writeProject(w, "Project")
			return
		}
		writeList(w, []any{})
	}))
	defer server.Close()
	catalog := NewCatalog(platformclient.New(server.URL, "pj-test"), "portal")
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	catalog.now = func() time.Time { return now }
	load := func(subject string) {
		t.Helper()
		if _, err := catalog.Load(context.Background(), subject, "Bearer token"); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 1024 {
		load(fmt.Sprintf("subject-%04d", i))
		now = now.Add(time.Millisecond)
	}
	if len(catalog.cache) != 1024 || calls.Load() != 3072 {
		t.Fatalf("cache capacity = %d, calls = %d", len(catalog.cache), calls.Load())
	}
	// A cache hit does not renew expiry or turn eviction into LRU.
	load("subject-0000")
	load("new-subject")
	if _, found := catalog.cache["subject-0000"]; found || len(catalog.cache) != 1024 {
		t.Fatalf("oldest expiry not evicted; size = %d, oldest present = %t", len(catalog.cache), found)
	}
	load("subject-0001")
	if calls.Load() != 3075 {
		t.Fatalf("non-oldest subject was evicted or oldest cache hit missed: %d calls", calls.Load())
	}
	load("subject-0000")
	if calls.Load() != 3078 || len(catalog.cache) != 1024 {
		t.Fatalf("evicted subject did not reload within capacity: %d calls, %d subjects", calls.Load(), len(catalog.cache))
	}
}

func TestCatalogFailureClassificationAndNoFailureCache(t *testing.T) {
	for _, failedPath := range []string{projectPath, installationsPath, definitionsPath} {
		for _, tc := range []struct {
			name     string
			status   int
			body     string
			denied   int
			listOnly bool
		}{
			{name: "unauthorized", status: http.StatusUnauthorized, denied: http.StatusUnauthorized},
			{name: "forbidden", status: http.StatusForbidden, denied: http.StatusForbidden},
			{name: "not found", status: http.StatusNotFound},
			{name: "server failure", status: http.StatusInternalServerError},
			{name: "total truncated", body: `{"data":[{"id":"one"}],"meta":{"total":2}}`, listOnly: true},
			{name: "cursor truncated", body: `{"data":[],"meta":{"total":0,"nextCursor":"next"}}`, listOnly: true},
			{name: "malformed", body: `{`},
			{name: "missing data", body: `{}`, listOnly: true},
		} {
			if failedPath == projectPath && tc.listOnly {
				continue
			}
			t.Run(failedPath+"/"+tc.name, func(t *testing.T) {
				var attempts atomic.Int32
				var recovered atomic.Bool
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == failedPath {
						attempts.Add(1)
						if !recovered.Load() {
							if tc.status != 0 {
								w.WriteHeader(tc.status)
							}
							_, _ = w.Write([]byte(tc.body))
							return
						}
					}
					if r.URL.Path == projectPath {
						writeProject(w, "Project")
						return
					}
					writeList(w, []any{})
				}))
				defer server.Close()
				catalog := NewCatalog(platformclient.New(server.URL, "pj-test"), "portal")
				for range 2 {
					snapshot, err := catalog.Load(context.Background(), "viewer", "Bearer token")
					if snapshot.Entries != nil || snapshot.Project != (Project{}) || err == nil {
						t.Fatalf("failure returned partial snapshot: %#v, %v", snapshot, err)
					}
					if tc.denied != 0 {
						var denied *DeniedError
						if !errors.As(err, &denied) || denied.Status != tc.denied || err.Error() != fmt.Sprintf("launcher denied: HTTP %d", tc.denied) {
							t.Fatalf("denial was not preserved: %v", err)
						}
					} else if !errors.Is(err, ErrUnavailable) || err.Error() != "launcher unavailable" {
						t.Fatalf("want ErrUnavailable; got %v", err)
					}
				}
				if attempts.Load() != 2 || len(catalog.cache) != 0 {
					t.Fatalf("failure cached: attempts = %d, cache size = %d", attempts.Load(), len(catalog.cache))
				}
				recovered.Store(true)
				for range 2 {
					snapshot, err := catalog.Load(context.Background(), "viewer", "Bearer token")
					if err != nil || snapshot.Entries == nil || len(snapshot.Entries) != 0 || snapshot.Project.Name != "Project" {
						t.Fatalf("recovery = %#v, %v", snapshot, err)
					}
				}
				if attempts.Load() != 3 {
					t.Fatalf("recovered success not cached: %d attempts", attempts.Load())
				}
			})
		}
	}
}

func TestCatalogTransportFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close()
	catalog := NewCatalog(platformclient.New(server.URL, "pj-test"), "portal")
	for range 2 {
		snapshot, err := catalog.Load(context.Background(), "viewer", "Bearer token")
		if !errors.Is(err, ErrUnavailable) || snapshot.Entries != nil || snapshot.Project != (Project{}) || len(catalog.cache) != 0 {
			t.Fatalf("transport failure = %#v, %v", snapshot, err)
		}
	}
}

func TestCatalogDoesNotHoldLockDuringPlatformRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == projectPath && r.Header.Get("Authorization") == "Bearer slow" {
			close(started)
			<-release
		}
		if r.URL.Path == projectPath {
			writeProject(w, "Project")
			return
		}
		writeList(w, []any{})
	}))
	defer server.Close()
	catalog := NewCatalog(platformclient.New(server.URL, "pj-test"), "portal")
	slow := make(chan error, 1)
	defer func() {
		close(release)
		select {
		case err := <-slow:
			if err != nil {
				t.Errorf("slow Platform request failed after release: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("slow Platform request did not finish after release")
		}
	}()
	go func() {
		_, err := catalog.Load(context.Background(), "slow", "Bearer slow")
		slow <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("slow Platform request did not start")
	}
	fast := make(chan error, 1)
	go func() {
		_, err := catalog.Load(context.Background(), "fast", "Bearer fast")
		catalog.Invalidate("fast")
		fast <- err
	}()
	select {
	case err := <-fast:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("another subject's request or invalidation blocked on the Platform round-trip")
	}
}
