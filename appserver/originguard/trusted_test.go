package originguard

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestNewTrustedOrigins(t *testing.T) {
	for _, tc := range []struct {
		name    string
		origin  string
		options Options
		want    string
	}{
		{"HTTPS", "https://console.example.com", Options{}, "https://console.example.com"},
		{"case and default port", "HTTPS://CONSOLE.EXAMPLE.COM:00443", Options{}, "https://console.example.com"},
		{"nondefault port", "https://console.example.com:08443", Options{}, "https://console.example.com:8443"},
		{"A-label", "https://XN--BCHER-KVA.EXAMPLE", Options{}, "https://xn--bcher-kva.example"},
		{"IPv4", "https://127.0.0.1:443", Options{}, "https://127.0.0.1"},
		{"IPv6", "https://[2001:0DB8:0:0::1]:443", Options{}, "https://[2001:db8::1]"},
		{"localhost opt in", "HTTP://LOCALHOST:80", Options{AllowLoopbackHTTP: true}, "http://localhost"},
		{"IPv4 loopback opt in", "http://127.0.0.2:8080", Options{AllowLoopbackHTTP: true}, "http://127.0.0.2:8080"},
		{"IPv6 loopback opt in", "http://[0:0:0:0:0:0:0:1]:8080", Options{AllowLoopbackHTTP: true}, "http://[::1]:8080"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trusted, err := NewTrustedOrigins([]string{tc.origin}, tc.options)
			if err != nil {
				t.Fatal(err)
			}
			if got := trusted.Origins(); !reflect.DeepEqual(got, []string{tc.want}) {
				t.Fatalf("Origins = %v, want %q", got, tc.want)
			}
			for _, origin := range []string{tc.origin, tc.want} {
				if got := CheckOrigin([]string{origin}, trusted); !got.Allowed {
					t.Fatalf("configured equivalent %q denied: %+v", origin, got)
				}
			}
		})
	}
}

func TestNewTrustedOriginsRejectsInvalid(t *testing.T) {
	invalid := []string{
		"", "null", "console.example.com", "//console.example.com", "https:console.example.com",
		"http://console.example.com", "ftp://console.example.com", "ws://console.example.com", "wss://console.example.com",
		"https://bücher.example", "https://ｃonsole.example.com", "https://console.example.com。",
		"https://console.example.com.", "https://console.example.com..", "https://.example.com",
		"https://console..example.com", "https://*.example.com", "https://under_score.example.com",
		"https://-console.example.com", "https://console-.example.com",
		"https://user@console.example.com", "https://user:pass@console.example.com",
		"https://console.example.com/", "https://console.example.com/path",
		"https://console.example.com?", "https://console.example.com?query=value",
		"https://console.example.com#", "https://console.example.com#fragment",
		"https://%63onsole.example.com", "https://console%2eexample.com", "https://console.example.com%2f",
		"https://console.example.com\\evil", "https://console.example.com\n",
		" https://console.example.com", "https://console.example.com ", "https://console.example.com\x7f",
		"https://console.example.com,https://other.example.com",
		"https://console.example.com https://other.example.com",
		"https://console.example.com:", "https://console.example.com:0", "https://console.example.com:65536",
		"https://console.example.com:-1", "https://console.example.com:+443", "https://console.example.com:abc",
		"https://", "https://:443", "https://[example.com]", "https://[127.0.0.1]",
		"https://::1", "https://[::1", "https://[fe80::1%25eth0]",
		"https://" + strings.Repeat("a", 64) + ".example.com",
		"https://" + strings.Repeat(strings.Repeat("a", 63)+".", 4) + "com",
	}
	for _, origin := range invalid {
		t.Run(origin, func(t *testing.T) {
			// A later bad URL must not leave a usable partial allowlist.
			trusted, err := NewTrustedOrigins([]string{"https://console.example.com", origin}, Options{})
			if err == nil {
				t.Fatalf("accepted invalid trusted origin %q", origin)
			}
			if len(trusted.Origins()) != 0 || CheckOrigin([]string{"https://console.example.com"}, trusted).Allowed {
				t.Fatal("construction error returned a partially trusted set")
			}
			if got := CheckOrigin([]string{origin}, testTrusted(t, "https://console.example.com")); got.Reason != RequestOriginNotAllowed || got.Allowed {
				t.Fatalf("invalid incoming origin decision = %+v", got)
			}
		})
	}
}

func TestLoopbackHTTPRequiresExplicitTrust(t *testing.T) {
	for _, origin := range []string{"http://localhost", "http://127.0.0.1", "http://[::1]"} {
		if _, err := NewTrustedOrigins([]string{origin}, Options{}); err == nil {
			t.Fatalf("HTTP loopback %q accepted without opt in", origin)
		}
	}
	for _, origin := range []string{
		"http://console.example.com", "http://localhost.evil.test", "http://dev.localhost",
		"http://192.168.0.1", "http://0.0.0.0", "http://[::]", "http://127.1", "http://2130706433",
	} {
		if _, err := NewTrustedOrigins([]string{origin}, Options{AllowLoopbackHTTP: true}); err == nil {
			t.Fatalf("non-loopback %q accepted with loopback opt in", origin)
		}
	}
	trusted, err := NewTrustedOrigins([]string{"http://localhost:8080"}, Options{AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"http://localhost:8081", "http://127.0.0.1:8080", "https://localhost:8080", "http://[::1]:8080"} {
		if CheckOrigin([]string{origin}, trusted).Allowed {
			t.Fatalf("loopback opt in implicitly trusted %q", origin)
		}
	}
}

func TestTrustedOriginsImmutable(t *testing.T) {
	input := []string{"https://console.example.com:443", "https://CONSOLE.example.com", "https://dashboard.example.com"}
	trusted, err := NewTrustedOrigins(input, Options{})
	if err != nil {
		t.Fatal(err)
	}
	input[0] = "https://evil.example.com"
	copy := trusted
	origins := copy.Origins()
	if !reflect.DeepEqual(origins, []string{"https://console.example.com", "https://dashboard.example.com"}) {
		t.Fatalf("normalized sorted deduplicated origins = %v", origins)
	}
	origins[0] = "https://evil.example.com"
	if !CheckOrigin([]string{"https://console.example.com"}, trusted).Allowed || CheckOrigin([]string{"https://evil.example.com"}, copy).Allowed {
		t.Fatal("caller mutated immutable trusted origins")
	}
}

func TestSnapshotReadiness(t *testing.T) {
	var source Snapshot
	if _, ready := source.Load(); ready {
		t.Fatal("zero snapshot is ready")
	}
	source.Store(testTrusted(t))
	if trusted, ready := source.Load(); !ready || len(trusted.Origins()) != 0 {
		t.Fatal("constructed empty snapshot must be ready")
	}
	source.Store(testTrusted(t, "https://console.example.com"))
	old, ready := source.Load()
	if !ready {
		t.Fatal("stored snapshot not ready")
	}
	invalid, err := NewTrustedOrigins([]string{"https://bücher.example"}, Options{})
	if err == nil {
		t.Fatal("Unicode trusted input accepted")
	}
	source.Store(invalid)
	if _, ready := source.Load(); ready {
		t.Fatal("construction error retained readiness")
	}
	if !CheckOrigin([]string{"https://console.example.com"}, old).Allowed {
		t.Fatal("snapshot replacement mutated an existing reader's snapshot")
	}
}

func TestSnapshotConcurrentReplacement(t *testing.T) {
	var source Snapshot
	console := testTrusted(t, "https://console.example.com")
	dashboard := testTrusted(t, "https://dashboard.example.com")
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 1000 {
				source.Store(console)
				source.Store(dashboard)
				source.Clear()
			}
		})
		workers.Go(func() {
			for range 1000 {
				trusted, ready := source.Load()
				if ready {
					consoleAllowed := CheckOrigin([]string{"https://console.example.com"}, trusted).Allowed
					dashboardAllowed := CheckOrigin([]string{"https://dashboard.example.com"}, trusted).Allowed
					if consoleAllowed == dashboardAllowed {
						t.Error("snapshot reader observed a partial or combined set")
						return
					}
				} else if len(trusted.Origins()) != 0 {
					t.Error("unavailable snapshot returned trusted origins")
					return
				}
			}
		})
	}
	workers.Wait()
}

type countingSource struct {
	trusted TrustedOrigins
	calls   int
}

func (s *countingSource) Load() (TrustedOrigins, bool) {
	s.calls++
	return s.trusted, true
}

func TestGuardLoadsOneSnapshotOnlyWhenNeeded(t *testing.T) {
	source := &countingSource{trusted: testTrusted(t, "https://console.example.com")}
	guard := Guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), source)
	for _, method := range []string{"GET", "HEAD", "OPTIONS", "POST"} {
		r := httptest.NewRequest(method, "/", nil)
		if method != "POST" {
			r.Header.Set("Origin", "https://console.example.com")
		}
		guard.ServeHTTP(httptest.NewRecorder(), r)
	}
	if source.calls != 0 {
		t.Fatalf("safe methods and CLI consulted source %d times", source.calls)
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Origin", "https://console.example.com")
	guard.ServeHTTP(httptest.NewRecorder(), r)
	if source.calls != 1 {
		t.Fatalf("browser mutation loaded %d snapshots, want one", source.calls)
	}
}
