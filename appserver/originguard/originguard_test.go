package originguard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func testTrusted(t *testing.T, origins ...string) TrustedOrigins {
	t.Helper()
	trusted, err := NewTrustedOrigins(origins, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return trusted
}

func TestCheck(t *testing.T) {
	trusted := testTrusted(t, "https://console.example.com", "https://dashboard.example.com")
	for _, tc := range []struct {
		name    string
		method  string
		origins []string
		fetch   bool
		cookie  bool
		reason  string
	}{
		{"console", "POST", []string{"https://console.example.com"}, true, true, ""},
		{"dashboard", "PUT", []string{"https://dashboard.example.com"}, false, false, ""},
		{"normalized", "PATCH", []string{"HTTPS://CONSOLE.EXAMPLE.COM:443"}, false, false, ""},
		{"sibling", "POST", []string{"https://evil.example.com"}, true, true, RequestOriginNotAllowed},
		{"port", "DELETE", []string{"https://console.example.com:8443"}, false, false, RequestOriginNotAllowed},
		{"suffix spoof", "POST", []string{"https://console.example.com.evil.test"}, false, false, RequestOriginNotAllowed},
		{"null", "POST", []string{"null"}, false, false, RequestOriginNotAllowed},
		{"duplicate", "POST", []string{"https://console.example.com", "https://console.example.com"}, false, false, RequestOriginNotAllowed},
		{"comma list", "POST", []string{"https://console.example.com,https://evil.example.com"}, false, false, RequestOriginNotAllowed},
		{"space list", "POST", []string{"https://console.example.com https://evil.example.com"}, false, false, RequestOriginNotAllowed},
		{"malformed", "POST", []string{"not-an-origin"}, false, false, RequestOriginNotAllowed},
		{"empty", "POST", []string{""}, false, false, RequestOriginNotAllowed},
		{"unicode", "POST", []string{"https://cönsole.example.com"}, false, false, RequestOriginNotAllowed},
		{"trailing dot", "POST", []string{"https://console.example.com."}, false, false, RequestOriginNotAllowed},
		{"encoded host", "POST", []string{"https://%63onsole.example.com"}, false, false, RequestOriginNotAllowed},
		{"userinfo", "POST", []string{"https://user@console.example.com"}, false, false, RequestOriginNotAllowed},
		{"path", "POST", []string{"https://console.example.com/"}, false, false, RequestOriginNotAllowed},
		{"query", "POST", []string{"https://console.example.com?"}, false, false, RequestOriginNotAllowed},
		{"fragment", "POST", []string{"https://console.example.com#"}, false, false, RequestOriginNotAllowed},
		{"cookie without origin", "POST", nil, false, true, RequestOriginRequired},
		{"fetch without origin", "POST", nil, true, false, RequestOriginRequired},
		{"cookie and fetch", "POST", nil, true, true, RequestOriginRequired},
		{"non browser", "POST", nil, false, false, ""},
		{"get", "GET", []string{"null"}, true, true, ""},
		{"head", "HEAD", nil, true, true, ""},
		{"options", "OPTIONS", []string{"https://evil.example.com"}, true, true, ""},
		{"custom method", "CUSTOM", nil, false, true, RequestOriginRequired},
		{"connect", "CONNECT", nil, false, true, RequestOriginRequired},
		{"trace", "TRACE", nil, false, true, RequestOriginRequired},
		{"method case sensitive", "get", nil, false, true, RequestOriginRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]string(nil), tc.origins...)
			got := Check(tc.method, tc.origins, tc.fetch, tc.cookie, trusted)
			if got.Reason != tc.reason || got.Allowed != (tc.reason == "") {
				t.Fatalf("Check = %+v, want reason %q", got, tc.reason)
			}
			if !reflect.DeepEqual(before, tc.origins) {
				t.Fatal("Check changed Origin values")
			}
		})
	}
}

func TestCheckOrigin(t *testing.T) {
	trusted := testTrusted(t, "https://xn--bcher-kva.example")
	for _, tc := range []struct {
		name    string
		origins []string
		reason  string
	}{
		{"A-label", []string{"https://xn--bcher-kva.example"}, ""},
		{"mixed case A-label", []string{"https://XN--BCHER-KVA.EXAMPLE"}, ""},
		{"unicode", []string{"https://bücher.example"}, RequestOriginNotAllowed},
		{"missing", nil, RequestOriginRequired},
		{"duplicate", []string{"https://xn--bcher-kva.example", "https://xn--bcher-kva.example"}, RequestOriginNotAllowed},
		{"untrusted", []string{"https://other.example"}, RequestOriginNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckOrigin(tc.origins, trusted)
			if got.Reason != tc.reason || got.Allowed != (tc.reason == "") {
				t.Fatalf("CheckOrigin = %+v, want reason %q", got, tc.reason)
			}
		})
	}
}

// Reading or closing the body belongs to the downstream handler, never the guard.
type unreadBody struct{ t *testing.T }

func (b unreadBody) Read([]byte) (int, error) {
	b.t.Fatal("guard read request body")
	return 0, nil
}

func (b unreadBody) Close() error {
	b.t.Fatal("guard closed request body")
	return nil
}

func TestGuard(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		header http.Header
		status int
		reason string
	}{
		{"allowed form", "POST", http.Header{"Origin": {"https://console.example.com"}, "Cookie": {"session=viewer"}, "Sec-Fetch-Site": {"same-origin"}, "Content-Type": {"application/x-www-form-urlencoded"}}, 204, ""},
		{"allowed JSON", "PATCH", http.Header{"Origin": {"https://console.example.com"}, "Content-Type": {"application/json"}}, 204, ""},
		{"sibling bearer", "POST", http.Header{"Origin": {"https://evil.example.com"}, "Authorization": {"Bearer valid-viewer"}, "Cookie": {"session=viewer"}, "Sec-Fetch-Site": {"same-site"}}, 403, RequestOriginNotAllowed},
		{"duplicated origin", "POST", http.Header{"Origin": {"https://console.example.com", "https://console.example.com"}}, 403, RequestOriginNotAllowed},
		{"mixed case duplicate keys", "POST", http.Header{"Origin": {"https://console.example.com"}, "origin": {"https://console.example.com"}}, 403, RequestOriginNotAllowed},
		{"noncanonical header keys", "POST", http.Header{"origin": {"https://console.example.com"}, "sec-fetch-site": {"same-origin"}}, 204, ""},
		{"cookie missing origin", "POST", http.Header{"Cookie": {"session=viewer"}}, 403, RequestOriginRequired},
		{"empty cookie", "POST", http.Header{"Cookie": {""}}, 403, RequestOriginRequired},
		{"nil cookie", "POST", http.Header{"cookie": nil}, 403, RequestOriginRequired},
		{"same site missing origin", "POST", http.Header{"Sec-Fetch-Site": {"same-site"}, "Authorization": {"Bearer valid-viewer"}}, 403, RequestOriginRequired},
		{"unknown fetch metadata", "POST", http.Header{"sEc-FeTcH-Future": nil}, 403, RequestOriginRequired},
		{"nil origin", "POST", http.Header{"Origin": nil}, 403, RequestOriginNotAllowed},
		{"empty origin", "POST", http.Header{"Origin": {""}}, 403, RequestOriginNotAllowed},
		{"CLI bearer", "POST", http.Header{"Authorization": {"Bearer valid-viewer"}}, 204, ""},
		{"authentication belongs downstream", "POST", nil, 204, ""},
		{"preflight", "OPTIONS", http.Header{"Origin": {"https://evil.example.com"}, "Access-Control-Request-Method": {"POST"}}, 204, ""},
		{"websocket GET", "GET", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Origin": {"https://evil.example.com"}}, 204, ""},
		{"override does not bypass POST", "POST", http.Header{"Cookie": {"session=viewer"}, "X-HTTP-Method-Override": {"GET"}}, 403, RequestOriginRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var source Snapshot
			source.Store(testTrusted(t, "https://console.example.com"))
			request := httptest.NewRequest(tc.method, "https://api.example.com/mutation?_method=GET", nil)
			request.Header = tc.header
			request.Body = unreadBody{t}
			before := request.Header.Clone()
			calls := 0
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r != request || !reflect.DeepEqual(r.Header, before) || r.Method != tc.method {
					t.Fatal("guard changed request, headers, or method")
				}
				w.WriteHeader(http.StatusNoContent)
			})
			response := httptest.NewRecorder()
			Guard(next, &source).ServeHTTP(response, request)
			assertResponse(t, response, tc.status, tc.reason)
			wantCalls := 0
			if tc.reason == "" {
				wantCalls = 1
			}
			if calls != wantCalls || !reflect.DeepEqual(request.Header, before) {
				t.Fatalf("next calls = %d, want %d; headers must remain unchanged", calls, wantCalls)
			}
		})
	}
}

func TestGuardUnavailable(t *testing.T) {
	var snapshot Snapshot
	var nilSnapshot *Snapshot
	for _, source := range []Source{nil, &snapshot, nilSnapshot} {
		for _, tc := range []struct {
			method string
			header http.Header
			status int
		}{
			{"POST", http.Header{"Origin": {"https://console.example.com"}}, 503},
			{"POST", http.Header{"Origin": {"null"}}, 503},
			{"POST", http.Header{"Cookie": {""}}, 503},
			{"DELETE", http.Header{"Sec-Fetch-Site": {"same-site"}}, 503},
			{"POST", http.Header{"Origin": nil}, 503},
			{"GET", http.Header{"Cookie": {"session=viewer"}}, 204},
			{"HEAD", http.Header{"Origin": {"null"}}, 204},
			{"OPTIONS", http.Header{"Origin": {"https://evil.example.com"}}, 204},
			{"POST", http.Header{"Authorization": {"Bearer valid-viewer"}}, 204},
			{"POST", nil, 204},
		} {
			request := httptest.NewRequest(tc.method, "https://api.example.com/mutation", nil)
			request.Header = tc.header
			request.Body = unreadBody{t}
			calls := 0
			response := httptest.NewRecorder()
			Guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				w.WriteHeader(http.StatusNoContent)
			}), source).ServeHTTP(response, request)
			reason := ""
			if tc.status == 503 {
				reason = TrustedOriginsUnavailable
			}
			assertResponse(t, response, tc.status, reason)
			if (calls == 0) != (tc.status == 503) {
				t.Fatalf("unavailable snapshot: next calls = %d for %s %v", calls, tc.method, tc.header)
			}
		}
	}
}

func TestGuardSnapshotReplacement(t *testing.T) {
	var source Snapshot
	guard := Guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), &source)
	check := func(origin string, status int, reason string) {
		t.Helper()
		r := httptest.NewRequest("POST", "/mutation", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		guard.ServeHTTP(w, r)
		assertResponse(t, w, status, reason)
	}
	check("https://console.example.com", 503, TrustedOriginsUnavailable)
	source.Store(testTrusted(t, "https://console.example.com"))
	check("https://console.example.com", 204, "")
	source.Store(testTrusted(t, "https://dashboard.example.com"))
	check("https://console.example.com", 403, RequestOriginNotAllowed)
	check("https://dashboard.example.com", 204, "")
	source.Store(testTrusted(t))
	check("https://dashboard.example.com", 403, RequestOriginNotAllowed)
	source.Clear()
	check("https://dashboard.example.com", 503, TrustedOriginsUnavailable)
}

func assertResponse(t *testing.T, response *httptest.ResponseRecorder, status int, reason string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d: %s", response.Code, status, response.Body.String())
	}
	if reason == "" {
		return
	}
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != reason || strings.TrimSpace(body.Message) == "" {
		t.Fatalf("error body = %+v, want reason %q and message", body, reason)
	}
	if response.Header().Get("Content-Type") != "application/json" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("incorrect error headers: %v", response.Header())
	}
}
