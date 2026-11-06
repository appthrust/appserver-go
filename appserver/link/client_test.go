package link

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testClient(origin string) *Client {
	return NewClient(NewResolver(nil, "caller", func(string) (string, bool) { return origin, true }, map[string]Required{"directory": {URLEnv: "URL"}}), nil)
}

type operationCall func(context.Context, string, Operation, Params, any, any) error

func TestClientTransport(t *testing.T) {
	for _, method := range []struct {
		name string
		bind func(*Client, Binding) operationCall
	}{
		{"Do", func(client *Client, _ Binding) operationCall { return client.Do }},
		{"DoAt", func(client *Client, binding Binding) operationCall {
			return func(ctx context.Context, bearer string, op Operation, params Params, in, out any) error {
				return client.DoAt(ctx, bearer, binding, op, params, in, out)
			}
		}},
	} {
		t.Run(method.name, func(t *testing.T) {
			t.Run("bearer_path_query_etag_and_principal_isolation", func(t *testing.T) {
				testClientBearerPathQueryETagAndPrincipalIsolation(t, method.bind)
			})
			t.Run("base_document_and_json_body", func(t *testing.T) {
				testClientBaseDocumentAndJSONBody(t, method.bind)
			})
			t.Run("error_classification_and_redirect_refusal", func(t *testing.T) {
				testClientErrorClassificationAndRedirectRefusal(t, method.bind)
			})
			t.Run("body_cap_timeout_and_inactive_states", func(t *testing.T) {
				testClientBodyCapTimeoutAndInactiveStates(t, method.bind)
			})
			t.Run("invalid_operation_target", func(t *testing.T) {
				for _, op := range []Operation{
					{Method: "GET", Path: "/people"},
					{Definition: "directory", Capability: "launcher.entries/v1", Method: "GET", Path: "/people"},
				} {
					client := NewClient(nil, roundTripFunc(func(*http.Request) (*http.Response, error) {
						t.Fatal("invalid operation made a request")
						return nil, nil
					}))
					err := method.bind(client, Binding{State: StateReady})(context.Background(), "Bearer viewer", op, Params{}, nil, nil)
					if err == nil || err.Error() != "link operation must set exactly one of Definition or Capability" {
						t.Fatalf("operation=%+v error=%v", op, err)
					}
				}
			})
		})
	}
}

func testClientBearerPathQueryETagAndPrincipalIsolation(t *testing.T, bind func(*Client, Binding) operationCall) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.EscapedPath() != "/api/directory/v1/groups/a%2Fb%20%3F/members" || r.URL.Query().Get("q") != "sales & ops" {
			t.Errorf("unexpected URL %s", r.URL)
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Forwarded-Host") != "" {
			t.Error("principal context leaked")
		}
		if r.Header.Get("Authorization") != "Bearer viewer" && r.Header.Get("Authorization") != "opaque-other" {
			t.Error("bearer changed")
		}
		if calls == 2 {
			if r.Header.Get("If-None-Match") != `"one"` {
				t.Error("missing ETag")
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.Header.Get("If-None-Match") != "" {
			t.Error("cache crossed principal")
		}
		w.Header().Set("ETag", `"one"`)
		w.Header().Set("Set-Cookie", "session=secret")
		fmt.Fprint(w, `{"items":["original"]}`)
	}))
	defer server.Close()
	client := testClient(server.URL)
	if client.http.Timeout != 5*time.Second || client.http.Jar != nil || client.Resolver() != client.resolver {
		t.Fatal("client defaults")
	}
	call := bind(client, Binding{Definition: "directory", State: StateReady, InternalURL: server.URL})
	op := Operation{Definition: "directory", Method: "GET", Base: "/api/directory/v1", Path: "/groups/{id}/members"}
	params := Params{Path: map[string]string{"id": "a/b ?"}, Query: url.Values{"q": {"sales & ops"}}}
	var first struct {
		Items []string `json:"items"`
	}
	if err := call(context.Background(), "Bearer viewer", op, params, nil, &first); err != nil {
		t.Fatal(err)
	}
	first.Items[0] = "mutated"
	var second struct {
		Items []string `json:"items"`
	}
	if err := call(context.Background(), "Bearer viewer", op, params, nil, &second); err != nil || second.Items[0] != "original" {
		t.Fatalf("cached response=%+v %v", second, err)
	}
	if err := call(context.Background(), "opaque-other", op, params, nil, &second); err != nil {
		t.Fatal(err)
	}
}

func testClientBaseDocumentAndJSONBody(t *testing.T, bind func(*Client, Binding) operationCall) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "verbatim" {
			t.Error("bearer changed")
		}
		switch r.URL.Path {
		case "/api/console/openapi.json":
			fmt.Fprint(w, `{"openapi":"3.0.3"}`)
		case "/api/directory/v1/import":
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				t.Error("JSON request")
			}
			var value map[string]string
			if err := json.NewDecoder(r.Body).Decode(&value); err != nil || value["name"] != "viewer" {
				t.Error("JSON input")
			}
			fmt.Fprint(w, `{"ok":true}`)
		default:
			t.Errorf("unexpected URL %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := testClient(server.URL)
	body, err := client.Document(context.Background(), "verbatim", "directory", "/api/console")
	if err != nil || string(body) != `{"openapi":"3.0.3"}` {
		t.Fatalf("document=%s %v", body, err)
	}
	var out struct {
		OK bool `json:"ok"`
	}
	call := bind(client, Binding{Definition: "directory", State: StateReady, InternalURL: server.URL})
	err = call(context.Background(), "verbatim", Operation{Definition: "directory", Method: "POST", Base: "/api/directory/v1", Path: "/import"}, Params{}, map[string]string{"name": "viewer"}, &out)
	if err != nil || !out.OK {
		t.Fatalf("post=%+v %v", out, err)
	}
}

func testClientErrorClassificationAndRedirectRefusal(t *testing.T, bind func(*Client, Binding) operationCall) {
	for _, status := range []int{301, 302, 304, 307, 401, 403, 404, 422, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(status)
				fmt.Fprint(w, `{"error":"callee_rejection","message":"No such person"}`)
			}))
			defer server.Close()
			client := testClient(server.URL)
			call := bind(client, Binding{Definition: "directory", State: StateReady, InternalURL: server.URL})
			op := Operation{Definition: "directory", Method: "GET", Base: "/api/directory/v1", Path: "/people"}
			err := call(context.Background(), "Bearer viewer", op, Params{}, nil, nil)
			var denied *DeniedError
			var rejected *RejectedError
			switch {
			case status == 401 || status == 403:
				if !errors.As(err, &denied) || denied.Status != status {
					t.Fatalf("denied=%v", err)
				}
			case status >= 400 && status < 500:
				if !errors.As(err, &rejected) || rejected.Status != status || rejected.Code != "callee_rejection" || rejected.Message != "No such person" {
					t.Fatalf("rejected=%v", err)
				}
			default:
				if !errors.Is(err, ErrUnavailable) {
					t.Fatalf("unavailable=%v", err)
				}
			}
			if calls != 1 {
				t.Fatal("redirect followed or request retried")
			}
			server.Close()
			if err := call(context.Background(), "Bearer viewer", op, Params{}, nil, nil); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("transport=%v", err)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testClientBodyCapTimeoutAndInactiveStates(t *testing.T, bind func(*Client, Binding) operationCall) {
	client := testClient("http://directory.internal")
	call := bind(client, Binding{Definition: "directory", State: StateReady, InternalURL: "http://directory.internal"})
	op := Operation{Definition: "directory", Method: "GET", Base: "/api/directory/v1", Path: "/people"}
	for _, size := range []int{maxBody, maxBody + 1} {
		client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", size))), Header: make(http.Header)}, nil
		})
		err := call(context.Background(), "Bearer viewer", op, Params{}, nil, nil)
		if (size > maxBody) != errors.Is(err, ErrUnavailable) {
			t.Fatalf("cap size=%d err=%v", size, err)
		}
	}
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	client.http.Timeout = time.Millisecond
	if err := call(context.Background(), "Bearer viewer", op, Params{}, nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("timeout=%v", err)
	}
	for _, state := range []State{StateAbsent, StateUnsupported, StateInstalling, ""} {
		resolver := NewResolver(nil, "caller", nil, nil)
		binding := Binding{Definition: "directory", State: state}
		resolver.cache["directory"] = cachedBinding{binding, time.Now().Add(time.Minute)}
		client := NewClient(resolver, roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("inactive callee called"); return nil, nil }))
		if err := bind(client, binding)(context.Background(), "Bearer viewer", op, Params{}, nil, nil); !errors.Is(err, ErrAbsent) {
			t.Fatalf("state=%s err=%v", state, err)
		}
	}
}

func TestClientDoAtProviderRoot(t *testing.T) {
	for _, op := range []Operation{
		{Capability: "launcher.entries/v1", Method: "GET", Path: "/launcher/entries"},
		{Definition: "directory", Method: "GET", Path: "/launcher/entries"},
	} {
		t.Run(op.Definition+op.Capability, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/launcher/entries" || r.URL.Query().Get("q") != "sales & ops" || r.Header.Get("Authorization") != "opaque-viewer" {
					t.Errorf("unexpected request %s %v", r.URL, r.Header)
				}
				fmt.Fprint(w, `{"items":["provider entry"]}`)
			}))
			defer server.Close()
			client := NewClient(nil, nil)
			binding := Binding{Definition: "provider", Capabilities: []string{"launcher.entries/v1"}, State: StateReady, InternalURL: server.URL}
			var out struct {
				Items []string `json:"items"`
			}
			err := client.DoAt(context.Background(), "opaque-viewer", binding, op, Params{Query: url.Values{"q": {"sales & ops"}}}, nil, &out)
			if err != nil || len(out.Items) != 1 || out.Items[0] != "provider entry" {
				t.Fatalf("response=%+v error=%v", out, err)
			}
		})
	}
}

func TestClientFetchBinaryWithoutCache(t *testing.T) {
	picture := []byte("\x89PNG\r\n\x1a\n")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.EscapedPath() != "/api/directory/v1/people/a%2Fb%20c/avatar" || r.URL.Query().Get("q") != "x & y" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer viewer" || r.Header.Get("Accept") != "image/*" || r.Header.Get("If-None-Match") != "" {
			t.Errorf("unexpected headers %v", r.Header)
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("ETag", `"picture"`)
		_, _ = w.Write(picture)
	}))
	defer server.Close()
	client := testClient(server.URL)
	op := Operation{Definition: "directory", Method: http.MethodGet, Base: "/api/directory/v1", Path: "/people/{id}/avatar"}
	params := Params{Path: map[string]string{"id": "a/b c"}, Query: url.Values{"q": {"x & y"}}}
	for range 2 {
		body, contentType, err := client.Fetch(t.Context(), "Bearer viewer", op, params)
		if err != nil || string(body) != string(picture) || contentType != "image/png" {
			t.Fatalf("body=%q contentType=%q error=%v", body, contentType, err)
		}
	}
	if calls != 2 || len(client.cache) != 0 {
		t.Fatalf("calls=%d cache=%v", calls, client.cache)
	}
}

func TestClientFetchErrorsAndBodyBound(t *testing.T) {
	op := Operation{Definition: "directory", Method: http.MethodGet, Base: "/api/directory/v1", Path: "/people/person/avatar"}
	for _, status := range []int{302, 304, 401, 403, 404, 422, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(status)
				fmt.Fprint(w, `{"error":"not_found","message":"No picture"}`)
			}))
			defer server.Close()
			client := testClient(server.URL)
			_, _, err := client.Fetch(t.Context(), "Bearer viewer", op, Params{})
			var denied *DeniedError
			var rejected *RejectedError
			switch {
			case status == 401 || status == 403:
				if !errors.As(err, &denied) || denied.Status != status {
					t.Fatalf("denied=%v", err)
				}
			case status >= 400 && status < 500:
				if !errors.As(err, &rejected) || rejected.Status != status || rejected.Code != "not_found" || rejected.Message != "No picture" {
					t.Fatalf("rejected=%v", err)
				}
			default:
				if !errors.Is(err, ErrUnavailable) {
					t.Fatalf("unavailable=%v", err)
				}
			}
			server.Close()
			if _, _, err := client.Fetch(t.Context(), "Bearer viewer", op, Params{}); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("transport=%v", err)
			}
		})
	}
	client := testClient("http://directory.internal")
	for _, size := range []int{maxBody, maxBody + 1} {
		client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", size))), Header: make(http.Header)}, nil
		})
		body, _, err := client.Fetch(t.Context(), "Bearer viewer", op, Params{})
		if size <= maxBody && (err != nil || len(body) != size) || size > maxBody && !errors.Is(err, ErrUnavailable) {
			t.Fatalf("size=%d body=%d error=%v", size, len(body), err)
		}
	}
	resolver := NewResolver(nil, "caller", nil, nil)
	resolver.cache["directory"] = cachedBinding{Binding{Definition: "directory", State: StateAbsent}, time.Now().Add(time.Minute)}
	client = NewClient(resolver, nil)
	if _, _, err := client.Fetch(t.Context(), "Bearer viewer", op, Params{}); !errors.Is(err, ErrAbsent) {
		t.Fatalf("absent=%v", err)
	}
}
