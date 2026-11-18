package requestlog_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/appthrust/appserver-go/appserver/httpx"
	"github.com/appthrust/appserver-go/appserver/requestlog"
)

func options(out io.Writer) requestlog.Options {
	return requestlog.Options{Service: "inventory", Output: out, Now: func() time.Time { return time.Unix(0, 0) }}
}

func onlyLine(t *testing.T, out *bytes.Buffer) map[string]any {
	t.Helper()
	b := out.Bytes()
	if !bytes.HasSuffix(b, []byte("\n")) || bytes.Count(b, []byte("\n")) != 1 {
		t.Fatalf("expected one newline-terminated JSON object, got %q", b)
	}
	var line map[string]any
	if err := json.Unmarshal(b, &line); err != nil {
		t.Fatal(err)
	}
	return line
}

func TestCompletedRequest(t *testing.T) {
	start := time.Date(2026, 8, 9, 10, 0, 0, 123456789, time.FixedZone("local", 3600))
	now := start
	var out bytes.Buffer
	opts := options(&out)
	opts.Now = func() time.Time { return now }
	mux := http.NewServeMux()
	mux.HandleFunc("POST /items/{id}", func(w http.ResponseWriter, r *http.Request) {
		if got := requestlog.ID(r.Context()); got != "abc._-123" || w.Header().Get("X-Request-Id") != got {
			t.Fatalf("missing inbound request ID before handler writes: %q", got)
		}
		w.Header().Set("X-Response-Secret", "response-header-secret")
		_, _ = io.WriteString(w, "response-body-secret") // implicit 200
		now = start.Add(15 * time.Millisecond)
		if out.Len() != 0 {
			t.Fatal("request was logged before handler returned")
		}
	})
	r := httptest.NewRequest(http.MethodPost, "/items/7?token=query-secret", strings.NewReader("request-body-secret"))
	r.Header.Set("X-Request-Id", "abc._-123")
	r.Header.Set("Authorization", "Bearer header-secret")
	r.AddCookie(&http.Cookie{Name: "session", Value: "cookie-secret"})
	w := httptest.NewRecorder()
	requestlog.Wrap(mux, opts).ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "response-body-secret" || w.Result().Header.Get("X-Response-Secret") != "response-header-secret" {
		t.Fatal("wrapper changed the response")
	}
	want := map[string]any{
		"ts": "2026-08-09T09:00:00.138456789Z", "level": "info", "msg": "request", "service": "inventory",
		"method": "POST", "path": "/items/7", "route": "POST /items/{id}", "status": float64(200),
		"bytes": float64(len("response-body-secret")), "duration_ms": float64(15), "request_id": "abc._-123",
	}
	if got := onlyLine(t, &out); !maps.Equal(got, want) {
		t.Fatalf("line = %#v, want %#v", got, want)
	}
}

func TestSkip(t *testing.T) {
	custom := func(r *http.Request) bool { return r.URL.Path == "/private-probe" }
	for _, tc := range []struct {
		method, path string
		status       int
		skip         func(*http.Request) bool
		logged       bool
	}{
		{"GET", "/healthz", 200, nil, false}, {"GET", "/readyz?details=1", 299, nil, false},
		{"GET", "/healthz", 300, nil, true}, {"GET", "/readyz", 503, nil, true},
		{"HEAD", "/healthz", 200, nil, true}, {"GET", "/readyz/", 200, nil, true},
		{"GET", "/private-probe", 204, custom, false}, {"GET", "/private-probe", 400, custom, true},
		{"GET", "/readyz", 200, custom, true},
	} {
		t.Run(fmt.Sprintf("%s %s %d", tc.method, tc.path, tc.status), func(t *testing.T) {
			var out bytes.Buffer
			opts := options(&out)
			opts.Skip = tc.skip
			w := httptest.NewRecorder()
			requestlog.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status) }), opts).ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != tc.status || w.Result().Header.Get("X-Request-Id") == "" {
				t.Fatalf("status = %d, headers = %v", w.Code, w.Result().Header)
			}
			if !tc.logged {
				if out.Len() != 0 {
					t.Fatalf("unexpected log %q", out.String())
				}
				return
			}
			line := onlyLine(t, &out)
			level := "info"
			if tc.status >= 500 {
				level = "error"
			}
			if line["status"] != float64(tc.status) || line["level"] != level || line["route"] != nil || line["bytes"] != float64(0) {
				t.Fatalf("unexpected log %#v", line)
			}
		})
	}
}

func TestRequestID(t *testing.T) {
	generated := make(map[string]bool)
	for _, tc := range []struct {
		values []string
		valid  bool
	}{
		{nil, false}, {[]string{""}, false}, {[]string{"A"}, true}, {[]string{strings.Repeat("Z", 64)}, true},
		{[]string{"aZ0-9._"}, true}, {[]string{strings.Repeat("a", 65)}, false}, {[]string{"one two"}, false},
		{[]string{"a/b"}, false}, {[]string{"abc\n"}, false}, {[]string{"ä"}, false}, {[]string{"a", "b"}, false},
	} {
		var out bytes.Buffer
		r := httptest.NewRequest("GET", "/", nil)
		for _, value := range tc.values {
			r.Header.Add("X-Request-Id", value)
		}
		w := httptest.NewRecorder()
		var id string
		requestlog.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id = requestlog.ID(r.Context())
			if w.Header().Get("X-Request-Id") != id {
				t.Fatalf("header differs from context ID %q", id)
			}
		}), options(&out)).ServeHTTP(w, r)
		line := onlyLine(t, &out)
		if line["request_id"] != id || w.Result().Header.Get("X-Request-Id") != id || line["status"] != float64(200) || line["bytes"] != float64(0) {
			t.Fatalf("unexpected empty response log %#v", line)
		}
		if tc.valid {
			if id != tc.values[0] {
				t.Errorf("changed valid ID %q to %q", tc.values, id)
			}
		} else {
			if _, err := hex.DecodeString(id); err != nil || len(id) == 0 || len(id) > 64 || generated[id] {
				t.Fatalf("bad generated ID %q for %q", id, tc.values)
			}
			generated[id] = true
		}
	}
}

func TestAnnotations(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	requestlog.SetError(r, errors.New("unwrapped"))
	requestlog.SetOutcome(r, "ignored", "unwrapped")
	if id := requestlog.ID(context.Background()); id != "" {
		t.Fatalf("unwrapped ID = %q", id)
	}

	prefix := strings.Repeat("a", 509) + "é"
	for _, tc := range []struct {
		status       int
		err          error
		code, detail string
	}{
		{502, errors.New(prefix + "€"), "internal_error", prefix},
		{500, errors.New(strings.Repeat("é", 256) + "more"), "internal_error", strings.Repeat("é", 256)},
		{503, errors.New("invalid\xfftext"), "internal_error", "invalidtext"},
		{503, fmt.Errorf("wrapped: %w", httpx.Fail(503, "unavailable", "private")), "unavailable", ""},
		{400, errors.New("private"), "internal_error", ""},
	} {
		var out bytes.Buffer
		requestlog.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestlog.SetError(r, tc.err)
			requestlog.SetOutcome(r, "incomplete", "upstream_closed")
			w.WriteHeader(tc.status)
		}), options(&out)).ServeHTTP(httptest.NewRecorder(), r)
		line := onlyLine(t, &out)
		detail, present := line["error"].(string)
		if line["error_code"] != tc.code || detail != tc.detail || present != (tc.detail != "") || !utf8.ValidString(detail) || len(detail) > 512 || line["outcome"] != "incomplete" || line["reason"] != "upstream_closed" {
			t.Fatalf("unexpected annotations: %#v", line)
		}
	}
}

func TestPanicPreservesValueAndResponse(t *testing.T) {
	for _, tc := range []struct {
		value                 any
		committed, wantStatus int
	}{
		{http.ErrAbortHandler, 0, 500}, {new(int), 202, 202},
	} {
		var out bytes.Buffer
		w := httptest.NewRecorder()
		h := requestlog.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestlog.SetError(r, errors.New("failed"))
			if tc.committed != 0 {
				w.WriteHeader(tc.committed)
			}
			panic(tc.value)
		}), options(&out))
		func() {
			defer func() {
				if got := recover(); got != tc.value {
					t.Fatalf("panic = %v, want %v", got, tc.value)
				}
			}()
			h.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
		}()
		line := onlyLine(t, &out)
		if line["panic"] != true || line["level"] != "error" || line["status"] != float64(tc.wantStatus) || line["error"] != "failed" {
			t.Fatalf("unexpected panic log %#v", line)
		}
		if w.Body.Len() != 0 || (tc.committed == 0 && w.Code != 200) || (tc.committed != 0 && w.Code != tc.committed) {
			t.Fatalf("wrapper wrote a panic response: %d %q", w.Code, w.Body.String())
		}
	}
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *deadlineRecorder) SetWriteDeadline(d time.Time) error { w.deadline = d; return nil }

func TestStreaming(t *testing.T) {
	var out bytes.Buffer
	underlying := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	deadline := time.Unix(1, 0)
	requestlog.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if w.(interface{ Unwrap() http.ResponseWriter }).Unwrap() != underlying {
			t.Fatal("wrong underlying writer")
		}
		ctrl := http.NewResponseController(w)
		if err := ctrl.SetWriteDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush() // commits an implicit 200 before the first event
		if !underlying.Flushed || out.Len() != 0 {
			t.Fatal("flush was buffered until completion")
		}
		_, _ = io.WriteString(w, "data: one\n\n")
		if err := ctrl.Flush(); err != nil {
			t.Fatal(err)
		}
		if got := underlying.Body.String(); got != "data: one\n\n" {
			t.Fatalf("first event = %q", got)
		}
		_, _ = w.Write([]byte("data: two\n\n"))
		requestlog.SetOutcome(r, "partial", "stream_closed")
	}), options(&out)).ServeHTTP(underlying, httptest.NewRequest("GET", "/events", nil))
	line := onlyLine(t, &out)
	if line["bytes"] != float64(len("data: one\n\ndata: two\n\n")) || line["status"] != float64(200) || line["outcome"] != "partial" || line["reason"] != "stream_closed" || underlying.deadline != deadline {
		t.Fatalf("unexpected streamed response %#v, deadline %v", line, underlying.deadline)
	}
}

type hijackRecorder struct {
	*httptest.ResponseRecorder
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (w *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) { return w.conn, w.rw, nil }

func TestHijack(t *testing.T) {
	for _, committed := range []int{0, 202} {
		t.Run(strconv.Itoa(committed), func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			underlying := &hijackRecorder{httptest.NewRecorder(), server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server))}
			var out bytes.Buffer
			requestlog.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var conn net.Conn
				var rw *bufio.ReadWriter
				var err error
				if committed != 0 {
					w.WriteHeader(committed)
					_, _ = w.Write([]byte("before"))
					conn, rw, err = http.NewResponseController(w).Hijack()
				} else {
					conn, rw, err = w.(http.Hijacker).Hijack()
				}
				if err != nil || conn != server || rw != underlying.rw {
					t.Fatalf("hijack = %v %v %v", conn, rw, err)
				}
				w.WriteHeader(500)
				if n, err := w.Write([]byte("too late")); n != 0 || !errors.Is(err, http.ErrHijacked) {
					t.Fatalf("post-hijack write = %d, %v", n, err)
				}
				w.(http.Flusher).Flush()
			}), options(&out)).ServeHTTP(underlying, httptest.NewRequest("GET", "/ws", nil))
			status, body := 101, ""
			if committed != 0 {
				status, body = committed, "before"
			}
			line := onlyLine(t, &out)
			if line["status"] != float64(status) || line["bytes"] != float64(len(body)) || underlying.Body.String() != body || underlying.Flushed || (committed == 0 && underlying.Code != 200) {
				t.Fatalf("unexpected hijack log %#v; response = %d %q", line, underlying.Code, underlying.Body.String())
			}
		})
	}
}

type countingOutput struct {
	bytes.Buffer
	writes int
}

func (out *countingOutput) Write(b []byte) (int, error) { out.writes++; return out.Buffer.Write(b) }

func TestConcurrentLines(t *testing.T) {
	const n = 64
	var out countingOutput
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	handlers := [2]http.Handler{requestlog.Wrap(next, options(&out)), requestlog.Wrap(next, options(&out))}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			r := httptest.NewRequest("GET", "/"+strconv.Itoa(i), nil)
			r.Header.Set("X-Request-Id", strconv.Itoa(i))
			<-start
			handlers[i%len(handlers)].ServeHTTP(httptest.NewRecorder(), r)
		})
	}
	close(start)
	wg.Wait()
	if out.writes != n {
		t.Fatalf("%d writes for %d requests", out.writes, n)
	}
	seen := make(map[string]bool)
	for line := range strings.SplitSeq(strings.TrimSuffix(out.String(), "\n"), "\n") {
		var entry struct {
			ID   string `json:"request_id"`
			Path string `json:"path"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if seen[entry.ID] || entry.Path != "/"+entry.ID {
			t.Fatalf("bad line %s", line)
		}
		seen[entry.ID] = true
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct lines, want %d", len(seen), n)
	}
}

func TestLoggedRequestIDIsTheOneSentToTheClient(t *testing.T) {
	var out bytes.Buffer
	handler := requestlog.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Request-Id", "42") // an app with its own ID contract
		w.WriteHeader(http.StatusAccepted)
	}), requestlog.Options{Service: "svc", Output: &out})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/chat", nil))
	var line struct {
		ID string `json:"request_id"`
	}
	if err := json.Unmarshal(out.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if got := recorder.Header().Get("X-Request-Id"); got != "42" || line.ID != got {
		t.Fatalf("header %q, logged %q; want both 42", got, line.ID)
	}
}

func TestUpstreamDerivedErrorCodeIsNotLoggedVerbatim(t *testing.T) {
	var out bytes.Buffer
	handler := requestlog.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteError(w, httpx.Fail(http.StatusBadGateway, "secret text from upstream body", "x"), "svc")
	}), requestlog.Options{Service: "svc", Output: &out})
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if strings.Contains(out.String(), "secret text") || !strings.Contains(out.String(), `"error_code":"other"`) {
		t.Fatalf("line = %s", out.String())
	}
}

func TestOversizedBodyStillClosesTheConnection(t *testing.T) {
	handler := requestlog.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4)); err != nil {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
		}
	}), requestlog.Options{Service: "svc", Output: io.Discard})
	server := httptest.NewServer(handler)
	defer server.Close()
	response, err := http.Post(server.URL, "text/plain", strings.NewReader("0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge || !response.Close {
		t.Fatalf("status %d, Connection: close = %v", response.StatusCode, response.Close)
	}
}
