// Package requestlog writes a structured completion log for HTTP requests.
package requestlog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/appthrust/appserver-go/appserver/httpx"
)

// Options configures Wrap. Service is the app's required catalog name.
type Options struct {
	Service string
	Output  io.Writer        // Defaults to os.Stderr.
	Now     func() time.Time // Defaults to time.Now.
	// Skip marks probe requests: a success is never logged and a failure is
	// logged once per failure streak. Defaults to GET /healthz, /readyz and
	// /.well-known/appthrust/health.
	Skip func(*http.Request) bool
}

type entry struct {
	Time       string  `json:"ts"`
	Level      string  `json:"level"`
	Message    string  `json:"msg"`
	Service    string  `json:"service"`
	Method     string  `json:"method"`
	Path       string  `json:"path"`
	Route      string  `json:"route,omitempty"`
	Status     int     `json:"status"`
	Bytes      int64   `json:"bytes"`
	DurationMS float64 `json:"duration_ms"`
	ID         string  `json:"request_id"`
	ErrorCode  string  `json:"error_code,omitempty"`
	Error      string  `json:"error,omitempty"`
	Outcome    string  `json:"outcome,omitempty"`
	Reason     string  `json:"reason,omitempty"`
	Panic      bool    `json:"panic,omitempty"`
}

// Independent wrappers can share the same output. Serialize only the final
// Write, not the handler, clock, error formatting, or JSON encoding.
var outputMu sync.Mutex

type lineWriter struct{ io.Writer }

func (w lineWriter) Write(b []byte) (int, error) {
	outputMu.Lock()
	defer outputMu.Unlock()
	return w.Writer.Write(b)
}

// Wrap logs one JSON line when next finishes. Place it outside the mux so
// unmatched requests, authentication failures, and upgrades are included.
func Wrap(next http.Handler, opts Options) http.Handler {
	if opts.Output == nil {
		opts.Output = os.Stderr
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Skip == nil {
		opts.Skip = func(r *http.Request) bool {
			if r.Method != http.MethodGet {
				return false
			}
			switch r.URL.Path {
			case "/healthz", "/readyz", "/.well-known/appthrust/health":
				return true
			}
			return false
		}
	}
	var output io.Writer = lineWriter{opts.Output}
	probes := &probeStreaks{failing: map[string]bool{}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := opts.Now()
		s := &requestState{id: requestID(r.Header.Values("X-Request-Id"))}
		r = r.WithContext(context.WithValue(r.Context(), contextKey{}, s))
		w.Header().Set("X-Request-Id", s.id)
		rw := &responseWriter{ResponseWriter: w, state: s}
		method, path := r.Method, r.URL.Path
		// The handler's panic is observed, never recovered: net/http still sees
		// the original value and stack, including http.ErrAbortHandler.
		panicked := true
		defer func() {
			end := opts.Now()
			status := rw.status
			if status == 0 {
				status = http.StatusOK
				if panicked {
					status = http.StatusInternalServerError
				}
			}
			if !panicked && opts.Skip(r) && probes.quiet(method+" "+path, status >= 200 && status < 300) {
				return
			}
			e := entry{
				Time: end.UTC().Format(time.RFC3339Nano), Level: "info", Message: "request", Service: opts.Service,
				Method: method, Path: path, Route: r.Pattern, Status: status, Bytes: rw.bytes,
				DurationMS: float64(end.Sub(start)) / float64(time.Millisecond), ID: s.id, Panic: panicked,
			}
			if rw.sentID != "" {
				e.ID = rw.sentID // matches what the client received
			}
			if status >= 500 || e.Panic {
				e.Level = "error"
			}
			s.addTo(&e)
			_ = json.NewEncoder(output).Encode(&e)
		}()
		next.ServeHTTP(rw.withHijacker(), r)
		panicked = false
	})
}

func requestID(values []string) string {
	if len(values) == 1 && validID(values[0]) {
		return values[0]
	}
	var b [16]byte
	rand.Read(b[:]) // crypto/rand.Read always fills b on supported Go versions.
	return hex.EncodeToString(b[:])
}

func validID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

type contextKey struct{}

type requestState struct {
	id              string
	mu              sync.Mutex
	errorCode       string
	detail          error
	outcome, reason string
}

func state(ctx context.Context) *requestState {
	s, _ := ctx.Value(contextKey{}).(*requestState)
	return s
}

// ID returns the request ID, or an empty string outside Wrap.
func ID(ctx context.Context) string {
	if s := state(ctx); s != nil {
		return s.id
	}
	return ""
}

// SetError annotates the current request, if wrapped. Only untyped errors on
// server failures and panics contribute diagnostic text; supply a log-safe error.
func SetError(r *http.Request, err error) {
	s := state(r.Context())
	if s == nil || err == nil {
		return
	}
	var apiError *httpx.Error
	if errors.As(err, &apiError) {
		s.setError(apiError.Code, nil)
	} else {
		s.setError("internal_error", err)
	}
}

func (s *requestState) setError(code string, detail error) {
	s.mu.Lock()
	s.errorCode, s.detail = code, detail
	s.mu.Unlock()
}

// SetOutcome records an application result not captured by the HTTP status.
// It has no effect outside Wrap.
func SetOutcome(r *http.Request, outcome, reason string) {
	if s := state(r.Context()); s != nil {
		s.mu.Lock()
		s.outcome, s.reason = outcome, reason
		s.mu.Unlock()
	}
}

func (s *requestState) addTo(e *entry) {
	s.mu.Lock()
	e.ErrorCode, e.Outcome, e.Reason = s.errorCode, s.outcome, s.reason
	detail := s.detail
	s.mu.Unlock()
	// Codes are fixed tokens by convention, but some apps forward one from an
	// upstream response; never let arbitrary text reach the line through it.
	if e.ErrorCode != "" && !validID(e.ErrorCode) {
		e.ErrorCode = "other"
	}
	if detail != nil && (e.Status >= 500 || e.Panic) {
		text := detail.Error()
		// Discard invalid bytes, including a partial rune at the cut.
		e.Error = strings.ToValidUTF8(text[:min(len(text), 512)], "")
	}
}

// probeStreaks remembers which probes are failing so a failure streak writes
// one line. It is bounded: a custom Skip may match arbitrary paths.
type probeStreaks struct {
	mu      sync.Mutex
	failing map[string]bool
}

const maxProbeStreaks = 64

// quiet reports whether this probe result should not be logged.
func (p *probeStreaks) quiet(key string, ok bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ok {
		delete(p.failing, key)
		return true
	}
	if p.failing[key] {
		return true
	}
	if len(p.failing) < maxProbeStreaks {
		p.failing[key] = true
	}
	return false
}
