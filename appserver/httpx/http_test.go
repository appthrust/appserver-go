package httpx_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/appthrust/appserver-go/appserver/httpx"
	"github.com/appthrust/appserver-go/appserver/requestlog"
)

type wrappedWriter struct{ http.ResponseWriter }

func (w wrappedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestWriteErrorWithAndWithoutRequestLog(t *testing.T) {
	var legacyLog bytes.Buffer
	oldOutput, oldPrefix, oldFlags := log.Writer(), log.Prefix(), log.Flags()
	t.Cleanup(func() { log.SetOutput(oldOutput); log.SetPrefix(oldPrefix); log.SetFlags(oldFlags) })
	log.SetOutput(&legacyLog)
	log.SetPrefix("")
	log.SetFlags(0)
	for _, tc := range []struct {
		name                                   string
		err                                    error
		status                                 int
		body, retryAfter, legacy, code, detail string
	}{
		{"typed client error", httpx.Invalid("bad value"), 400, "{\"error\":\"invalid_request\",\"message\":\"bad value\"}\n", "", "", "invalid_request", ""},
		{"wrapped typed server error", fmt.Errorf("cause: %w", &httpx.Error{Status: 503, Code: "busy", Message: "Try again", RetryAfter: "5"}), 503,
			"{\"error\":\"busy\",\"message\":\"Try again\"}\n", "5", "", "busy", ""},
		{"untyped", errors.New("connection failed"), 500, "{\"error\":\"internal_error\",\"message\":\"The inventory could not complete this request\"}\n", "",
			"inventory request failed: connection failed\n", "internal_error", "connection failed"},
	} {
		for _, wrapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wrapped=%t", tc.name, wrapped), func(t *testing.T) {
				legacyLog.Reset()
				var out bytes.Buffer
				var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					httpx.WriteError(wrappedWriter{wrappedWriter{w}}, tc.err, "inventory")
				})
				if wrapped {
					h = requestlog.Wrap(h, requestlog.Options{Service: "inventory", Output: &out, Now: func() time.Time { return time.Unix(0, 0) }})
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest("GET", "/items", nil))
				hdr := w.Result().Header
				if w.Code != tc.status || w.Body.String() != tc.body || hdr.Get("Content-Type") != "application/json" || hdr.Get("Cache-Control") != "no-store" || hdr.Get("Retry-After") != tc.retryAfter {
					t.Fatalf("response = %d %v %q", w.Code, hdr, w.Body.String())
				}
				if !wrapped {
					if legacyLog.String() != tc.legacy || hdr.Get("X-Request-Id") != "" {
						t.Fatalf("legacy log = %q; headers = %v", legacyLog.String(), hdr)
					}
					return
				}
				if legacyLog.Len() != 0 {
					t.Fatalf("unexpected duplicate log: %s", &legacyLog)
				}
				var line map[string]any
				if err := json.Unmarshal(out.Bytes(), &line); err != nil {
					t.Fatal(err)
				}
				detail, present := line["error"].(string)
				if line["error_code"] != tc.code || detail != tc.detail || present != (tc.detail != "") || line["status"] != float64(tc.status) || line["bytes"] != float64(len(tc.body)) {
					t.Fatalf("wrong request log %#v", line)
				}
			})
		}
	}
}
