package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/appthrust/appserver-go/apphealth"
)

func TestHandlerPublicBoundary(t *testing.T) {
	var registry Registry
	registry.Capability("search", true, CheckFunc(func(context.Context) Status { return Status{State: apphealth.StateServing} }))
	h := registry.Handler(func() (string, string) { return "sha256:test", "v1" })
	for _, header := range []string{"", apphealth.PublicRouteHeader, "Authorization"} {
		t.Run(header, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, Path, nil)
			if header != "" {
				r.Header[header] = []string{""}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := http.StatusOK
			if header != "" {
				want = http.StatusNotFound
			}
			if w.Code != want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("health response is cacheable")
			}
			if header != "" {
				return
			}
			var report apphealth.Report
			if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if err := report.Validate([]string{"search"}); err != nil {
				t.Fatal(err)
			}
			if report.Release.ArtifactDigest != "sha256:test" || report.Release.ReleaseVersion != "v1" || report.ObservedAt.IsZero() {
				t.Fatalf("report=%+v", report)
			}
		})
	}
	// The API-server proxy itself supplies these headers; they are not public markers.
	r := httptest.NewRequest(http.MethodGet, Path, nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "apiserver")
	r.Header.Set("X-Forwarded-For", "192.0.2.1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("service proxy rejected: %d", w.Code)
	}
}

func TestHandlerBudgetAndMessageBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var registry Registry
		registry.Capability("slow", true, CheckFunc(func(ctx context.Context) Status { <-ctx.Done(); return unknown() }))
		registry.Capability("long", false, CheckFunc(func(context.Context) Status {
			return Status{State: apphealth.StateServing, Message: strings.Repeat("界", 100)}
		}))
		start := time.Now()
		w := httptest.NewRecorder()
		registry.Handler(nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, Path, nil))
		if time.Since(start) != Budget {
			t.Fatalf("elapsed=%s", time.Since(start))
		}
		var report apphealth.Report
		if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if err := report.Validate([]string{"slow", "long"}); err != nil {
			t.Fatal(err)
		}
		if report.Capabilities[0].State != apphealth.StateUnknown {
			t.Fatalf("slow=%+v", report.Capabilities[0])
		}
	})
}

func TestRateLimited(t *testing.T) {
	now := time.Now()
	calls := 0
	checker := RateLimited(CheckFunc(func(context.Context) Status {
		calls++
		if calls == 1 {
			return Status{State: apphealth.StateServing}
		}
		return Status{State: apphealth.StateFailing, Reason: apphealth.ReasonDependencyUnavailable}
	})).(*synthetic)
	checker.now = func() time.Time { return now }
	first := checker.Check(context.Background())
	now = now.Add(SyntheticInterval - time.Nanosecond)
	if got := checker.Check(context.Background()); got != first || calls != 1 {
		t.Fatalf("cached=%+v calls=%d", got, calls)
	}
	now = now.Add(time.Nanosecond)
	if got := checker.Check(context.Background()); got.State != apphealth.StateFailing || calls != 2 {
		t.Fatalf("refreshed=%+v calls=%d", got, calls)
	}
}

func TestOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name          string
		attempts      []bool
		state, reason string
	}{
		{"empty", nil, apphealth.StateUnknown, apphealth.ReasonNoEvidence},
		{"all ok", []bool{true, true, true}, apphealth.StateServing, ""},
		{"below half", []bool{true, true, false}, apphealth.StateServing, ""},
		{"half", []bool{true, false}, apphealth.StateDegraded, apphealth.ReasonUpstreamUnavailable},
		{"one failure", []bool{false}, apphealth.StateDegraded, apphealth.ReasonUpstreamUnavailable},
		{"all fail", []bool{false, false, false}, apphealth.StateFailing, apphealth.ReasonUpstreamUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var outcomes Outcomes
			for _, ok := range tc.attempts {
				outcomes.Record(ok, apphealth.ReasonUpstreamUnavailable)
			}
			got := outcomes.Check(context.Background())
			if got.State != tc.state || got.Reason != tc.reason {
				t.Fatalf("got=%+v", got)
			}
		})
	}
	var outcomes Outcomes
	for range 16 {
		outcomes.Record(false, apphealth.ReasonUpstreamDenied)
	}
	for range 16 {
		outcomes.Record(true, "")
	}
	if got := outcomes.Check(context.Background()); got.State != apphealth.StateServing {
		t.Fatalf("ring did not recover: %+v", got)
	}
	synctest.Test(t, func(t *testing.T) {
		var outcomes Outcomes
		outcomes.Record(true, "")
		time.Sleep(outcomeWindow + time.Nanosecond)
		if got := outcomes.Check(context.Background()); got.State != apphealth.StateUnknown {
			t.Fatalf("expired=%+v", got)
		}
	})
}

func TestLastModelOutcomeRecoversImmediately(t *testing.T) {
	var outcomes Outcomes
	if got := outcomes.Last(); got.State != apphealth.StateUnknown {
		t.Fatalf("empty=%+v", got)
	}
	outcomes.Record(false, apphealth.ReasonUpstreamUnavailable)
	if got := outcomes.Last(); got.State != apphealth.StateFailing {
		t.Fatalf("failure=%+v", got)
	}
	outcomes.Record(false, apphealth.ReasonResourceExhausted)
	if got := outcomes.Last(); got.State != apphealth.StateDegraded {
		t.Fatalf("busy=%+v", got)
	}
	outcomes.Record(true, "")
	if got := outcomes.Last(); got.State != apphealth.StateServing {
		t.Fatalf("recovery=%+v", got)
	}
}
