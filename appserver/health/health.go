// Package health serves application capability evidence independently of readiness.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/appthrust/appserver-go/apphealth"
)

const Path = "/.well-known/appthrust/health"
const Budget = 2 * time.Second
const SyntheticInterval = 15 * time.Second
const outcomeWindow = 5 * time.Minute

// Status must contain product-safe text, never raw dependency errors or secrets.
type Status struct {
	State   string
	Reason  string
	Message string
}

type Checker interface{ Check(context.Context) Status }
type CheckFunc func(context.Context) Status

func (f CheckFunc) Check(ctx context.Context) Status { return f(ctx) }

type capability struct {
	name     string
	required bool
	checker  Checker
	slot     chan struct{}
}

// Registry is configured before Handler is mounted. Required is declaration
// metadata only: the controller, not the application, aggregates health.
type Registry struct{ capabilities []capability }

func (r *Registry) Capability(name string, required bool, c Checker) {
	if name == "" || c == nil {
		panic("health: capability name and checker are required")
	}
	for _, existing := range r.capabilities {
		if existing.name == name {
			panic("health: duplicate capability " + name)
		}
	}
	r.capabilities = append(r.capabilities, capability{name: name, required: required, checker: c, slot: make(chan struct{}, 1)})
}

func unknown() Status {
	return Status{State: apphealth.StateUnknown, Reason: apphealth.ReasonNoEvidence}
}

// Handler rejects the public marker set by
// appthrust-operator/pkg/controllers/core/publish/model/httppublish/httproute.go:
// KnativeBackendFilters. Envoy Gateway v1.8.4 internal/gatewayapi/filters.go:
// processRequestHeaderModifierFilter translates Set to Append:false; its
// internal/xds/translator/route.go:buildXdsAddedHeaders uses OVERWRITE_IF_EXISTS_OR_ADD.
// Knative v1.22.1 pkg/queue/sharedmain/main.go:buildProxyHandler prunes only
// activator.RevisionHeaders via pkg/http/proxy.go:NewHeaderPruningReverseProxy.
// It consumes K-Original-Host in RewriteHostOut, but preserves this application header.
// Authorization is also rejected: pkg/appserver/identity.Authenticate
// uses it for bearer/assertions; k8s.io/apiserver v0.34.0
// pkg/endpoints/filters/authentication.go:89 removes it after authentication.
// Do NOT reject X-Forwarded-* headers: apimachinery/pkg/util/proxy/transport.go
// sets them on Service proxy requests.
func (r *Registry) Handler(release func() (digest, version string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		for key := range req.Header {
			if strings.EqualFold(key, apphealth.PublicRouteHeader) || strings.EqualFold(key, "Authorization") {
				http.NotFound(w, req)
				return
			}
		}
		if req.URL.Path != Path {
			http.NotFound(w, req)
			return
		}
		if req.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(req.Context(), Budget)
		defer cancel()
		type result struct {
			index  int
			status Status
		}
		results := make(chan result, len(r.capabilities))
		report := apphealth.Report{Capabilities: make([]apphealth.Capability, len(r.capabilities))}
		pending := 0
		for i, c := range r.capabilities {
			report.Capabilities[i] = apphealth.Capability{Name: c.name, State: apphealth.StateUnknown, Reason: apphealth.ReasonNoEvidence, Message: "Health check has no observation within its budget"}
			select {
			case c.slot <- struct{}{}:
				pending++
				go func(i int, c capability) {
					defer func() { <-c.slot }()
					results <- result{i, c.checker.Check(ctx)}
				}(i, c)
			default:
				// A checker that ignores cancellation cannot accumulate goroutines.
			}
		}
		for pending > 0 {
			select {
			case result := <-results:
				pending--
				s := result.status
				if len(s.Message) > 256 {
					s.Message = s.Message[:256]
					for !utf8.ValidString(s.Message) {
						s.Message = s.Message[:len(s.Message)-1]
					}
				}
				c := apphealth.Capability{Name: report.Capabilities[result.index].Name, State: s.State, Reason: s.Reason, Message: s.Message}
				if (apphealth.Report{Capabilities: []apphealth.Capability{c}}).Validate(nil) == nil {
					report.Capabilities[result.index] = c
				}
			case <-ctx.Done():
				pending = 0
			}
		}
		if release != nil {
			report.Release.ArtifactDigest, report.Release.ReleaseVersion = release()
		}
		report.ObservedAt = time.Now().UTC()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(report)
	})
}

// RateLimited coalesces probes and caches their result for at least 15 seconds.
// Checkers must honor ctx; while a probe is in flight other callers get the last
// result, or wait within ctx for the first result, never starting a second probe.
func RateLimited(c Checker) Checker { return &synthetic{checker: c, now: time.Now} }

type synthetic struct {
	mu      sync.Mutex
	checker Checker
	now     func() time.Time
	next    time.Time
	running chan struct{}
	status  Status
}

func (s *synthetic) Check(ctx context.Context) Status {
	s.mu.Lock()
	if s.running != nil || s.now().Before(s.next) {
		result := s.status
		wait := s.running
		if result.State == "" && wait != nil {
			s.mu.Unlock()
			select {
			case <-wait:
				s.mu.Lock()
				result = s.status
				s.mu.Unlock()
				return result
			case <-ctx.Done():
				return unknown()
			}
		}
		if result.State == "" {
			result = Status{State: apphealth.StateUnknown, Reason: apphealth.ReasonInitialising}
		}
		s.mu.Unlock()
		return result
	}
	s.running = make(chan struct{})
	s.next = s.now().Add(SyntheticInterval)
	s.mu.Unlock()
	result := s.checker.Check(ctx)
	s.mu.Lock()
	s.status = result
	close(s.running)
	s.running = nil
	s.mu.Unlock()
	return result
}

type outcome struct {
	at    time.Time
	ok    bool
	class string
}

// Outcomes is a zero-value-ready, concurrent ring of the last 16 attempts,
// expiring after five minutes. Record only attempted work, not invalid requests
// or caller authentication failures. class is a wire reason, never an error.
type Outcomes struct {
	mu      sync.Mutex
	entries [16]outcome
	next    int
}

func (o *Outcomes) Record(ok bool, class string) {
	if o == nil {
		return
	}
	switch class {
	case apphealth.ReasonDependencyUnavailable, apphealth.ReasonUpstreamUnavailable, apphealth.ReasonUpstreamDenied, apphealth.ReasonResourceExhausted, apphealth.ReasonInitialising, apphealth.ReasonNoEvidence:
	default:
		class = apphealth.ReasonUpstreamUnavailable
	}
	o.mu.Lock()
	o.entries[o.next] = outcome{at: time.Now(), ok: ok, class: class}
	o.next = (o.next + 1) % len(o.entries)
	o.mu.Unlock()
}

func (o *Outcomes) Check(context.Context) Status {
	if o == nil {
		return unknown()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	cutoff := time.Now().Add(-outcomeWindow)
	total, failures := 0, 0
	var latest time.Time
	class := ""
	for _, entry := range o.entries {
		if entry.at.Before(cutoff) {
			continue
		}
		total++
		if !entry.ok {
			failures++
			if entry.at.After(latest) {
				latest, class = entry.at, entry.class
			}
		}
	}
	if total == 0 {
		return unknown()
	}
	if failures*2 < total {
		return Status{State: apphealth.StateServing}
	}
	state := apphealth.StateDegraded
	if total >= 3 && failures == total {
		state = apphealth.StateFailing
	}
	return Status{State: state, Reason: class, Message: fmt.Sprintf("%d of the last %d attempts failed", failures, total)}
}

// WithDependency keeps failing application outcomes visible even when a cheap
// dependency check succeeds. A dependency outage takes precedence over traffic.
func WithDependency(outcomes *Outcomes, dependency Checker) Checker {
	return CheckFunc(func(ctx context.Context) Status {
		d := dependency.Check(ctx)
		if d.State != apphealth.StateServing {
			return d
		}
		s := outcomes.Check(ctx)
		if s.State == apphealth.StateUnknown {
			return d
		}
		return s
	})
}

// Last retains the most recent warmup/inference result until new work replaces
// it. Model servers combine this with current supervisor readiness; unlike a
// traffic-rate summary, an idle model must not forget a failed inference.
func (o *Outcomes) Last() Status {
	if o == nil {
		return unknown()
	}
	o.mu.Lock()
	entry := o.entries[(o.next+len(o.entries)-1)%len(o.entries)]
	o.mu.Unlock()
	if entry.at.IsZero() {
		return unknown()
	}
	if entry.ok {
		return Status{State: apphealth.StateServing}
	}
	state := apphealth.StateFailing
	if entry.class == apphealth.ReasonResourceExhausted {
		state = apphealth.StateDegraded
	}
	return Status{State: state, Reason: entry.class, Message: "The last model operation failed"}
}
