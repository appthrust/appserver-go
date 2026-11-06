// Package pending keeps an built-in app server alive and unready while a dependency
// such as its database is unreachable. A Pod that exits on the first failed
// connection turns a CNPG failover into a CrashLoopBackOff ladder on top of
// the failover; serving 503 from /readyz and the API until the dependency
// connects costs only the outage itself.
package pending

import (
	"context"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// RetryMax bounds the wait between connection attempts.
const RetryMax = 30 * time.Second

// Handler serves a placeholder until Swap installs the real handler. Readiness
// flips once and stays true: later outages are the installed handler's
// concern (its pool reconnects on its own).
type Handler struct {
	handler atomic.Pointer[http.Handler]
	ready   atomic.Bool
}

func Serve(placeholder http.Handler) *Handler {
	h := &Handler{}
	h.handler.Store(&placeholder)
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	(*h.handler.Load()).ServeHTTP(w, r)
}

func (h *Handler) Ready() bool { return h.ready.Load() }

// Swap installs handler and marks the server ready.
func (h *Handler) Swap(handler http.Handler) {
	h.handler.Store(&handler)
	h.ready.Store(true)
}

// Probes registers GET /healthz, always ok, and GET /readyz, 503 until ready
// reports true. Liveness never depends on the dependency, so an outage marks
// the Pod unready instead of restarting it. A nil ready is always ready.
func Probes(mux *http.ServeMux, ready func() bool) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if ready != nil && !ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready\n"))
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
}

// Connect returns immediately and runs connect in the background, retrying
// with waits doubling from initial to RetryMax until connect succeeds or stop
// is called. The first attempt is not synchronous: a dependency whose packets
// are dropped (no RST) blocks connect for its full dial timeout, and a server
// that waits for it before listening fails its liveness probe and is killed
// instead of reporting NotReady. The returned stop cancels the in-flight
// attempt, waits for the loop, and closes whatever a successful connect
// returned. name labels log lines.
func Connect(name string, initial time.Duration, connect func(context.Context) (io.Closer, error)) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var closer io.Closer
	attempt := func() error {
		c, err := connect(ctx)
		if err != nil {
			return err
		}
		mu.Lock()
		closer = c
		mu.Unlock()
		return nil
	}
	done := make(chan struct{})
	closeResource := func() {
		mu.Lock()
		defer mu.Unlock()
		if closer != nil {
			_ = closer.Close()
		}
	}
	go func() {
		defer close(done)
		err := attempt()
		for delay := initial; err != nil; delay = min(2*delay, RetryMax) {
			log.Printf("%s unavailable, retrying in %s: %v", name, delay, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			if err = attempt(); err == nil {
				log.Printf("%s connected", name)
			}
		}
	}()
	return func() {
		cancel()
		<-done
		closeResource()
	}
}
