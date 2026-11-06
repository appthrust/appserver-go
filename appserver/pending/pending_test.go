package pending

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type closer struct{ closed atomic.Bool }

func (c *closer) Close() error { c.closed.Store(true); return nil }

func TestConnectRetriesUntilSuccessAndStopCloses(t *testing.T) {
	h := Serve(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	resource := &closer{}
	var attempts atomic.Int32
	stop := Connect("test database", time.Millisecond, func(context.Context) (io.Closer, error) {
		if attempts.Add(1) < 4 {
			return nil, errors.New("refused")
		}
		h.Swap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		return resource, nil
	})
	if h.Ready() {
		t.Fatal("ready before the first attempt succeeded")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !h.Ready() {
		if time.Now().After(deadline) {
			t.Fatalf("never became ready after %d attempts", attempts.Load())
		}
		time.Sleep(time.Millisecond)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != 200 || attempts.Load() != 4 {
		t.Fatalf("status=%d attempts=%d", w.Code, attempts.Load())
	}
	stop()
	if !resource.closed.Load() {
		t.Fatal("stop did not close the connected resource")
	}
}

func TestStopDuringBackoffReturnsPromptly(t *testing.T) {
	var attempts atomic.Int32
	stop := Connect("test database", time.Hour, func(context.Context) (io.Closer, error) {
		attempts.Add(1)
		return nil, errors.New("refused")
	})
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop waited out the backoff")
	}
	if attempts.Load() != 1 {
		t.Fatalf("attempts=%d", attempts.Load())
	}
}

func TestImmediateSuccessClosesOnStop(t *testing.T) {
	resource := &closer{}
	stop := Connect("test database", time.Hour, func(context.Context) (io.Closer, error) { return resource, nil })
	stop()
	if !resource.closed.Load() {
		t.Fatal("stop did not close the resource")
	}
}

// A dependency whose packets are dropped blocks the dial for its whole
// timeout. Connect must still return at once so the server can listen and
// answer its liveness probe; stop must cancel the in-flight attempt.
func TestBlackholedFirstAttemptDoesNotBlockConnect(t *testing.T) {
	cancelled := make(chan struct{})
	started := time.Now()
	stop := Connect("test database", time.Hour, func(ctx context.Context) (io.Closer, error) {
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	})
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Connect blocked on the first attempt for %s", elapsed)
	}
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not cancel the in-flight attempt")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not return after cancelling the attempt")
	}
}

// A late success after a blackholed first attempt is still adopted and closed.
func TestLateSuccessAfterBlockedFirstAttempt(t *testing.T) {
	resource := &closer{}
	var attempts atomic.Int32
	stop := Connect("test database", 10*time.Millisecond, func(ctx context.Context) (io.Closer, error) {
		if attempts.Add(1) == 1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(200 * time.Millisecond):
				return nil, errors.New("dial timeout")
			}
		}
		return resource, nil
	})
	deadline := time.Now().Add(5 * time.Second)
	for attempts.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	stop()
	if !resource.closed.Load() {
		t.Fatal("stop did not close the late-connected resource")
	}
}
