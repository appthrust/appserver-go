package identity

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A waiter signals when it enters the resolver's select, without sleeps or
// depending on goroutine scheduling. It never cancels the exchange leader.
type waitingAccessContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *waitingAccessContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestAppAccessSingleFlightSharesFailureAndBoundsInflight(t *testing.T) {
	f := newAppAccessFixture(t)
	f.status.Store(http.StatusServiceUnavailable)
	f.started, f.release = make(chan struct{}, 10), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(f.release) })
	a := f.auth(t, func(c *AppAccessConfig) { c.CacheSize = 1 })
	key := appAccessKey{issuer: f.issuer(), subject: "person", audience: "expense-client"}
	bearer := f.bearer(t, key.subject, key.audience)
	leader := make(chan error, 1)
	go func() { _, err := a.appAccess.resolve(t.Context(), key, bearer); leader <- err }()
	select {
	case <-f.started:
	case <-time.After(5 * time.Second):
		t.Fatal("leader exchange never started")
	}
	other := key
	other.subject = "other-person"
	_, err := a.appAccess.resolve(t.Context(), other, f.bearer(t, other.subject, other.audience))
	require.Error(t, err, "another identity must not exceed the inflight bound")
	const waiters = 5
	results := make(chan error, waiters)
	for range waiters {
		ctx := &waitingAccessContext{Context: t.Context(), entered: make(chan struct{})}
		go func() { _, err := a.appAccess.resolve(ctx, key, bearer); results <- err }()
		select {
		case <-ctx.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("waiter did not join exchange")
		}
	}
	// A waiter may depart while the same exchange remains available to others.
	cancelContext, cancel := context.WithCancel(t.Context())
	ctx := &waitingAccessContext{Context: cancelContext, entered: make(chan struct{})}
	cancelled := make(chan error, 1)
	go func() { _, err := a.appAccess.resolve(ctx, key, bearer); cancelled <- err }()
	select {
	case <-ctx.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled waiter did not join")
	}
	cancel()
	require.Error(t, <-cancelled)
	release.Do(func() { close(f.release) })
	require.Error(t, <-leader)
	for range waiters {
		require.Error(t, <-results)
	}
	require.EqualValues(t, 1, f.calls.Load(), "concurrent waiters must share the failed attempt")
	_, err = a.appAccess.resolve(t.Context(), key, bearer)
	require.Error(t, err)
	require.EqualValues(t, 2, f.calls.Load(), "a later request must retry; failures are not cached")
}
