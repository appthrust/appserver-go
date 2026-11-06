package accesskey

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestHTTPJWKSSourceCacheAndStaleOnError(t *testing.T) {
	set := NewES256Signer("current", mustES256Key(t)).JWKS()
	var fetches atomic.Int32
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if r.Method != http.MethodGet {
			t.Error("JWKS fetch must use GET")
		}
		if fail.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := json.NewEncoder(w).Encode(set); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	source := NewHTTPJWKSSource(server.URL, server.Client(), time.Minute).(*httpJWKSSource)
	source.now = func() time.Time { return now }
	for i := range 3 {
		keys, err := source.Keys(context.Background())
		if err != nil || len(keys.Keys) != 1 || keys.Keys[0].KeyID != "current" {
			t.Fatalf("cached fetch %d failed: %v", i, err)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("cached fetch count = %d, want 1", fetches.Load())
	}
	now = now.Add(time.Minute)
	if _, err := source.Keys(context.Background()); err != nil || fetches.Load() != 2 {
		t.Fatalf("TTL boundary fetch: %v, count %d", err, fetches.Load())
	}
	fail.Store(true)
	now = now.Add(time.Minute)
	keys, err := source.Keys(context.Background())
	if err != nil || len(keys.Keys) != 1 || keys.Keys[0].KeyID != "current" || fetches.Load() != 3 {
		t.Fatalf("stale-on-error: %v, fetch count %d", err, fetches.Load())
	}
	uncached := NewHTTPJWKSSource(server.URL, server.Client(), time.Minute)
	if _, err := uncached.Keys(context.Background()); err == nil {
		t.Fatal("initial fetch failure must not become an empty successful cache")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := fetches.Load()
	if _, err := source.Keys(ctx); !errors.Is(err, context.Canceled) || fetches.Load() != before {
		t.Fatal("canceled requests must not fetch")
	}
}

func TestHTTPJWKSSourceSingleFlight(t *testing.T) {
	set := NewES256Signer("current", mustES256Key(t)).JWKS()
	var fetches atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fetches.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		if err := json.NewEncoder(w).Encode(set); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	defer releaseOnce.Do(func() { close(release) })
	source := NewHTTPJWKSSource(server.URL, server.Client(), time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const workers = 16
	results := make(chan error, workers)
	for range workers {
		go func() {
			keys, err := source.Keys(ctx)
			if err == nil && (len(keys.Keys) != 1 || keys.Keys[0].KeyID != "current") {
				err = errors.New("missing shared key set")
			}
			results <- err
		}()
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("HTTP refresh did not start")
	}
	waitCtx, waitCancel := context.WithCancel(ctx)
	waitResult := make(chan error, 1)
	go func() {
		_, err := source.Keys(waitCtx)
		waitResult <- err
	}()
	waitCancel()
	if err := <-waitResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v", err)
	}
	releaseOnce.Do(func() { close(release) })
	for range workers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("concurrent fetch count = %d, want 1", fetches.Load())
	}
}

func TestHTTPJWKSUnknownKidRefreshThrottle(t *testing.T) {
	old, current := mustES256Key(t), mustES256Key(t)
	oldSet := NewES256Signer("old", old).JWKS()
	rotatedSet := NewES256Signer("current", current, oldSet.Keys[0]).JWKS()
	var fetches atomic.Int32
	var rotated atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		set := oldSet
		if rotated.Load() {
			set = rotatedSet
		}
		if err := json.NewEncoder(w).Encode(set); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	source := NewHTTPJWKSSource(server.URL, server.Client(), time.Hour).(*httpJWKSSource)
	source.now = func() time.Time { return now }
	key := testKey()
	claims := NewClaims("https://dashboard.example/access", key.Project, Decide(&key, true, now), now, MaxAssertionTTL)
	verifier := NewVerifier(claims.Issuer, source)
	verifier.now = func() time.Time { return now }
	verify := func(kid string, signingKey any, want error) {
		t.Helper()
		raw := signPayload(t, signingKey, jose.ES256, kid, AssertionType, claims)
		if _, err := verifier.Verify(context.Background(), raw, "knowledge"); !errors.Is(err, want) {
			t.Fatalf("verification error = %v, want %v", err, want)
		}
	}
	verify("old", old, nil)
	verify("old", old, nil)
	if fetches.Load() != 1 {
		t.Fatalf("known kid fetches = %d, want 1", fetches.Load())
	}
	rotated.Store(true)
	verify("current", current, nil)
	verify("old", old, nil)
	if fetches.Load() != 2 {
		t.Fatalf("unknown kid must force one refresh, got %d fetches", fetches.Load())
	}
	for range 3 {
		verify("unknown", current, ErrInvalidAssertion)
	}
	if fetches.Load() != 2 {
		t.Fatal("unknown kid refreshes exceeded one per minute")
	}
	now = now.Add(time.Minute)
	verify("unknown", current, ErrInvalidAssertion)
	if fetches.Load() != 3 {
		t.Fatalf("refresh after throttle expiry: %d fetches, want 3", fetches.Load())
	}
}

func TestHTTPJWKSSourceRejectsInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]} trailing`))
	}))
	defer server.Close()
	if _, err := NewHTTPJWKSSource(server.URL, server.Client(), time.Minute).Keys(context.Background()); err == nil {
		t.Fatal("invalid JWKS JSON was accepted")
	}
}
