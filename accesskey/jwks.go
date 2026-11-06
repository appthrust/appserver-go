package accesskey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// JWKSSource provides trusted verification keys. Returned sets are read-only.
type JWKSSource interface {
	Keys(ctx context.Context) (jose.JSONWebKeySet, error)
}

type staticJWKSSource struct{ set jose.JSONWebKeySet }

func NewStaticJWKSSource(set jose.JSONWebKeySet) JWKSSource {
	return &staticJWKSSource{set: set}
}

func (s *staticJWKSSource) Keys(context.Context) (jose.JSONWebKeySet, error) {
	return s.set, nil
}

type jwksFetch struct {
	done chan struct{}
	set  jose.JSONWebKeySet
	err  error
}

type httpJWKSSource struct {
	url    string
	client *http.Client
	ttl    time.Duration
	now    func() time.Time

	mu          sync.Mutex
	set         jose.JSONWebKeySet
	cached      bool
	expires     time.Time
	lastUnknown time.Time
	inflight    *jwksFetch
}

// NewHTTPJWKSSource caches successful responses for ttl, coalesces concurrent
// fetches, and serves the last successful set on refresh errors. A nil client
// uses http.DefaultClient; callers should supply a timeout or context deadline.
// Unknown-kid refreshes bypass ttl at most once per minute per source.
func NewHTTPJWKSSource(url string, client *http.Client, ttl time.Duration) JWKSSource {
	if client == nil {
		client = http.DefaultClient
	}
	return &httpJWKSSource{url: url, client: client, ttl: ttl, now: time.Now}
}

func (s *httpJWKSSource) Keys(ctx context.Context) (jose.JSONWebKeySet, error) {
	return s.keys(ctx, false)
}

func (s *httpJWKSSource) refresh(ctx context.Context) (jose.JSONWebKeySet, error) {
	return s.keys(ctx, true)
}

func (s *httpJWKSSource) keys(ctx context.Context, unknown bool) (jose.JSONWebKeySet, error) {
	if err := ctx.Err(); err != nil {
		return jose.JSONWebKeySet{}, err
	}
	s.mu.Lock()
	now := s.now()
	if !unknown && s.cached && now.Before(s.expires) {
		set := s.set
		s.mu.Unlock()
		return set, nil
	}
	if f := s.inflight; f != nil {
		s.mu.Unlock()
		select {
		case <-f.done:
			return f.set, f.err
		case <-ctx.Done():
			return jose.JSONWebKeySet{}, ctx.Err()
		}
	}
	if unknown && !s.lastUnknown.IsZero() && now.Sub(s.lastUnknown) < time.Minute {
		set := s.set
		s.mu.Unlock()
		return set, nil
	}
	if unknown {
		s.lastUnknown = now
	}
	f := &jwksFetch{done: make(chan struct{})}
	s.inflight = f
	s.mu.Unlock()

	set, err := s.fetch(ctx)
	s.mu.Lock()
	if err == nil {
		s.set, s.cached, s.expires = set, true, s.now().Add(s.ttl)
	} else if s.cached {
		set, err = s.set, nil
	}
	f.set, f.err = set, err
	s.inflight = nil
	close(f.done)
	s.mu.Unlock()
	return set, err
}

func (s *httpJWKSSource) fetch(ctx context.Context) (jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("accesskey: JWKS request: %w", err)
	}
	response, err := s.client.Do(req)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("accesskey: fetch JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, fmt.Errorf("accesskey: JWKS HTTP status %d", response.StatusCode)
	}
	// A bounded read also rejects a valid JSON prefix followed by excess data.
	const maxBytes = 1 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("accesskey: read JWKS: %w", err)
	}
	if len(data) > maxBytes {
		return jose.JSONWebKeySet{}, errors.New("accesskey: JWKS exceeds 1 MiB")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("accesskey: decode JWKS: %w", err)
	}
	return set, nil
}
