package link

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxBody = 4 << 20

type cacheKey struct {
	url       string
	principal [32]byte
}
type cachedResponse struct {
	etag    string
	body    []byte
	expires time.Time
}

type Client struct {
	resolver *Resolver
	http     *http.Client
	mu       sync.Mutex
	cache    map[cacheKey]cachedResponse
}

func NewClient(resolver *Resolver, transport http.RoundTripper) *Client {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &Client{resolver: resolver, http: &http.Client{Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, cache: make(map[cacheKey]cachedResponse)}
}
func (c *Client) Resolver() *Resolver { return c.resolver }

func (c *Client) Do(ctx context.Context, bearer string, op Operation, params Params, in any, out any) error {
	if err := op.validateTarget(); err != nil {
		return err
	}
	binding, err := c.resolver.Resolve(ctx, bearer, op.Definition)
	if err != nil {
		return err
	}
	return c.DoAt(ctx, bearer, binding, op, params, in, out)
}

// DoAt calls an operation at an already-resolved provider binding using the
// viewer's bearer verbatim. A non-Ready binding is absent, not a transport error.
func (c *Client) DoAt(ctx context.Context, bearer string, binding Binding, op Operation, params Params, in, out any) error {
	body, err := c.do(ctx, bearer, binding, op, params, in)
	if err != nil || out == nil || len(body) == 0 {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: invalid JSON response: %v", ErrUnavailable, err)
	}
	return nil
}

// Document fetches the callee-owned OpenAPI document over the same authenticated,
// bounded transport as operations. Base is the contract's servers[0].url.
func (c *Client) Document(ctx context.Context, bearer, definition, base string) ([]byte, error) {
	binding, err := c.resolver.Resolve(ctx, bearer, definition)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, bearer, binding, Operation{Definition: definition, Base: base, Method: http.MethodGet, Path: "/openapi.json"}, Params{}, nil)
}

// Fetch reads a binary operation without caching its response.
func (c *Client) Fetch(ctx context.Context, bearer string, op Operation, params Params) ([]byte, string, error) {
	if err := op.validateTarget(); err != nil {
		return nil, "", err
	}
	binding, err := c.resolver.Resolve(ctx, bearer, op.Definition)
	if err != nil {
		return nil, "", err
	}
	return c.request(ctx, bearer, binding, op, params, nil, "image/*", false)
}

func (c *Client) do(ctx context.Context, bearer string, binding Binding, op Operation, params Params, in any) ([]byte, error) {
	body, _, err := c.request(ctx, bearer, binding, op, params, in, "application/json", true)
	return body, err
}

func (c *Client) request(ctx context.Context, bearer string, binding Binding, op Operation, params Params, in any, accept string, cache bool) ([]byte, string, error) {
	if err := op.validateTarget(); err != nil {
		return nil, "", err
	}
	if binding.State != StateReady {
		return nil, "", ErrAbsent
	}
	if binding.InternalURL == "" {
		return nil, "", ErrUnavailable
	}
	base := op.Base
	path := op.Path
	for name, value := range params.Path {
		path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(value))
	}
	if (base != "" && !strings.HasPrefix(base, "/")) || !strings.HasPrefix(path, "/") || strings.ContainsAny(base+path, "{}?#") {
		return nil, "", fmt.Errorf("invalid link operation path")
	}
	endpoint := strings.TrimRight(binding.InternalURL, "/") + strings.TrimRight(base, "/") + path
	if query := params.Query.Encode(); query != "" {
		endpoint += "?" + query
	}
	var input io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return nil, "", err
		}
		input = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, op.Method, endpoint, input)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Accept", accept)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	cache = cache && req.Method == http.MethodGet
	var key cacheKey
	var cached cachedResponse
	if cache {
		key = cacheKey{endpoint, sha256.Sum256([]byte(bearer))}
		c.mu.Lock()
		cached = c.cache[key]
		if !time.Now().Before(cached.expires) {
			delete(c.cache, key)
			cached = cachedResponse{}
		}
		c.mu.Unlock()
		if cached.etag != "" {
			req.Header.Set("If-None-Match", cached.etag)
		}
	}
	response, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified && cache && cached.etag != "" {
		return bytes.Clone(cached.body), "", nil
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, "", &DeniedError{Status: response.StatusCode}
	}
	if response.StatusCode >= 500 {
		return nil, "", fmt.Errorf("%w: HTTP %d", ErrUnavailable, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil {
		return nil, "", fmt.Errorf("%w: reading response: %v", ErrUnavailable, err)
	}
	if len(body) > maxBody {
		return nil, "", fmt.Errorf("%w: response exceeds 4 MiB", ErrUnavailable)
	}
	if response.StatusCode >= 400 {
		var envelope struct {
			Code    string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &envelope)
		return nil, "", &RejectedError{Status: response.StatusCode, Code: envelope.Code, Message: envelope.Message}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, "", fmt.Errorf("%w: HTTP %d", ErrUnavailable, response.StatusCode)
	}
	if cache {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.cache {
			if !now.Before(entry.expires) {
				delete(c.cache, key)
			}
		}
		if etag := response.Header.Get("ETag"); etag != "" {
			c.cache[key] = cachedResponse{etag, bytes.Clone(body), now.Add(cacheTTL)}
		} else {
			delete(c.cache, key)
		}
		c.mu.Unlock()
	}
	return body, response.Header.Get("Content-Type"), nil
}
