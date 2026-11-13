package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/appthrust/appserver-go/accesskey"
	"github.com/appthrust/appserver-go/appserver/httpx"
	"github.com/appthrust/appserver-go/appserver/platformenv"
)

const (
	appAccessCacheSize = 1024
	appAccessCacheSkew = 5 * time.Second
	userTokenPath      = "/api/v1/access/user-token"
)

// AppAccessConfig opts an Authenticator into user-permission exchange. Project
// and exactly one of Installation or Application are required, even when the app
// currently declares no roles. Configuration is copied at construction.
type AppAccessConfig struct {
	PlatformOrigin  string
	Project         string
	Installation    string
	InstallationUID string
	Application     string
	// RequirePermissions makes Authenticate deny declared apps with empty scope.
	RequirePermissions bool
	// CacheSize bounds cached users and concurrent exchanges; zero uses 1024.
	CacheSize int
	// Now supplies the clock for assertion verification and caching; nil uses time.Now.
	Now func() time.Time
}

// AppAccessFromEnv reads existing platform connection variables. installation
// is the app's known installation/definition name. Optional environment overrides
// are reserved for platforms that inject installation identity; they are not
// injected by the initial ADR-0082 platform release.
func AppAccessFromEnv(installation string) AppAccessConfig {
	if value := os.Getenv("PLATFORM_APP_INSTALLATION_NAME"); value != "" {
		installation = value
	}
	return AppAccessConfig{
		PlatformOrigin: os.Getenv("PLATFORM_API_URL"), Project: os.Getenv("PLATFORM_PROJECT_ID"),
		Installation: installation, InstallationUID: os.Getenv("PLATFORM_APP_INSTALLATION_UID"),
	}
}

// AppAccess describes the app's access model, not a grant. Only the
// verified Principal.Scopes grants permissions. Nil Identity.Access means no exchange.
type AppAccess struct {
	Declared bool `json:"declared"`
	Accepted bool `json:"accepted"`
}

type appAccessKey struct{ issuer, subject, audience string }
type appAccessResult struct {
	access  AppAccess
	scopes  []string
	expires time.Time
	application, applicationUID string
}
type appAccessFlight struct {
	done   chan struct{}
	result appAccessResult
	err    error
}
type appAccessClient struct {
	config   AppAccessConfig
	http     *http.Client
	verifier *accesskey.Verifier
	now      func() time.Time
	mu       sync.Mutex
	cache    map[appAccessKey]appAccessResult
	flights  map[appAccessKey]*appAccessFlight
}

func newAppAccessClient(config AppAccessConfig, client *http.Client, verifier *accesskey.Verifier) (*appAccessClient, error) {
	origin, err := platformenv.Validate(config.PlatformOrigin, config.Project)
	if err != nil {
		return nil, err
	}
	if (config.Installation == "") == (config.Application == "") {
		return nil, errors.New("app access requires exactly one of installation or application")
	}
	if config.CacheSize < 0 {
		return nil, errors.New("app access cache size must not be negative")
	}
	if config.CacheSize == 0 {
		config.CacheSize = appAccessCacheSize
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	config.PlatformOrigin = origin.String()
	return &appAccessClient{
		config: config, now: config.Now, verifier: verifier,
		http: &http.Client{Transport: client.Transport, Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		cache: make(map[appAccessKey]appAccessResult), flights: make(map[appAccessKey]*appAccessFlight),
	}, nil
}

func accessUnavailable(retryAfter string) error {
	return &httpx.Error{Status: http.StatusServiceUnavailable, Code: "access_unavailable", Message: "App access verification is unavailable", RetryAfter: retryAfter}
}

// resolve is called only after OIDC verification; neither the bearer nor the
// returned assertion is retained in the cache. Each caller owns its scope slice.
func (c *appAccessClient) resolve(ctx context.Context, key appAccessKey, bearer string) (appAccessResult, error) {
	if key.issuer == "" || key.subject == "" || key.audience == "" {
		return appAccessResult{}, httpx.Fail(http.StatusUnauthorized, "unauthenticated", "A valid app user bearer is required")
	}
	if ctx.Err() != nil {
		return appAccessResult{}, accessUnavailable("")
	}
	c.mu.Lock()
	if cached, found := c.cache[key]; found {
		if c.now().Before(cached.expires) {
			c.mu.Unlock()
			cached.scopes = slices.Clone(cached.scopes)
			return cached, nil
		}
		delete(c.cache, key)
	}
	if flight := c.flights[key]; flight != nil {
		c.mu.Unlock()
		select {
		case <-flight.done:
			if flight.err != nil {
				return appAccessResult{}, flight.err
			}
			if !c.now().Before(flight.result.expires) {
				return appAccessResult{}, accessUnavailable("")
			}
			result := flight.result
			result.scopes = slices.Clone(result.scopes)
			return result, nil
		case <-ctx.Done():
			return appAccessResult{}, accessUnavailable("")
		}
	}
	if len(c.flights) >= c.config.CacheSize {
		c.mu.Unlock()
		return appAccessResult{}, accessUnavailable("1")
	}
	flight := &appAccessFlight{done: make(chan struct{})}
	c.flights[key] = flight
	c.mu.Unlock()

	result, err := c.exchange(ctx, key, bearer)
	c.mu.Lock()
	if err == nil && c.now().Before(result.expires) {
		if len(c.cache) >= c.config.CacheSize {
			// Evict the earliest expiry, retaining a bounded map without an LRU allocation per hit.
			var oldest appAccessKey
			var expiry time.Time
			for k, entry := range c.cache {
				if expiry.IsZero() || entry.expires.Before(expiry) {
					oldest, expiry = k, entry.expires
				}
			}
			delete(c.cache, oldest)
		}
		c.cache[key] = result
	}
	flight.result, flight.err = result, err
	delete(c.flights, key)
	close(flight.done)
	c.mu.Unlock()
	result.scopes = slices.Clone(result.scopes)
	return result, err
}

func (c *appAccessClient) exchange(ctx context.Context, key appAccessKey, bearer string) (appAccessResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.PlatformOrigin+userTokenPath, nil)
	if err != nil {
		return appAccessResult{}, accessUnavailable("")
	}
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Accept", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return appAccessResult{}, accessUnavailable("")
	}
	receivedAt := c.now()
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return appAccessResult{}, httpx.Fail(http.StatusUnauthorized, "unauthenticated", "A valid app user bearer is required")
	case http.StatusTooManyRequests:
		hint := response.Header.Get("Retry-After")
		if seconds, err := strconv.ParseUint(hint, 10, 32); err != nil || seconds == 0 {
			if _, err := http.ParseTime(hint); err != nil {
				hint = "1"
			}
		}
		return appAccessResult{}, accessUnavailable(hint)
	default:
		return appAccessResult{}, accessUnavailable("")
	}
	const maxResponse = 1 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil || len(data) > maxResponse {
		return appAccessResult{}, accessUnavailable("")
	}
	var wire struct {
		Token           string    `json:"token"`
		ExpiresAt       time.Time `json:"expiresAt"`
		Audience        string    `json:"audience"`
		Project         string    `json:"project"`
		Installation    string    `json:"installation"`
		InstallationUID string    `json:"installationUID"`
		Application     string    `json:"application"`
		Roles           []string  `json:"roles"`
		Scopes          []string  `json:"scopes"`
		Access          struct {
			Declared *bool `json:"declared"`
			Accepted *bool `json:"accepted"`
		} `json:"access"`
	}
	if json.Unmarshal(data, &wire) != nil || wire.Access.Declared == nil || wire.Access.Accepted == nil ||
		wire.Audience != key.audience || wire.Project != c.config.Project ||
		(c.config.Installation != "" && (wire.Installation != c.config.Installation ||
			(c.config.InstallationUID != "" && wire.InstallationUID != c.config.InstallationUID))) ||
		(c.config.Application != "" && wire.Application != c.config.Application) {
		return appAccessResult{}, accessUnavailable("")
	}
	claims, err := c.verifier.VerifySession(ctx, wire.Token, accesskey.SessionBinding{
		Audience: key.audience, Subject: key.subject, SubjectIssuer: key.issuer,
		Project: c.config.Project, Installation: c.config.Installation, InstallationUID: c.config.InstallationUID,
		Application: c.config.Application,
	}, c.now())
	if err != nil || !wire.ExpiresAt.Equal(claims.ExpiresAt) || !c.now().Before(claims.ExpiresAt) {
		return appAccessResult{}, accessUnavailable("")
	}
	// Bound retention by a local duration as well as signed wall-clock expiry:
	// a slow app clock must not extend the cache by its offset from the issuer.
	expires := claims.ExpiresAt.Add(-appAccessCacheSkew)
	localExpiry := receivedAt.Add(claims.ExpiresAt.Sub(claims.IssuedAt) - appAccessCacheSkew)
	if localExpiry.Before(expires) {
		expires = localExpiry
	}
	return appAccessResult{
		access: AppAccess{Declared: *wire.Access.Declared, Accepted: *wire.Access.Accepted},
		scopes: claims.Scopes, expires: expires,
		application: claims.Application, applicationUID: claims.ApplicationUID,
	}, nil
}
