package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/appthrust/appserver-go/accesskey"
	"github.com/appthrust/appserver-go/appserver/httpx"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

type appAccessFixture struct {
	server       *httptest.Server
	key          *ecdsa.PrivateKey
	assertionKey *ecdsa.PrivateKey
	now          atomic.Int64
	calls        atomic.Int32
	jwks         atomic.Int32
	status       atomic.Int32
	declared     atomic.Bool
	accepted     atomic.Bool
	scope        atomic.Value
	mutate       func(map[string]any)
	response     func(map[string]any)
	started      chan struct{}
	release      chan struct{}
}

func newAppAccessFixture(t *testing.T) *appAccessFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	f := &appAccessFixture{key: key, assertionKey: key}
	f.now.Store(time.Now().Truncate(time.Second).Unix())
	f.status.Store(http.StatusOK)
	f.declared.Store(true)
	f.accepted.Store(true)
	f.scope.Store("reports:read reports:approve")
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oidc/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.issuer(), "jwks_uri": f.server.URL + "/oidc/keys", "id_token_signing_alg_values_supported": []string{"ES256"}})
		case "/oidc/keys", "/access/jwks.json":
			if r.URL.Path == "/access/jwks.json" {
				f.jwks.Add(1)
			}
			_ = json.NewEncoder(w).Encode(accesskey.NewES256Signer("test-key", f.key).JWKS())
		case userTokenPath:
			f.calls.Add(1)
			if r.Method != http.MethodPost {
				t.Error("exchange must POST")
			}
			body, err := io.ReadAll(r.Body)
			if err != nil || len(body) != 0 {
				t.Error("exchange must have no body")
			}
			if r.Header.Get("Accept") != "application/json" {
				t.Error("missing JSON accept header")
			}
			parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
			if len(parts) != 3 {
				t.Error("missing forwarded user bearer")
				w.WriteHeader(400)
				return
			}
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			var user userClaims
			if err != nil || json.Unmarshal(payload, &user) != nil || user.Issuer == "" || user.Subject == "" {
				t.Error("invalid forwarded user bearer")
				w.WriteHeader(400)
				return
			}
			if f.started != nil {
				f.started <- struct{}{}
				<-f.release
			}
			if status := int(f.status.Load()); status != http.StatusOK {
				w.Header().Set("Retry-After", "7")
				if status == http.StatusFound {
					w.Header().Set("Location", "/redirect-target")
				}
				w.WriteHeader(status)
				return
			}
			now := f.clock()
			claims := map[string]any{
				"iss": f.server.URL + "/access", "sub": "user:" + user.Subject, "aud": []string{user.AuthorizedParty},
				"scope": f.scope.Load().(string), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "test-id",
				"appthrust.io/credential": "session", "appthrust.io/subject_kind": "user", "appthrust.io/subject_issuer": user.Issuer,
				"appthrust.io/project": "project-x", "appthrust.io/installation": "expense", "appthrust.io/installation_uid": "uid-x",
			}
			if f.mutate != nil {
				f.mutate(claims)
			}
			response := map[string]any{
				"token":     signAppToken(t, f.assertionKey, accesskey.AssertionType, claims),
				"expiresAt": now.Add(time.Minute), "audience": user.AuthorizedParty, "project": "project-x",
				"installation": "expense", "installationUID": "uid-x", "roles": []string{"Admin"},
				// These are intentionally not the signed scopes: only the assertion grants access.
				"scopes": []string{"untrusted:permission"},
				"access": map[string]bool{"declared": f.declared.Load(), "accepted": f.accepted.Load()},
			}
			if f.response != nil {
				f.response(response)
			}
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(response)
		default:
			t.Errorf("unexpected endpoint: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func signAppToken(t *testing.T, key *ecdsa.PrivateKey, typ string, claims any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("kid", "test-key"))
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	token, err := signer.Sign(payload)
	require.NoError(t, err)
	raw, err := token.CompactSerialize()
	require.NoError(t, err)
	return raw
}

func (f *appAccessFixture) clock() time.Time { return time.Unix(f.now.Load(), 0) }
func (f *appAccessFixture) issuer() string   { return f.server.URL + "/oidc" }
func (f *appAccessFixture) config() AppAccessConfig {
	return AppAccessConfig{PlatformOrigin: f.server.URL, Project: "project-x", Installation: "expense", InstallationUID: "uid-x", Now: f.clock}
}
func (f *appAccessFixture) auth(t *testing.T, change func(*AppAccessConfig)) *Authenticator {
	t.Helper()
	config := f.config()
	if change != nil {
		change(&config)
	}
	a, err := New(Trust{OIDCIssuer: f.issuer(), OIDCAudiences: []string{"platform-api"}, AccessIssuer: f.server.URL + "/access", AccessAudience: "expense-key", AppAccess: &config})
	require.NoError(t, err)
	return a
}
func (f *appAccessFixture) bearer(t *testing.T, subject, azp string) string {
	t.Helper()
	return "Bearer " + signAppToken(t, f.key, "JWT", map[string]any{
		"iss": f.issuer(), "sub": subject, "aud": []string{"platform-api"}, "azp": azp,
		"exp": time.Now().Add(time.Hour).Unix(), "email": "person@example.test", "name": "Person", "groups": []string{"accounting"},
	})
}
func serveAppRequest(a *Authenticator, bearer string, guard bool) *httptest.ResponseRecorder {
	next := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	if guard {
		next = RequireAppAccess(next)
	}
	r := httptest.NewRequest(http.MethodGet, "/reports", nil)
	r.Header.Set("Authorization", bearer)
	w := httptest.NewRecorder()
	a.Middleware(next).ServeHTTP(w, r)
	return w
}
func requireAppError(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	require.Equal(t, status, w.Code)
	var body httpx.Error
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, code, body.Code)
	require.NotEmpty(t, body.Message)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestAppAccessHappyPath(t *testing.T) {
	f := newAppAccessFixture(t)
	a := f.auth(t, nil)
	bearer := f.bearer(t, "person", "expense-client")
	value, forwarded, err := a.Authenticate(t.Context(), bearer)
	require.NoError(t, err)
	require.True(t, forwarded == bearer, "only the original OIDC bearer may be forwarded")
	require.Equal(t, "user", value.Principal.Kind)
	require.Equal(t, "person", value.Principal.Subject)
	require.Equal(t, "project-x", value.Principal.Project)
	require.Equal(t, []string{"accounting"}, value.Principal.Groups)
	require.Equal(t, "person@example.test", value.Email)
	require.Equal(t, "Person", value.Name)
	require.True(t, value.Principal.Has("reports:approve"))
	require.False(t, value.Principal.Has("Admin"))
	require.False(t, value.Principal.Has("accounting"))
	require.False(t, value.Principal.Has("untrusted:permission"))
	require.Equal(t, &AppAccess{Declared: true, Accepted: true}, value.Access)
	require.EqualValues(t, 1, f.calls.Load())
	require.EqualValues(t, 1, f.jwks.Load())
}

func TestAppAccessTargetBinding(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		application                       bool
		applicationClaim, applicationUID  string
		installationClaim, installationUID string
		reject                            bool
	}{
		{name: "application", application: true, applicationClaim: "expense", applicationUID: "app-uid"},
		{name: "application governed by installation", application: true, applicationClaim: "expense", applicationUID: "app-uid", installationClaim: "catalog-expense", installationUID: "uid-x"},
		{name: "wrong application", application: true, applicationClaim: "other", applicationUID: "app-uid", reject: true},
		{name: "missing application pair", application: true, reject: true},
		{name: "missing application name", application: true, applicationUID: "app-uid", reject: true},
		{name: "missing application UID", application: true, applicationClaim: "expense", reject: true},
		{name: "legacy installation", installationClaim: "expense", installationUID: "uid-x"},
		{name: "installation with application", applicationClaim: "expense-app", applicationUID: "app-uid", installationClaim: "expense", installationUID: "uid-x"},
		{name: "application with installation name only", application: true, applicationClaim: "expense", applicationUID: "app-uid", installationClaim: "expense", reject: true},
		{name: "application with installation UID only", application: true, applicationClaim: "expense", applicationUID: "app-uid", installationUID: "uid-x", reject: true},
		{name: "installation name only", installationClaim: "expense", reject: true},
		{name: "installation UID only", installationUID: "uid-x", reject: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAppAccessFixture(t)
			f.mutate = func(claims map[string]any) {
				for name, value := range map[string]string{
					"appthrust.io/application": tc.applicationClaim, "appthrust.io/application_uid": tc.applicationUID,
					"appthrust.io/installation": tc.installationClaim, "appthrust.io/installation_uid": tc.installationUID,
				} {
					if value == "" {
						delete(claims, name)
					} else {
						claims[name] = value
					}
				}
			}
			f.response = func(wire map[string]any) {
				if tc.application || tc.applicationClaim != "" {
					wire["application"] = "expense"
					wire["applicationUID"] = "unsigned-app-uid"
				}
				if tc.application && tc.installationClaim == "" && tc.installationUID == "" {
					delete(wire, "installation")
					delete(wire, "installationUID")
				}
			}
			a := f.auth(t, func(c *AppAccessConfig) {
				if tc.application {
					c.Application = "expense"
					c.Installation, c.InstallationUID = "", ""
				}
			})
			bearer := f.bearer(t, "person", "expense-client")
			for range 2 {
				if tc.reject {
					requireAppError(t, serveAppRequest(a, bearer, false), 503, "access_unavailable")
					continue
				}
				value, forwarded, err := a.Authenticate(t.Context(), bearer)
				require.NoError(t, err)
				require.Equal(t, bearer, forwarded)
				require.Equal(t, tc.applicationClaim, value.Principal.Application)
				require.Equal(t, tc.applicationUID, value.Principal.ApplicationUID)
				require.True(t, value.Principal.Has("reports:approve"))
				require.False(t, value.Principal.Has("untrusted:permission"))
			}
			if tc.reject {
				require.EqualValues(t, 2, f.calls.Load(), "invalid assertions must not be cached")
			} else {
				require.EqualValues(t, 1, f.calls.Load(), "verified application identity must survive a cache hit")
			}
		})
	}
}

func TestAppAccessRejectsAssertionMismatches(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		value       any
	}{
		{"issuer", "iss", "https://wrong.example/access"},
		{"audience", "aud", []string{"other-client"}},
		{"project", "appthrust.io/project", "project-y"},
		{"installation", "appthrust.io/installation", "other-app"},
		{"uid", "appthrust.io/installation_uid", "recreated-uid"},
		{"credential", "appthrust.io/credential", "key"},
		{"subject_kind", "appthrust.io/subject_kind", "component"},
		{"subject", "sub", "user:other-person"},
		{"subject_issuer", "appthrust.io/subject_issuer", "https://other.example/oidc"},
		{"expired", "exp", int64(1)},
		{"over_long_lifetime", "iat", time.Now().Add(-6 * time.Minute).Unix()},
		{"missing_iat", "iat", nil},
		{"future_iat", "iat", time.Now().Add(time.Hour).Unix()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAppAccessFixture(t)
			f.mutate = func(claims map[string]any) { claims[tc.field] = tc.value }
			a := f.auth(t, nil)
			for range 2 {
				requireAppError(t, serveAppRequest(a, f.bearer(t, "person", "expense-client"), false), 503, "access_unavailable")
			}
			require.EqualValues(t, 2, f.calls.Load(), "verification failure must not be cached")
		})
	}
	t.Run("bad_signature", func(t *testing.T) {
		f := newAppAccessFixture(t)
		var err error
		f.assertionKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		requireAppError(t, serveAppRequest(f.auth(t, nil), f.bearer(t, "person", "expense-client"), false), 503, "access_unavailable")
	})
}

// Both Projects install the same app. A Project-X assertion must not grant a
// Project-Y app any permission, even if the unsigned response metadata names Y.
func TestAppAccessRejectsProjectXAssertionInProjectY(t *testing.T) {
	f := newAppAccessFixture(t)
	f.response = func(wire map[string]any) { wire["project"] = "project-y" }
	a := f.auth(t, func(c *AppAccessConfig) { c.Project = "project-y" })
	requireAppError(t, serveAppRequest(a, f.bearer(t, "person", "expense-client"), false), 503, "access_unavailable")
}

func TestAppAccessAudienceContainsAZPAndOptionalUID(t *testing.T) {
	f := newAppAccessFixture(t)
	f.mutate = func(claims map[string]any) {
		claims["aud"] = []string{"other", "expense-client"}
		claims["appthrust.io/installation_uid"] = "other-uid"
	}
	a := f.auth(t, func(c *AppAccessConfig) { c.InstallationUID = "" })
	value, _, err := a.Authenticate(t.Context(), f.bearer(t, "person", "expense-client"))
	require.NoError(t, err)
	require.True(t, value.Principal.Has("reports:approve"))
}

func TestAppAccessSessionNetworkBearerRejectedAndKeysStillAccepted(t *testing.T) {
	f := newAppAccessFixture(t)
	a := f.auth(t, nil)
	claims := accesskey.Claims{Issuer: f.server.URL + "/access", Subject: accesskey.Subject{Kind: accesskey.SubjectUser, ID: "person"},
		Audience: "expense-key", Project: "project-x", Scopes: []string{"reports:approve"}, KeyName: "key-name", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	keyBearer := "Bearer " + signAppToken(t, f.key, accesskey.AssertionType, claims)
	value, _, err := a.Authenticate(t.Context(), keyBearer)
	require.NoError(t, err)
	require.Equal(t, "key", value.Principal.Kind)
	require.True(t, value.Principal.Has("reports:approve"))
	require.Equal(t, http.StatusNoContent, serveAppRequest(a, keyBearer, true).Code)
	for _, audience := range []string{"expense-key", "expense-client", "platform-api"} {
		for _, issuer := range []string{f.server.URL + "/access", f.issuer()} {
			token := signAppToken(t, f.key, accesskey.AssertionType, map[string]any{
				"iss": issuer, "aud": []string{audience}, "sub": "user:person", "exp": time.Now().Add(time.Minute).Unix(),
				"appthrust.io/credential": "session", "appthrust.io/subject_kind": "user", "email": "person@example.test",
			})
			requireAppError(t, serveAppRequest(a, "Bearer "+token, false), 401, "unauthenticated")
		}
	}
	require.EqualValues(t, 0, f.calls.Load(), "neither key nor internal assertion may be exchanged")
}

func TestAppAccessFailureSemantics(t *testing.T) {
	for _, status := range []int{401, 403, 404, 409, 429, 500, 503, 302} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := newAppAccessFixture(t)
			f.status.Store(int32(status))
			a := f.auth(t, nil)
			for range 2 {
				w := serveAppRequest(a, f.bearer(t, "person", "expense-client"), false)
				if status == 401 {
					requireAppError(t, w, 401, "unauthenticated")
				} else {
					requireAppError(t, w, 503, "access_unavailable")
				}
				if status == 429 {
					require.Equal(t, "7", w.Header().Get("Retry-After"))
				}
			}
			require.EqualValues(t, 2, f.calls.Load())
		})
	}
	t.Run("transport", func(t *testing.T) {
		f := newAppAccessFixture(t)
		a := f.auth(t, nil)
		a.appAccess.http.Transport = failingAccessTransport{}
		requireAppError(t, serveAppRequest(a, f.bearer(t, "person", "expense-client"), false), 503, "access_unavailable")
	})
	for _, field := range []string{"token", "access", "expiresAt", "project", "installation", "installationUID", "audience"} {
		t.Run("missing_"+field, func(t *testing.T) {
			f := newAppAccessFixture(t)
			f.response = func(wire map[string]any) { delete(wire, field) }
			requireAppError(t, serveAppRequest(f.auth(t, nil), f.bearer(t, "person", "expense-client"), false), 503, "access_unavailable")
		})
	}
}

type failingAccessTransport struct{}

func (failingAccessTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport offline")
}

func TestAppAccessRequiresVerifiedBearerWithAZP(t *testing.T) {
	f := newAppAccessFixture(t)
	a := f.auth(t, nil)
	requireAppError(t, serveAppRequest(a, f.bearer(t, "person", ""), false), 401, "unauthenticated")
	bearer := "Bearer " + unsigned(map[string]any{"iss": f.issuer(), "aud": "platform-api", "azp": "expense-client", "sub": "person", "email": "person@example.test"})
	requireAppError(t, serveAppRequest(a, bearer, false), 401, "unauthenticated")
	require.EqualValues(t, 0, f.calls.Load())
}

func TestAppAccessCacheHitExpiryAndNoStaleFallback(t *testing.T) {
	f := newAppAccessFixture(t)
	a := f.auth(t, nil)
	bearer := f.bearer(t, "person", "expense-client")
	value, _, err := a.Authenticate(t.Context(), bearer)
	require.NoError(t, err)
	value.Principal.Scopes[0] = "poison"
	value.Access.Declared = false
	f.now.Add(54)
	value, _, err = a.Authenticate(t.Context(), bearer)
	require.NoError(t, err)
	require.True(t, value.Principal.Has("reports:read"))
	require.True(t, value.Access.Declared)
	require.EqualValues(t, 1, f.calls.Load())
	f.now.Add(1) // exp minus the five-second skew expires at this exact boundary.
	f.scope.Store("reports:read")
	value, _, err = a.Authenticate(t.Context(), bearer)
	require.NoError(t, err)
	require.False(t, value.Principal.Has("reports:approve"))
	require.EqualValues(t, 2, f.calls.Load())
	f.now.Add(55)
	f.status.Store(503)
	for range 2 {
		requireAppError(t, serveAppRequest(a, bearer, false), 503, "access_unavailable")
	}
	require.EqualValues(t, 4, f.calls.Load())
}

func TestAppAccessCacheLifetimeWithClockOffset(t *testing.T) {
	for _, tc := range []struct {
		name      string
		issuerLag time.Duration
		ttl       time.Duration
		cacheTTL  time.Duration
	}{
		{"app clock 25 seconds behind", -25 * time.Second, time.Minute, 55 * time.Second},
		{"app clock 20 seconds ahead", 20 * time.Second, time.Minute, 35 * time.Second},
		{"zero computed lifetime", 0, 5 * time.Second, 0},
		{"negative computed lifetime", 0, 4 * time.Second, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAppAccessFixture(t)
			f.mutate = func(claims map[string]any) {
				issued := f.clock().Add(-tc.issuerLag)
				claims["iat"] = issued.Unix()
				claims["exp"] = issued.Add(tc.ttl).Unix()
			}
			f.response = func(wire map[string]any) {
				wire["expiresAt"] = f.clock().Add(-tc.issuerLag).Add(tc.ttl)
			}
			a := f.auth(t, nil)
			bearer := f.bearer(t, "person", "expense-client")
			_, _, err := a.Authenticate(t.Context(), bearer)
			require.NoError(t, err)
			require.EqualValues(t, 1, f.calls.Load())
			if tc.cacheTTL > 0 {
				f.now.Add(int64((tc.cacheTTL - time.Second) / time.Second))
				_, _, err = a.Authenticate(t.Context(), bearer)
				require.NoError(t, err)
				require.EqualValues(t, 1, f.calls.Load(), "entry should remain cached until its deadline")
				f.now.Add(1)
			}
			_, _, err = a.Authenticate(t.Context(), bearer)
			require.NoError(t, err)
			require.EqualValues(t, 2, f.calls.Load(), "expired or non-positive lifetime must cause another exchange")
		})
	}
}

func TestAppAccessCacheSeparatesSubjectsAndClientsAndIsBounded(t *testing.T) {
	f := newAppAccessFixture(t)
	a := f.auth(t, func(c *AppAccessConfig) { c.CacheSize = 2 })
	for _, user := range []struct{ sub, azp string }{{"person", "client-a"}, {"person", "client-b"}, {"other", "client-a"}, {"third", "client-a"}} {
		f.now.Add(1)
		_, _, err := a.Authenticate(t.Context(), f.bearer(t, user.sub, user.azp))
		require.NoError(t, err)
	}
	require.EqualValues(t, 4, f.calls.Load())
	_, _, err := a.Authenticate(t.Context(), f.bearer(t, "person", "client-a"))
	require.NoError(t, err)
	require.EqualValues(t, 5, f.calls.Load(), "oldest subject was evicted")
	a.appAccess.mu.Lock()
	require.LessOrEqual(t, len(a.appAccess.cache), 2)
	a.appAccess.mu.Unlock()
}

func TestAppAccessCacheSeparatesIssuers(t *testing.T) {
	f := newAppAccessFixture(t)
	a := f.auth(t, nil)
	// Exercise the exchange client's cache with already-verified identities. The
	// Authenticator separately rejects issuers outside its OIDC trust configuration.
	for _, issuer := range []string{f.issuer(), "https://second.example/oidc"} {
		bearer := "Bearer " + signAppToken(t, f.key, "JWT", map[string]any{"iss": issuer, "sub": "person", "azp": "expense-client"})
		result, err := a.appAccess.resolve(t.Context(), appAccessKey{issuer: issuer, subject: "person", audience: "expense-client"}, bearer)
		require.NoError(t, err)
		require.NotEmpty(t, result.scopes)
	}
	require.EqualValues(t, 2, f.calls.Load())
}

func TestAppAccessConcurrentExchangesSingleFlight(t *testing.T) {
	f := newAppAccessFixture(t)
	f.started, f.release = make(chan struct{}, 20), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(f.release) })
	a := f.auth(t, nil)
	bearer := f.bearer(t, "person", "expense-client")
	const callers = 12
	results := make(chan error, callers)
	start := make(chan struct{})
	for range callers {
		go func() { <-start; _, _, err := a.Authenticate(t.Context(), bearer); results <- err }()
	}
	close(start)
	select {
	case <-f.started:
	case <-time.After(5 * time.Second):
		t.Fatal("exchange never started")
	}
	// A cancelled waiter cannot cancel the leader or cause a second exchange.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, _, err := a.Authenticate(ctx, bearer)
	require.Error(t, err)
	releaseOnce.Do(func() { close(f.release) })
	for range callers {
		require.NoError(t, <-results)
	}
	require.EqualValues(t, 1, f.calls.Load())
}

func TestAppAccessMiddlewareDeclaredAndUndeclared(t *testing.T) {
	for _, defaultGuard := range []bool{false, true} {
		for _, tc := range []struct {
			name               string
			declared, accepted bool
			scope              string
			status             int
		}{
			{"declared-empty", true, true, "", 403},
			{"pending-acceptance", true, false, "", 403},
			{"undeclared", false, false, "", 204},
			{"permission", true, true, "reports:read", 204},
		} {
			t.Run(tc.name+"/default="+strconv.FormatBool(defaultGuard), func(t *testing.T) {
				f := newAppAccessFixture(t)
				f.declared.Store(tc.declared)
				f.accepted.Store(tc.accepted)
				f.scope.Store(tc.scope)
				a := f.auth(t, func(c *AppAccessConfig) { c.RequirePermissions = defaultGuard })
				w := serveAppRequest(a, f.bearer(t, "person", "expense-client"), !defaultGuard)
				if tc.status == 403 {
					requireAppError(t, w, 403, "forbidden")
				} else {
					require.Equal(t, tc.status, w.Code)
				}
			})
		}
	}
}

func TestAppAccessMiddlewareRequiresExchangeAndContext(t *testing.T) {
	a, err := New(Trust{})
	require.NoError(t, err)
	requireAppError(t, serveAppRequest(a, "Bearer "+unsigned(map[string]any{"sub": "person", "email": "person@example.test"}), true), 503, "access_unavailable")
	w := httptest.NewRecorder()
	RequireAppAccess(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unguarded handler invoked") })).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	requireAppError(t, w, 401, "unauthenticated")
}

func TestAppAccessConfigurationAndEnvironment(t *testing.T) {
	f := newAppAccessFixture(t)
	for _, field := range []string{"origin", "project", "installation", "oidc", "access", "cache"} {
		t.Run(field, func(t *testing.T) {
			config := f.config()
			trust := Trust{OIDCIssuer: f.issuer(), OIDCAudiences: []string{"platform-api"}, AccessIssuer: f.server.URL + "/access", AppAccess: &config}
			switch field {
			case "origin":
				config.PlatformOrigin = ""
			case "project":
				config.Project = ""
			case "installation":
				config.Installation = ""
			case "oidc":
				trust.OIDCIssuer = ""
			case "access":
				trust.AccessIssuer = ""
			case "cache":
				config.CacheSize = -1
			}
			a, err := New(trust)
			require.Error(t, err)
			require.Nil(t, a)
		})
	}
	t.Setenv("PLATFORM_API_URL", f.server.URL)
	t.Setenv("PLATFORM_PROJECT_ID", "project-x")
	t.Setenv("PLATFORM_APP_INSTALLATION_NAME", "")
	t.Setenv("PLATFORM_APP_INSTALLATION_UID", "")
	config := AppAccessFromEnv("expense")
	require.Equal(t, "expense", config.Installation)
	require.Equal(t, "project-x", config.Project)
	require.Equal(t, f.server.URL, config.PlatformOrigin)
	t.Setenv("PLATFORM_APP_INSTALLATION_NAME", "custom")
	t.Setenv("PLATFORM_APP_INSTALLATION_UID", "custom-uid")
	config = AppAccessFromEnv("expense")
	require.Equal(t, "custom", config.Installation)
	require.Equal(t, "custom-uid", config.InstallationUID)
	// Role-only apps need no key audience and never enable network key assertions.
	config = f.config()
	a, err := New(Trust{OIDCIssuer: f.issuer(), OIDCAudiences: []string{"platform-api"}, AccessIssuer: f.server.URL + "/access", AppAccess: &config})
	require.NoError(t, err)
	value, _, err := a.Authenticate(t.Context(), f.bearer(t, "person", "expense-client"))
	require.NoError(t, err)
	require.True(t, value.Principal.Has("reports:approve"))
}

func TestAppAccessConfigRequiresExactlyOneTarget(t *testing.T) {
	f := newAppAccessFixture(t)
	for _, tc := range []struct {
		name, application, installation string
		reject                          bool
	}{
		{name: "application", application: "expense"},
		{name: "installation", installation: "expense"},
		{name: "both", application: "expense", installation: "expense", reject: true},
		{name: "neither", reject: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := f.config()
			config.Application, config.Installation, config.InstallationUID = tc.application, tc.installation, ""
			a, err := New(Trust{
				OIDCIssuer: f.issuer(), OIDCAudiences: []string{"platform-api"},
				AccessIssuer: f.server.URL + "/access", AppAccess: &config,
			})
			if tc.reject {
				require.EqualError(t, err, "app access requires exactly one of installation or application")
				require.Nil(t, a)
			} else {
				require.NoError(t, err)
				require.NotNil(t, a)
			}
		})
	}
}

func TestAppAccessMiddlewareExposesVerifiedIdentity(t *testing.T) {
	f := newAppAccessFixture(t)
	a := f.auth(t, nil)
	called := false
	handler := a.Middleware(RequireAppAccess(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		value, ok := FromContext(r.Context())
		require.True(t, ok)
		require.True(t, value.Principal.Has("reports:approve"))
		require.Equal(t, "user", value.Principal.Kind)
		w.WriteHeader(http.StatusNoContent)
	})))
	req := httptest.NewRequest(http.MethodGet, "/reports", nil)
	req.Header.Set("Authorization", f.bearer(t, "person", "expense-client"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)
	require.True(t, called)
}
