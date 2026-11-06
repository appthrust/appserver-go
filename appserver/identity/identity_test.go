package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/appthrust/appserver-go/accesskey"
	"github.com/stretchr/testify/require"
)

func encode(value any) string {
	body, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(body)
}

func unsigned(claims any) string {
	return encode(map[string]string{"alg": "none"}) + "." + encode(claims) + "."
}

func TestHTTPClientSharesTrust(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	auth, err := New(Trust{OIDCIssuer: server.URL, OIDCCAPEM: caPEM, OIDCAudiences: []string{"platform-api"}})
	require.NoError(t, err)
	client := auth.HTTPClient()
	require.Same(t, auth.http, client)
	require.Equal(t, 10*time.Second, client.Timeout)
	t.Cleanup(client.CloseIdleConnections)
	response, err := client.Get(server.URL)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusNoContent, response.StatusCode)
}

func TestHTTPClientDevelopmentMode(t *testing.T) {
	auth, err := New(Trust{})
	require.NoError(t, err)
	client := auth.HTTPClient()
	require.Same(t, auth.http, client)
	require.Nil(t, client.Transport)
	require.Equal(t, 10*time.Second, client.Timeout)

	client = (&Authenticator{}).HTTPClient()
	require.Nil(t, client.Transport)
	require.Equal(t, 10*time.Second, client.Timeout)
}

func TestUnverifiedDevelopmentClaims(t *testing.T) {
	auth, err := New(Trust{})
	if err != nil {
		t.Fatal(err)
	}
	claims, bearer, err := auth.Authenticate(context.Background(), "Bearer "+unsigned(map[string]any{"sub": "subject", "email": "USER@example.test", "preferred_username": "Username", "groups": []string{"engineering"}}))
	if err != nil || claims.Principal.Kind != "user" || claims.Principal.Subject != "subject" || len(claims.Principal.Groups) != 1 || claims.Email != "user@example.test" || claims.Name != "Username" || bearer == "" {
		t.Fatalf("claims=%+v bearer=%q err=%v", claims, bearer, err)
	}
	for _, header := range []string{
		"", "Basic x", "Bearer", "Bearer invalid", "Bearer a.b.c", "Bearer " + unsigned(map[string]string{"email": "a@example.test"}),
		"Bearer " + unsigned(map[string]string{"sub": "subject"}),
		"Bearer " + unsigned(map[string]any{"sub": "s", "email": "a@example.test", "exp": time.Now().Add(-time.Hour).Unix()}),
		"Bearer " + unsigned(map[string]any{"sub": "s", "email": "a@example.test", "nbf": time.Now().Add(time.Hour).Unix()}),
		"Bearer " + unsigned(map[string]any{"sub": "s", "email": "invalid"}),
	} {
		if _, _, err := auth.Authenticate(context.Background(), header); err == nil {
			t.Errorf("accepted invalid token %q", header)
		}
	}
}

func TestOIDCVerificationIssuerSignatureExpiryAndCachedJWKS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	var discovery, jwks atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discovery.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			jwks.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	auth, err := New(Trust{OIDCIssuer: issuer, OIDCAudiences: []string{"other-client", "appthrust-platform-api"}})
	if err != nil {
		t.Fatal(err)
	}
	if discovery.Load() != 0 || jwks.Load() != 0 {
		t.Fatal("constructor contacted the issuer")
	}
	sign := func(claims any, signingKey *rsa.PrivateKey) string {
		t.Helper()
		body := encode(map[string]string{"alg": "RS256", "kid": "test-key"}) + "." + encode(claims)
		hash := sha256.Sum256([]byte(body))
		sig, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, hash[:])
		if err != nil {
			t.Fatal(err)
		}
		return body + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	valid := map[string]any{"iss": issuer, "aud": []string{"account", "appthrust-platform-api"}, "sub": "subject", "email": "user@example.test", "name": "Verified", "groups": []string{"engineering"}, "exp": time.Now().Add(time.Hour).Unix()}
	for range 2 {
		identity, _, err := auth.Authenticate(context.Background(), "Bearer "+sign(valid, key))
		require.NoError(t, err)
		require.Equal(t, accesskey.Principal{Kind: "user", Subject: "subject", Groups: []string{"engineering"}}, identity.Principal)
	}
	if discovery.Load() != 1 || jwks.Load() != 1 {
		t.Fatalf("discovery/JWKS not cached: %d/%d", discovery.Load(), jwks.Load())
	}
	for _, scenario := range []struct {
		name     string
		audience any
		accepted bool
	}{
		{name: "missing audience"},
		{name: "empty audience set", audience: []string{}},
		{name: "unrelated string audience", audience: "wrong-client"},
		{name: "unrelated audience set", audience: []string{"account", "wrong-client"}},
		{name: "required string audience", audience: "appthrust-platform-api", accepted: true},
		{name: "required audience in set", audience: []string{"account", "appthrust-platform-api"}, accepted: true},
		{name: "another configured audience", audience: "other-client", accepted: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			valid["aud"] = scenario.audience
			header := "Bearer " + sign(valid, key)
			got, bearer, err := auth.Authenticate(t.Context(), header)
			if !scenario.accepted {
				require.EqualError(t, err, "untrusted JWT audience")
				require.Equal(t, Identity{}, got)
				require.Empty(t, bearer)
				return
			}
			require.NoError(t, err)
			require.Equal(t, accesskey.Principal{Kind: "user", Subject: "subject", Groups: []string{"engineering"}}, got.Principal)
			require.Equal(t, header, bearer)
		})
	}
	valid["aud"] = "appthrust-platform-api"
	valid["iss"] = issuer + "/wrong"
	if _, _, err := auth.Authenticate(context.Background(), "Bearer "+sign(valid, key)); err == nil {
		t.Fatal("accepted wrong issuer")
	}
	valid["iss"] = issuer
	valid["exp"] = time.Now().Add(-time.Hour).Unix()
	if _, _, err := auth.Authenticate(context.Background(), "Bearer "+sign(valid, key)); err == nil {
		t.Fatal("accepted expired token")
	}
	valid["exp"] = time.Now().Add(time.Hour).Unix()
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.Authenticate(context.Background(), "Bearer "+sign(valid, other)); err == nil {
		t.Fatal("accepted invalid signature")
	}
}

// A fresh Pod discovers the issuer on its first authenticated request, and a
// SPA sends several at once. Every concurrent caller must wait for the single
// in-flight discovery rather than fail with ErrUnavailable.
func TestConcurrentFirstRequestsShareOneDiscovery(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	var discovery atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discovery.Add(1)
			time.Sleep(300 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	auth, err := New(Trust{OIDCIssuer: issuer, OIDCAudiences: []string{"appthrust-platform-api"}})
	if err != nil {
		t.Fatal(err)
	}
	body := encode(map[string]string{"alg": "RS256", "kid": "test-key"}) + "." + encode(map[string]any{"iss": issuer, "aud": "appthrust-platform-api", "sub": "subject", "email": "user@example.test", "exp": time.Now().Add(time.Hour).Unix()})
	hash := sha256.Sum256([]byte(body))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	token := "Bearer " + body + "." + base64.RawURLEncoding.EncodeToString(sig)

	const callers = 8
	errs := make(chan error, callers)
	for range callers {
		go func() {
			_, _, err := auth.Authenticate(context.Background(), token)
			errs <- err
		}()
	}
	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent first request failed: %v", err)
		}
	}
	if discovery.Load() != 1 {
		t.Fatalf("discovery ran %d times, want 1", discovery.Load())
	}

	// A waiter whose own context ends before the leader's discovery completes
	// leaves with ErrUnavailable instead of blocking on the leader.
	fresh, err := New(Trust{OIDCIssuer: issuer, OIDCAudiences: []string{"appthrust-platform-api"}})
	if err != nil {
		t.Fatal(err)
	}
	leader := make(chan error, 1)
	go func() {
		_, _, err := fresh.Authenticate(context.Background(), token)
		leader <- err
	}()
	time.Sleep(50 * time.Millisecond) // leader is inside the 300ms discovery
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := fresh.Authenticate(ctx, token); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cancelled waiter error = %v, want ErrUnavailable", err)
	}
	if err := <-leader; err != nil {
		t.Fatalf("leader failed: %v", err)
	}
}

func TestTrustConfiguration(t *testing.T) {
	for _, audiences := range [][]string{nil, {}, {""}, {" ", ""}} {
		_, err := New(Trust{OIDCIssuer: "https://issuer.example", OIDCAudiences: audiences})
		require.ErrorContains(t, err, "OIDC audiences are required")
	}
	_, err := New(Trust{AccessAudience: "knowledge"})
	require.ErrorContains(t, err, "access issuer is required")
	t.Setenv("PLATFORM_OIDC_ISSUER", "https://oidc.example")
	t.Setenv("PLATFORM_OIDC_ISSUER_CA_PEM", "")
	t.Setenv("KNOWLEDGE_OIDC_AUDIENCES", " first, ,second ")
	t.Setenv("PLATFORM_ACCESS_ISSUER", "https://platform.example/access")
	t.Setenv("KNOWLEDGE_ACCESS_AUDIENCE", "knowledge")
	auth, err := New(FromEnv("KNOWLEDGE"))
	require.NoError(t, err)
	require.Equal(t, []string{"first", "second"}, auth.trust.OIDCAudiences)
	require.NotNil(t, auth.access)
	t.Setenv("KNOWLEDGE_ACCESS_AUDIENCE", "")
	auth, err = New(FromEnv("KNOWLEDGE"))
	require.NoError(t, err)
	require.Nil(t, auth.access)
}

func TestFromEnvSharesPlatformTrustAcrossAppInstallations(t *testing.T) {
	t.Setenv("PLATFORM_OIDC_ISSUER", "https://identity.example/realms/platform")
	t.Setenv("PLATFORM_OIDC_ISSUER_CA_PEM", "shared CA bundle")
	t.Setenv("PLATFORM_ACCESS_ISSUER", "https://platform.example/access")
	for _, prefix := range []string{"BUILDER_CONSOLE", "DIRECTORY", "KNOWLEDGE", "PORTAL", "TOOL_BUILDER"} {
		t.Run(prefix, func(t *testing.T) {
			t.Setenv(prefix+"_OIDC_AUDIENCES", prefix+"-user,platform-api")
			t.Setenv(prefix+"_ACCESS_AUDIENCE", prefix+"-access")
			require.Equal(t, Trust{
				OIDCIssuer:     "https://identity.example/realms/platform",
				OIDCCAPEM:      "shared CA bundle",
				OIDCAudiences:  []string{prefix + "-user", "platform-api"},
				AccessIssuer:   "https://platform.example/access",
				AccessAudience: prefix + "-access",
			}, FromEnv(prefix))
		})
	}
}

func TestAccessAssertionsAndRawKeyRejection(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := accesskey.NewES256Signer("test-key", key)
	var fetches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/access/jwks.json", r.URL.Path)
		fetches.Add(1)
		require.NoError(t, json.NewEncoder(w).Encode(signer.JWKS()))
	}))
	defer server.Close()
	issuer := accesskey.IssuerURL(server.URL)
	trust := Trust{OIDCIssuer: "https://unavailable.example", OIDCAudiences: []string{"user-client"}, AccessIssuer: issuer, AccessAudience: "knowledge"}
	auth, err := New(trust)
	require.NoError(t, err)
	claims := accesskey.Claims{
		Issuer: issuer, Subject: accesskey.Subject{Kind: accesskey.SubjectComponent, ID: "app"},
		Audience: "knowledge", Scopes: []string{"search", "documents:read"}, Project: "pj-test",
		KeyName: "test-key", JTI: "test", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	}
	token, err := signer.Sign(claims)
	require.NoError(t, err)
	for range 2 {
		got, bearer, err := auth.Authenticate(t.Context(), "Bearer "+token)
		require.NoError(t, err)
		require.Equal(t, claims.Principal(), got.Principal)
		require.Empty(t, got.Email)
		require.Equal(t, "Bearer "+token, bearer)
	}
	require.EqualValues(t, 1, fetches.Load())
	claims.Audience = "other"
	wrongAudience, err := signer.Sign(claims)
	require.NoError(t, err)
	_, _, err = auth.Authenticate(t.Context(), "Bearer "+wrongAudience)
	require.ErrorIs(t, err, accesskey.ErrInvalidAssertion)
	secret, err := accesskey.Generate("knowl", rand.Reader)
	require.NoError(t, err)
	_, _, err = auth.Authenticate(t.Context(), "Bearer "+secret.String())
	require.ErrorIs(t, err, ErrRawKeyNotAccepted)
	trust.AccessAudience = ""
	disabled, err := New(trust)
	require.NoError(t, err)
	_, _, err = disabled.Authenticate(t.Context(), "Bearer "+token)
	require.ErrorContains(t, err, "access assertions are not accepted")
}
