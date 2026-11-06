package identity

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/appthrust/appserver-go/appserver/pgstore/testutil"
)

func TestPrivateCAForDiscoveryAndJWKS(t *testing.T) {
	issuer := testutil.NewOIDCIssuer(t)
	bearer := issuer.Bearer(t)
	withoutCA, err := New(Trust{OIDCIssuer: issuer.Server.URL, OIDCAudiences: []string{"appthrust-platform-api"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := withoutCA.Authenticate(t.Context(), bearer); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("untrusted issuer: %v", err)
	}
	if issuer.Discovery.Load() != 0 || issuer.JWKS.Load() != 0 {
		t.Fatal("untrusted issuer passed TLS verification")
	}
	trusted, err := New(Trust{OIDCIssuer: issuer.Server.URL, OIDCCAPEM: issuer.CAPEM, OIDCAudiences: []string{"appthrust-platform-api"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(trusted.http.CloseIdleConnections)
	for range 2 {
		ctx, cancel := context.WithCancel(t.Context())
		claims, gotBearer, err := trusted.Authenticate(ctx, bearer)
		cancel()
		if err != nil || claims.Principal.Subject != "subject" || gotBearer != bearer {
			t.Fatalf("trusted token: claims=%+v bearer=%q err=%v", claims, gotBearer, err)
		}
	}
	if issuer.Discovery.Load() != 1 || issuer.JWKS.Load() != 1 {
		t.Fatalf("discovery/JWKS not cached: %d/%d", issuer.Discovery.Load(), issuer.JWKS.Load())
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	if !roots.AppendCertsFromPEM([]byte(issuer.CAPEM)) {
		t.Fatal("test CA is invalid")
	}
	transport := trusted.http.Transport.(*http.Transport)
	if !roots.Equal(transport.TLSClientConfig.RootCAs) {
		t.Fatal("custom CA replaced system trust roots")
	}
	if trusted.http.Timeout != 10*time.Second || withoutCA.http.Timeout != 10*time.Second {
		t.Fatal("discovery and JWKS requests must have a bounded timeout")
	}
}

func TestInvalidCAPEMFailsConstruction(t *testing.T) {
	issuer := testutil.NewOIDCIssuer(t)
	malformed := "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n"
	for name, caPEM := range map[string]string{
		"text":              "invalid PEM",
		"whitespace":        " \n",
		"malformed":         malformed,
		"invalid DER":       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})),
		"non-certificate":   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a certificate")})),
		"valid then broken": issuer.CAPEM + malformed,
		"broken then valid": malformed + issuer.CAPEM,
		"trailing text":     issuer.CAPEM + "invalid PEM",
	} {
		t.Run(name, func(t *testing.T) {
			for _, issuerURL := range []string{"", issuer.Server.URL} {
				if auth, err := New(Trust{OIDCIssuer: issuerURL, OIDCCAPEM: caPEM, OIDCAudiences: []string{"appthrust-platform-api"}}); err == nil || auth != nil || !strings.Contains(err.Error(), "OIDC CA PEM") {
					t.Fatalf("invalid CA accepted: auth=%v err=%v", auth, err)
				}
			}
		})
	}
	if issuer.Discovery.Load() != 0 {
		t.Fatal("constructor contacted issuer")
	}
	bundle, err := New(Trust{OIDCIssuer: issuer.Server.URL, OIDCCAPEM: "\n" + issuer.CAPEM + issuer.CAPEM + "\n", OIDCAudiences: []string{"appthrust-platform-api"}})
	if err != nil {
		t.Fatalf("valid PEM bundle rejected: %v", err)
	}
	t.Cleanup(bundle.http.CloseIdleConnections)
}

func TestLazyDiscoveryBackoffAndRecovery(t *testing.T) {
	issuer := testutil.NewOIDCIssuer(t)
	issuer.Available.Store(false)
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	auth, err := New(Trust{OIDCIssuer: issuer.Server.URL, OIDCCAPEM: issuer.CAPEM, OIDCAudiences: []string{"appthrust-platform-api"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(auth.http.CloseIdleConnections)
	if issuer.Discovery.Load() != 0 {
		t.Fatal("constructor contacted unavailable issuer")
	}
	bearer := issuer.Bearer(t)
	started := time.Now()
	if _, _, err := auth.Authenticate(t.Context(), bearer); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unavailable issuer: %v", err)
	}
	finished := time.Now()
	if auth.retryAt.Before(started.Add(5*time.Second)) || auth.retryAt.After(finished.Add(5*time.Second)) {
		t.Fatalf("retry deadline %s is not five seconds after failure", auth.retryAt)
	}
	for range 10 {
		if _, _, err := auth.Authenticate(t.Context(), bearer); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("backoff: %v", err)
		}
	}
	if issuer.Discovery.Load() != 1 || strings.Count(logs.String(), "console identity discovery failed") != 1 {
		t.Fatalf("discovery/logging repeated during backoff: calls=%d logs=%s", issuer.Discovery.Load(), logs.String())
	}
	// Expire only the retry deadline, as the platform access-cache tests do.
	auth.mu.Lock()
	auth.retryAt = time.Now().Add(-time.Second)
	auth.mu.Unlock()
	if _, _, err := auth.Authenticate(t.Context(), bearer); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("second unavailable window: %v", err)
	}
	if issuer.Discovery.Load() != 2 || strings.Count(logs.String(), "console identity discovery failed") != 2 {
		t.Fatalf("failure window did not log once: calls=%d logs=%s", issuer.Discovery.Load(), logs.String())
	}
	issuer.Available.Store(true)
	if _, _, err := auth.Authenticate(t.Context(), bearer); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("issuer recovery bypassed backoff: %v", err)
	}
	auth.mu.Lock()
	auth.retryAt = time.Now().Add(-time.Second)
	auth.mu.Unlock()
	claims, _, err := auth.Authenticate(t.Context(), bearer)
	if err != nil || claims.Principal.Subject != "subject" {
		t.Fatalf("recovery failed: claims=%+v err=%v", claims, err)
	}
	if issuer.Discovery.Load() != 3 || issuer.JWKS.Load() != 1 {
		t.Fatalf("recovery discovery/JWKS calls=%d/%d", issuer.Discovery.Load(), issuer.JWKS.Load())
	}
	if _, _, err := auth.Authenticate(t.Context(), "Bearer "+unsigned(map[string]string{"sub": "subject", "email": "user@example.test"})); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("recovery must verify signatures, not fall back to unverified claims: %v", err)
	}
}

// A concurrent caller waits for the in-flight discovery and shares its
// outcome: the issuer is contacted once, and a failed attempt makes every
// waiter Unavailable together with the leader.
func TestConcurrentDiscoveryWaitsForLeaderAndSharesFailure(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer issuer.Close()
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) }) // a failed assertion must not leave the issuer handler blocked
	auth, err := New(Trust{OIDCIssuer: issuer.URL, OIDCAudiences: []string{"appthrust-platform-api"}})
	if err != nil {
		t.Fatal(err)
	}
	bearer := "Bearer " + unsigned(map[string]any{"iss": issuer.URL, "aud": "appthrust-platform-api"})
	result := make(chan error, 1)
	go func() {
		_, _, err := auth.Authenticate(t.Context(), bearer)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery did not start")
	}
	concurrent := make(chan error, 1)
	go func() {
		_, _, err := auth.Authenticate(t.Context(), bearer)
		concurrent <- err
	}()
	select {
	case err := <-concurrent:
		t.Fatalf("concurrent request did not wait for the in-flight discovery: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-result; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("discovery failure: %v", err)
	}
	if err := <-concurrent; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("concurrent request after failed discovery: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("issuer contacted %d times during one in-flight discovery, want 1", calls.Load())
	}
}
