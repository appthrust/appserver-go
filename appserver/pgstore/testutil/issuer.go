package testutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// OIDCIssuer serves discovery and JWKS over TLS signed by an isolated test CA.
type OIDCIssuer struct {
	Server    *httptest.Server
	CAPEM     string
	Available atomic.Bool
	Discovery atomic.Int32
	JWKS      atomic.Int32
	key       *rsa.PrivateKey
}

func NewOIDCIssuer(t *testing.T) *OIDCIssuer {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &OIDCIssuer{CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), key: key}
	issuer.Available.Store(true)
	issuer.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			issuer.Discovery.Add(1)
			if !issuer.Available.Load() {
				http.Error(w, "identity offline", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": issuer.Server.URL, "jwks_uri": issuer.Server.URL + "/keys",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			issuer.JWKS.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{
				"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	issuer.Server.Config.ErrorLog = log.New(io.Discard, "", 0)
	issuer.Server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	issuer.Server.StartTLS()
	t.Cleanup(issuer.Server.Close)
	return issuer
}

func (i *OIDCIssuer) Bearer(t *testing.T) string {
	t.Helper()
	claims, err := json.Marshal(map[string]any{
		"iss": i.Server.URL, "sub": "subject", "email": "user@example.test", "name": "Verified",
		"aud": []string{"appthrust-platform-api"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test-key"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
	hash := sha256.Sum256([]byte(body))
	signature, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	return "Bearer " + body + "." + base64.RawURLEncoding.EncodeToString(signature)
}
