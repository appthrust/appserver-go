package accesskey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func mustES256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := GenerateES256Key()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestPKCS8(t *testing.T) {
	key := mustES256Key(t)
	encoded, err := MarshalPKCS8(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(encoded, []byte("-----BEGIN PRIVATE KEY-----\n")) {
		t.Fatal("PKCS8 storage must be PEM")
	}
	parsed, err := ParsePKCS8(encoded)
	if err != nil || !key.Equal(parsed) {
		t.Fatalf("PKCS8 round trip failed: %v", err)
	}
	wrongCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(wrongCurve)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"malformed", []byte("not PEM")},
		{"DER instead of PEM", der},
		{"wrong curve", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})},
		{"wrong label", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})},
		{"bad DER", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")})},
		{"multiple keys", append(bytes.Clone(encoded), encoded...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePKCS8(tc.data); err == nil {
				t.Fatal("invalid key storage was accepted")
			}
		})
	}
	for _, key := range []*ecdsa.PrivateKey{nil, wrongCurve} {
		if _, err := MarshalPKCS8(key); err == nil {
			t.Fatal("invalid private key was marshaled")
		}
	}
}

func TestSignerPublishesOnlyPublicKeys(t *testing.T) {
	current, retired := mustES256Key(t), mustES256Key(t)
	signer := NewES256Signer("current", current,
		jose.JSONWebKey{Key: retired, KeyID: "retired", Use: "sig", Algorithm: "ES256"},
		jose.JSONWebKey{Key: bytes.Repeat([]byte("x"), 32), KeyID: "symmetric"})
	set := signer.JWKS()
	if len(set.Keys) != 2 || set.Keys[0].KeyID != "current" || set.Keys[1].KeyID != "retired" {
		t.Fatal("JWKS must contain current then retired public keys")
	}
	for _, key := range set.Keys {
		if !key.IsPublic() || !key.Valid() {
			t.Fatal("JWKS leaked a private or invalid key")
		}
	}
}

func TestSignerRejectsInvalidConfigurationAndLongTTL(t *testing.T) {
	key := mustES256Key(t)
	for _, signer := range []Signer{NewES256Signer("", key), NewES256Signer("key", nil)} {
		if _, err := signer.Sign(Claims{}); err == nil {
			t.Fatal("invalid signing configuration was accepted")
		}
	}
	now := time.Now()
	if _, err := NewES256Signer("key", key).Sign(Claims{IssuedAt: now, ExpiresAt: now.Add(MaxAssertionTTL + time.Second)}); err == nil {
		t.Fatal("signer must not issue assertions beyond MaxAssertionTTL")
	}
}
