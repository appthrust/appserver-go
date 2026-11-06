package accesskey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

type Signer interface {
	Sign(Claims) (string, error)
	JWKS() jose.JSONWebKeySet
}

type es256Signer struct {
	signer jose.Signer
	set    jose.JSONWebKeySet
	err    error
}

// NewES256Signer publishes the current public key first, followed by retired
// public keys. Private retired keys are converted to public keys; symmetric
// keys are omitted. Configuration errors are returned by Sign.
func NewES256Signer(kid string, key *ecdsa.PrivateKey, retired ...jose.JSONWebKey) Signer {
	s := &es256Signer{}
	if kid == "" || !isP256Key(key) {
		s.err = errors.New("accesskey: signer requires a kid and P-256 private key")
		return s
	}
	current := jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}
	s.set.Keys = make([]jose.JSONWebKey, 0, 1+len(retired))
	s.set.Keys = append(s.set.Keys, current)
	for _, key := range retired {
		public := key.Public()
		if public.IsPublic() {
			s.set.Keys = append(s.set.Keys, public)
		}
	}
	s.signer, s.err = jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType(AssertionType).WithHeader("kid", kid))
	return s
}

func (s *es256Signer) Sign(claims Claims) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if claims.ExpiresAt.Sub(claims.IssuedAt) > MaxAssertionTTL {
		return "", errors.New("accesskey: assertion TTL exceeds five minutes")
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("accesskey: encode assertion: %w", err)
	}
	signed, err := s.signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("accesskey: sign assertion: %w", err)
	}
	return signed.CompactSerialize()
}

// JWKS returns public keys only. Callers must treat the returned set as read-only.
func (s *es256Signer) JWKS() jose.JSONWebKeySet { return s.set }

func GenerateES256Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// MarshalPKCS8 encodes a P-256 private key as a PEM PRIVATE KEY block for Secret
// storage. It never includes credential material in errors.
func MarshalPKCS8(key *ecdsa.PrivateKey) ([]byte, error) {
	if !isP256Key(key) {
		return nil, errors.New("accesskey: PKCS8 requires a P-256 private key")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("accesskey: marshal PKCS8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePKCS8 decodes one PEM PKCS#8 P-256 private key.
func ParsePKCS8(data []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("accesskey: invalid PKCS8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("accesskey: parse PKCS8: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !isP256Key(key) {
		return nil, errors.New("accesskey: PKCS8 requires a P-256 private key")
	}
	return key, nil
}

func isP256Key(key *ecdsa.PrivateKey) bool {
	return key != nil && key.Curve == elliptic.P256() && key.D != nil && key.X != nil && key.Y != nil
}
