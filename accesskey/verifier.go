package accesskey

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

var (
	ErrInvalidAssertion = errors.New("accesskey: invalid assertion")
	// ErrExpiredAssertion also matches ErrInvalidAssertion through errors.Is.
	ErrExpiredAssertion = fmt.Errorf("%w: expired", ErrInvalidAssertion)
)

const assertionLeeway = 30 * time.Second

type Verifier struct {
	issuer string
	src    JWKSSource
	now    func() time.Time
}

func NewVerifier(issuer string, src JWKSSource) *Verifier {
	return &Verifier{issuer: issuer, src: src, now: time.Now}
}

// Verify accepts only compact ES256 assertions from the configured issuer, with
// a signed typ and kid, the requested audience, and an unexpired exp (30s leeway).
// An unknown kid triggers one additional source lookup; HTTP sources rate-limit
// that forced refresh independently of their normal cache TTL.
func (v *Verifier) Verify(ctx context.Context, raw, audience string) (Claims, error) {
	payload, err := v.verifyPayload(ctx, raw)
	if err != nil {
		return Claims{}, err
	}
	var credential struct {
		Kind string `json:"appthrust.io/credential"`
	}
	if json.Unmarshal(payload, &credential) != nil || credential.Kind == "session" {
		return Claims{}, fmt.Errorf("%w: session assertions are internal", ErrInvalidAssertion)
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, fmt.Errorf("%w: claims", ErrInvalidAssertion)
	}
	if claims.Issuer == "" || claims.Issuer != v.issuer {
		return Claims{}, fmt.Errorf("%w: issuer", ErrInvalidAssertion)
	}
	if audience == "" || claims.Audience != audience {
		return Claims{}, fmt.Errorf("%w: audience", ErrInvalidAssertion)
	}
	if !v.now().Before(claims.ExpiresAt.Add(assertionLeeway)) {
		return Claims{}, ErrExpiredAssertion
	}
	return claims, nil
}

// verifyPayload shares signature, algorithm, protected-header and JWKS checks
// between network key assertions and SDK-internal session assertions.
func (v *Verifier) verifyPayload(ctx context.Context, raw string) ([]byte, error) {
	token, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(token.Signatures) != 1 {
		return nil, fmt.Errorf("%w: encoding or algorithm", ErrInvalidAssertion)
	}
	header := token.Signatures[0].Protected
	if header.ExtraHeaders[jose.HeaderType] != AssertionType || header.KeyID == "" {
		return nil, fmt.Errorf("%w: typ or kid", ErrInvalidAssertion)
	}
	if v.src == nil {
		return nil, fmt.Errorf("%w: missing JWKS source", ErrInvalidAssertion)
	}
	set, err := v.src.Keys(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: JWKS: %w", ErrInvalidAssertion, err)
	}
	if !hasKeyID(set, header.KeyID) {
		if source, ok := v.src.(interface {
			refresh(context.Context) (jose.JSONWebKeySet, error)
		}); ok {
			set, err = source.refresh(ctx)
		} else {
			set, err = v.src.Keys(ctx)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: JWKS refresh: %w", ErrInvalidAssertion, err)
		}
	}
	for _, key := range set.Keys {
		if key.KeyID != header.KeyID || key.Algorithm != "" && key.Algorithm != string(jose.ES256) || key.Use != "" && key.Use != "sig" {
			continue
		}
		public, ok := key.Key.(*ecdsa.PublicKey)
		if !ok || public == nil || public.Curve != elliptic.P256() {
			continue
		}
		payload, err := token.Verify(public)
		if err != nil {
			continue
		}
		return payload, nil
	}
	return nil, fmt.Errorf("%w: unknown kid or signature", ErrInvalidAssertion)
}

func hasKeyID(set jose.JSONWebKeySet, kid string) bool {
	for _, key := range set.Keys {
		if key.KeyID == kid {
			return true
		}
	}
	return false
}
