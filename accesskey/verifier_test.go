package accesskey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func signPayload(t *testing.T, key any, alg jose.SignatureAlgorithm, kid, typ string, claims any) string {
	t.Helper()
	opts := &jose.SignerOptions{}
	if kid != "" {
		opts.WithHeader("kid", kid)
	}
	if typ != "" {
		opts.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSignVerifyRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	key := testKey()
	claims := NewClaims("https://dashboard.example/access", key.Project, Decide(&key, true, now), now, time.Minute)
	signer := NewES256Signer("current", mustES256Key(t))
	raw, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	header := parsed.Signatures[0].Protected
	if header.KeyID != "current" || header.ExtraHeaders[jose.HeaderType] != AssertionType || header.Algorithm != "ES256" {
		t.Fatal("incorrect protected header")
	}
	verifier := NewVerifier(claims.Issuer, NewStaticJWKSSource(signer.JWKS()))
	verifier.now = func() time.Time { return now }
	got, err := verifier.Verify(context.Background(), raw, "knowledge")
	if err != nil || !reflect.DeepEqual(got, claims) {
		t.Fatalf("assertion round trip failed: %v", err)
	}
}

func TestVerifierBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	key := testKey()
	claims := NewClaims("https://dashboard.example/access", key.Project, Decide(&key, true, now), now, time.Minute)
	private := mustES256Key(t)
	set := NewES256Signer("current", private).JWKS()
	for _, tc := range []struct {
		name     string
		audience string
		issuer   string
		kid      string
		typ      string
		alg      jose.SignatureAlgorithm
		key      any
		expiry   time.Time
		want     error
	}{
		{"valid", "knowledge", claims.Issuer, "current", AssertionType, jose.ES256, private, now.Add(time.Minute), nil},
		{"wrong audience", "other", claims.Issuer, "current", AssertionType, jose.ES256, private, now.Add(time.Minute), ErrInvalidAssertion},
		{"empty audience", "", claims.Issuer, "current", AssertionType, jose.ES256, private, now.Add(time.Minute), ErrInvalidAssertion},
		{"wrong issuer", "knowledge", claims.Issuer + "/", "current", AssertionType, jose.ES256, private, now.Add(time.Minute), ErrInvalidAssertion},
		{"expired", "knowledge", claims.Issuer, "current", AssertionType, jose.ES256, private, now.Add(-31 * time.Second), ErrExpiredAssertion},
		{"expiry leeway boundary", "knowledge", claims.Issuer, "current", AssertionType, jose.ES256, private, now.Add(-30 * time.Second), ErrExpiredAssertion},
		{"within expiry leeway", "knowledge", claims.Issuer, "current", AssertionType, jose.ES256, private, now.Add(-29 * time.Second), nil},
		{"wrong typ", "knowledge", claims.Issuer, "current", "JWT", jose.ES256, private, now.Add(time.Minute), ErrInvalidAssertion},
		{"missing typ", "knowledge", claims.Issuer, "current", "", jose.ES256, private, now.Add(time.Minute), ErrInvalidAssertion},
		{"missing kid", "knowledge", claims.Issuer, "", AssertionType, jose.ES256, private, now.Add(time.Minute), ErrInvalidAssertion},
		{"unknown kid", "knowledge", claims.Issuer, "unknown", AssertionType, jose.ES256, private, now.Add(time.Minute), ErrInvalidAssertion},
		{"wrong signature", "knowledge", claims.Issuer, "current", AssertionType, jose.ES256, mustES256Key(t), now.Add(time.Minute), ErrInvalidAssertion},
		{"HS256 confusion", "knowledge", claims.Issuer, "current", AssertionType, jose.HS256, bytes.Repeat([]byte("x"), 32), now.Add(time.Minute), ErrInvalidAssertion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := claims
			payload.ExpiresAt = tc.expiry
			raw := signPayload(t, tc.key, tc.alg, tc.kid, tc.typ, payload)
			verifier := NewVerifier(tc.issuer, NewStaticJWKSSource(set))
			verifier.now = func() time.Time { return now }
			_, err := verifier.Verify(context.Background(), raw, tc.audience)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if tc.want != nil && !errors.Is(err, ErrInvalidAssertion) {
				t.Fatal("all assertion errors, including expiry, must wrap ErrInvalidAssertion")
			}
		})
	}
}

func TestVerifierRejectsMalformedClaims(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	key := testKey()
	claims := NewClaims("https://dashboard.example/access", key.Project, Decide(&key, true, now), now, time.Minute)
	private := mustES256Key(t)
	verifier := NewVerifier(claims.Issuer, NewStaticJWKSSource(NewES256Signer("current", private).JWKS()))
	verifier.now = func() time.Time { return now }
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		field string
		value any
	}{
		{"string audience", "aud", "knowledge"},
		{"multiple audiences", "aud", []string{"knowledge", "other"}},
		{"empty audience", "aud", []string{}},
		{"missing expiry", "exp", nil},
		{"malformed subject", "sub", "unknown:id"},
		{"mismatched subject kind", "appthrust.io/subject_kind", "user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var payload map[string]any
			if err := json.Unmarshal(data, &payload); err != nil {
				t.Fatal(err)
			}
			payload[tc.field] = tc.value
			raw := signPayload(t, private, jose.ES256, "current", AssertionType, payload)
			if _, err := verifier.Verify(context.Background(), raw, "knowledge"); !errors.Is(err, ErrInvalidAssertion) {
				t.Fatalf("invalid claim error = %v", err)
			}
		})
	}
	for _, raw := range []string{"", "not.a.jwt", "{}"} {
		if _, err := verifier.Verify(context.Background(), raw, "knowledge"); !errors.Is(err, ErrInvalidAssertion) {
			t.Fatalf("malformed assertion error = %v", err)
		}
	}
}

type jwksSourceFunc func(context.Context) (jose.JSONWebKeySet, error)

func (f jwksSourceFunc) Keys(ctx context.Context) (jose.JSONWebKeySet, error) { return f(ctx) }

func TestVerifierRefreshesUnknownKidOnce(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	key := testKey()
	claims := NewClaims("https://dashboard.example/access", key.Project, Decide(&key, true, now), now, time.Minute)
	old, current := mustES256Key(t), mustES256Key(t)
	raw, err := NewES256Signer("old", old).Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	currentSet := NewES256Signer("current", current).JWKS()
	rotatedSet := NewES256Signer("current", current, jose.JSONWebKey{Key: old, KeyID: "old"}).JWKS()
	sourceErr := errors.New("JWKS unavailable")
	for _, tc := range []struct {
		name   string
		second jose.JSONWebKeySet
		err    error
		want   error
	}{
		{"rotated retired key", rotatedSet, nil, nil},
		{"still unknown", currentSet, nil, ErrInvalidAssertion},
		{"refresh failed", jose.JSONWebKeySet{}, sourceErr, ErrInvalidAssertion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			src := jwksSourceFunc(func(context.Context) (jose.JSONWebKeySet, error) {
				calls++
				if calls == 1 {
					return currentSet, nil
				}
				return tc.second, tc.err
			})
			verifier := NewVerifier(claims.Issuer, src)
			verifier.now = func() time.Time { return now }
			_, err := verifier.Verify(context.Background(), raw, "knowledge")
			if !errors.Is(err, tc.want) || calls != 2 {
				t.Fatalf("refresh error = %v, source calls = %d", err, calls)
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatal("JWKS failure cause was lost")
			}
		})
	}
	verifier := NewVerifier(claims.Issuer, jwksSourceFunc(func(context.Context) (jose.JSONWebKeySet, error) {
		return jose.JSONWebKeySet{}, sourceErr
	}))
	if _, err := verifier.Verify(context.Background(), raw, "knowledge"); !errors.Is(err, ErrInvalidAssertion) || !errors.Is(err, sourceErr) {
		t.Fatalf("initial source error = %v", err)
	}
}
