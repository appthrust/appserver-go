package accesskey

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestNewClaims(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	key := testKey()
	key.SpaceRetired = []string{"documents:read"}
	decision := Decide(&key, true, now)
	seen := make(map[string]bool)
	for _, ttl := range []time.Duration{time.Minute, MaxAssertionTTL, time.Hour, 0, -time.Second} {
		t.Run(ttl.String(), func(t *testing.T) {
			claims := NewClaims("https://dashboard.example/access", "pj-owner", decision, now, ttl)
			if claims.Issuer != "https://dashboard.example/access" || claims.Project != "pj-owner" || claims.Subject != key.Subject || claims.KeyName != key.Name || claims.Audience != key.Audience {
				t.Fatal("claims do not bind the decision")
			}
			if !slices.Equal(claims.Scopes, []string{"search"}) || !claims.IssuedAt.Equal(now) || !claims.ExpiresAt.Equal(now.Add(min(ttl, MaxAssertionTTL))) {
				t.Fatal("wrong effective scopes or TTL")
			}
			jti, err := base64.RawURLEncoding.DecodeString(claims.JTI)
			if err != nil || len(jti) != 16 || seen[claims.JTI] {
				t.Fatal("jti must contain 16 fresh random bytes")
			}
			seen[claims.JTI] = true
		})
	}
	if claims := NewClaims("issuer", "project", Decision{Outcome: Revoked, Key: &key}, now, time.Minute); !reflect.DeepEqual(claims, Claims{}) {
		t.Fatal("denied decisions must not produce claims")
	}
}

func TestClaimsJSONAndPrincipal(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	key := testKey()
	claims := NewClaims(IssuerURL("https://dashboard.example///"), key.Project, Decide(&key, true, now), now, time.Minute)
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"iss": "https://dashboard.example/access", "sub": "component:component-id",
		"aud": []any{"knowledge"}, "scope": "documents:read search",
		"appthrust.io/project": "pj-test", "appthrust.io/key": "ak-test",
		"appthrust.io/subject_kind": "component", "jti": claims.JTI,
		"iat": float64(now.Unix()), "exp": float64(now.Add(time.Minute).Unix()),
	}
	if !reflect.DeepEqual(wire, want) {
		t.Fatal("claim JSON names, types, or values differ from the wire contract")
	}
	var decoded Claims
	if err := json.Unmarshal(data, &decoded); err != nil || !reflect.DeepEqual(decoded, claims) {
		t.Fatalf("claims JSON round trip failed: %v", err)
	}
	principal := decoded.Principal()
	if principal.Kind != "key" || principal.Subject != key.Subject.String() || principal.KeyName != key.Name || principal.Project != key.Project || !slices.Equal(principal.Scopes, claims.Scopes) || len(principal.Groups) != 0 {
		t.Fatal("incorrect principal projection")
	}
	if IssuerSuffix != "/access" || JWKSURL(claims.Issuer) != "https://dashboard.example/access/jwks.json" || JWKSURL(claims.Issuer+"/") != JWKSURL(claims.Issuer) {
		t.Fatal("incorrect issuer or JWKS URL derivation")
	}
}
