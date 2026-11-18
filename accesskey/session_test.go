package accesskey

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestVerifierRejectsSessionAsNetworkKeyAssertion(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key := mustES256Key(t)
	verifier := NewVerifier("https://platform.example/access", NewStaticJWKSSource(NewES256Signer("current", key).JWKS()))
	claims := map[string]any{
		"iss": "https://platform.example/access", "sub": "user:person", "aud": []string{"expense"}, "scope": "reports:approve",
		"appthrust.io/project": "project-x", "appthrust.io/installation": "expense", "appthrust.io/installation_uid": "uid-x",
		"appthrust.io/subject_kind": "user", "appthrust.io/credential": "session", "appthrust.io/subject_issuer": "https://oidc.example",
		"appthrust.io/principal": "u_" + strings.Repeat("A", 43), "appthrust.io/group_grants": []any{},
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	}
	raw := signPayload(t, key, jose.ES256, "current", AssertionType, claims)
	if _, err := verifier.Verify(context.Background(), raw, "expense"); !errors.Is(err, ErrInvalidAssertion) {
		t.Fatalf("session accepted by network verifier: %v", err)
	}
	binding := SessionBinding{Audience: "expense", Subject: "person", SubjectIssuer: "https://oidc.example", Project: "project-x", Installation: "expense", InstallationUID: "uid-x"}
	if _, err := verifier.VerifySession(context.Background(), raw, binding, now); err != nil {
		t.Fatalf("internal verifier rejected matching session: %v", err)
	}
	if _, err := verifier.VerifySession(context.Background(), raw, binding, now.Add(time.Minute)); !errors.Is(err, ErrExpiredAssertion) {
		t.Fatalf("session expiry must have no leeway: %v", err)
	}
	for _, field := range []string{"audience", "subject", "issuer", "project", "installation"} {
		t.Run(field, func(t *testing.T) {
			incomplete := binding
			switch field {
			case "audience":
				incomplete.Audience = ""
			case "subject":
				incomplete.Subject = ""
			case "issuer":
				incomplete.SubjectIssuer = ""
			case "project":
				incomplete.Project = ""
			case "installation":
				incomplete.Installation = ""
			}
			if _, err := verifier.VerifySession(context.Background(), raw, incomplete, now); !errors.Is(err, ErrInvalidAssertion) {
				t.Fatal("incomplete binding accepted")
			}
		})
	}
}

func TestVerifySessionIssuedAtLeeway(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	key := mustES256Key(t)
	verifier := NewVerifier("https://platform.example/access", NewStaticJWKSSource(NewES256Signer("current", key).JWKS()))
	binding := SessionBinding{Audience: "expense", Subject: "person", SubjectIssuer: "https://oidc.example", Project: "project-x", Installation: "expense"}
	for _, tc := range []struct {
		name   string
		ahead  time.Duration
		reject bool
	}{
		{"within leeway", assertionLeeway - time.Second, false},
		{"at leeway", assertionLeeway, false},
		{"beyond leeway", assertionLeeway + time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issued := now.Add(tc.ahead)
			claims := map[string]any{
				"iss": "https://platform.example/access", "sub": "user:person", "aud": []string{"expense"}, "scope": "reports:approve",
				"appthrust.io/project": "project-x", "appthrust.io/installation": "expense",
				"appthrust.io/subject_kind": "user", "appthrust.io/credential": "session", "appthrust.io/subject_issuer": "https://oidc.example",
				"appthrust.io/principal": "u_" + strings.Repeat("A", 43), "appthrust.io/group_grants": []any{},
				"iat": issued.Unix(), "exp": issued.Add(time.Minute).Unix(),
			}
			raw := signPayload(t, key, jose.ES256, "current", AssertionType, claims)
			_, err := verifier.VerifySession(context.Background(), raw, binding, now)
			if tc.reject {
				if !errors.Is(err, ErrInvalidAssertion) {
					t.Fatalf("future issued-at beyond leeway must be rejected: %v", err)
				}
			} else if err != nil {
				t.Fatalf("issued-at within clock leeway must be accepted: %v", err)
			}
		})
	}
}

func TestPrincipalHasExactPermissionForPeopleAndKeys(t *testing.T) {
	for _, kind := range []string{"user", "key"} {
		p := Principal{Kind: kind, Scopes: []string{"reports:approve", "reports:*", ""}, Groups: []string{"reports:delete"}}
		for _, tc := range []struct {
			permission string
			allowed    bool
		}{
			{"reports:approve", true}, {"reports:read", false}, {"reports:delete", false}, {"Reports:approve", false}, {"", false},
		} {
			if p.Has(tc.permission) != tc.allowed {
				t.Errorf("%s permission %q: want %v", kind, tc.permission, tc.allowed)
			}
		}
	}
}

func TestVerifySessionSignedPersonAndGroupGrants(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key := mustES256Key(t)
	verifier := NewVerifier("https://platform.example/access", NewStaticJWKSSource(NewES256Signer("current", key).JWKS()))
	binding := SessionBinding{Audience: "expense", Subject: "person", SubjectIssuer: "https://oidc.example", Project: "project-x", Installation: "expense"}
	principal := "u_" + strings.Repeat("A", 43)
	group := "g_" + strings.Repeat("B", 42) + "A"
	grants := []GroupGrant{{Group: group, Permissions: []string{"reports:read"}}}
	for _, tc := range []struct {
		name, field string
		value       any
		invalid     bool
	}{
		{name: "signed facts"},
		{name: "empty grants", field: "appthrust.io/group_grants", value: []GroupGrant{}},
		{name: "missing principal", field: "appthrust.io/principal", invalid: true},
		{name: "empty principal", field: "appthrust.io/principal", value: "", invalid: true},
		{name: "null principal", field: "appthrust.io/principal", value: json.RawMessage("null"), invalid: true},
		{name: "non-string principal", field: "appthrust.io/principal", value: 7, invalid: true},
		{name: "malformed principal", field: "appthrust.io/principal", value: "u_person", invalid: true},
		{name: "key principal", field: "appthrust.io/principal", value: "k_" + strings.Repeat("A", 43), invalid: true},
		{name: "missing grants", field: "appthrust.io/group_grants", invalid: true},
		{name: "null grants", field: "appthrust.io/group_grants", value: json.RawMessage("null"), invalid: true},
		{name: "object grants", field: "appthrust.io/group_grants", value: map[string]any{}, invalid: true},
		{name: "null grant", field: "appthrust.io/group_grants", value: []any{nil}, invalid: true},
		{name: "malformed group", field: "appthrust.io/group_grants", value: []GroupGrant{{Group: "g_team", Permissions: []string{}}}, invalid: true},
		{name: "missing permissions", field: "appthrust.io/group_grants", value: []any{map[string]any{"group": group}}, invalid: true},
		{name: "null permissions", field: "appthrust.io/group_grants", value: []GroupGrant{{Group: group}}, invalid: true},
		{name: "non-string permission", field: "appthrust.io/group_grants", value: []any{map[string]any{"group": group, "permissions": []any{7}}}, invalid: true},
		{name: "empty permission", field: "appthrust.io/group_grants", value: []GroupGrant{{Group: group, Permissions: []string{""}}}, invalid: true},
		{name: "malformed permission", field: "appthrust.io/group_grants", value: []GroupGrant{{Group: group, Permissions: []string{"reports:read reports:approve"}}}, invalid: true},
		{name: "too many groups", field: "appthrust.io/group_grants", value: slices.Repeat(grants, 65), invalid: true},
		{name: "oversized grants", field: "appthrust.io/group_grants", value: []GroupGrant{{Group: group, Permissions: slices.Repeat([]string{strings.Repeat("a", 64)}, 128)}}, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{
				"iss": "https://platform.example/access", "sub": "user:person", "aud": []string{"expense"}, "scope": "reports:read reports:approve",
				"appthrust.io/project": "project-x", "appthrust.io/installation": "expense",
				"appthrust.io/subject_kind": "user", "appthrust.io/credential": "session", "appthrust.io/subject_issuer": "https://oidc.example",
				"appthrust.io/principal": principal, "appthrust.io/group_grants": grants,
				"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
			}
			if tc.field != "" {
				if tc.value == nil {
					delete(claims, tc.field)
				} else {
					claims[tc.field] = tc.value
				}
			}
			raw := signPayload(t, key, jose.ES256, "current", AssertionType, claims)
			result, err := verifier.VerifySession(t.Context(), raw, binding, now)
			if tc.invalid {
				if !errors.Is(err, ErrInvalidAssertion) || !reflect.DeepEqual(result, SessionClaims{}) {
					t.Fatalf("invalid signed facts returned claims: %+v, %v", result, err)
				}
				if tc.name == "missing principal" && !strings.Contains(err.Error(), "missing signed principal (appthrust.io/principal)") {
					t.Fatalf("missing principal not identified: %v", err)
				}
				return
			}
			wantGrants := grants
			if tc.field != "" {
				wantGrants = tc.value.([]GroupGrant)
			}
			if err != nil || result.Principal != principal || !reflect.DeepEqual(result.GroupGrants, wantGrants) {
				t.Fatalf("signed identity lost: %+v, %v", result, err)
			}
		})
	}
}
