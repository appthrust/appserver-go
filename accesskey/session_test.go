package accesskey

import (
	"context"
	"errors"
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
