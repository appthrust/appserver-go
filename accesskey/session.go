package accesskey

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// SessionBinding binds an SDK-internal assertion to a verified OIDC user and
// this app installation. InstallationUID is optional; all other fields are required.
type SessionBinding struct {
	Audience, Subject, SubjectIssuer       string
	Project, Installation, InstallationUID string
}

// SessionClaims contains only verified permissions and their validity window.
// Session assertions must never be accepted as network bearer credentials.
type SessionClaims struct {
	Scopes              []string
	IssuedAt, ExpiresAt time.Time
}

// VerifySession verifies an exchange result, not a network bearer. Issued-at
// tolerates the shared assertion clock leeway, but expiry has no leeway.
// now is an injected clock.
func (v *Verifier) VerifySession(ctx context.Context, raw string, binding SessionBinding, now time.Time) (SessionClaims, error) {
	if binding.Audience == "" || binding.Subject == "" || binding.SubjectIssuer == "" || binding.Project == "" || binding.Installation == "" {
		return SessionClaims{}, fmt.Errorf("%w: incomplete session binding", ErrInvalidAssertion)
	}
	payload, err := v.verifyPayload(ctx, raw)
	if err != nil {
		return SessionClaims{}, err
	}
	var wire struct {
		Issuer          string   `json:"iss"`
		Subject         string   `json:"sub"`
		Audience        []string `json:"aud"`
		Scope           string   `json:"scope"`
		Project         string   `json:"appthrust.io/project"`
		Installation    string   `json:"appthrust.io/installation"`
		InstallationUID string   `json:"appthrust.io/installation_uid"`
		Credential      string   `json:"appthrust.io/credential"`
		SubjectKind     string   `json:"appthrust.io/subject_kind"`
		SubjectIssuer   string   `json:"appthrust.io/subject_issuer"`
		IssuedAt        int64    `json:"iat"`
		ExpiresAt       int64    `json:"exp"`
	}
	if json.Unmarshal(payload, &wire) != nil {
		return SessionClaims{}, fmt.Errorf("%w: session claims", ErrInvalidAssertion)
	}
	if v.issuer == "" || wire.Issuer != v.issuer || !slices.Contains(wire.Audience, binding.Audience) ||
		wire.Credential != "session" || wire.SubjectKind != "user" || wire.Subject != "user:"+binding.Subject ||
		wire.SubjectIssuer != binding.SubjectIssuer || wire.Project != binding.Project || wire.Installation != binding.Installation ||
		(binding.InstallationUID != "" && wire.InstallationUID != binding.InstallationUID) {
		return SessionClaims{}, fmt.Errorf("%w: session binding", ErrInvalidAssertion)
	}
	issued, expires := time.Unix(wire.IssuedAt, 0), time.Unix(wire.ExpiresAt, 0)
	if wire.IssuedAt <= 0 || !expires.After(issued) || expires.Sub(issued) > MaxAssertionTTL || issued.After(now.Add(assertionLeeway)) {
		return SessionClaims{}, fmt.Errorf("%w: session lifetime", ErrInvalidAssertion)
	}
	if !now.Before(expires) {
		return SessionClaims{}, ErrExpiredAssertion
	}
	return SessionClaims{Scopes: strings.Fields(wire.Scope), IssuedAt: issued, ExpiresAt: expires}, nil
}
