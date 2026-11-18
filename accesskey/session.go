package accesskey

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// These bounds match the Platform API's app group grant projection.
const (
	maxSessionGroupGrants     = 64
	maxSessionGroupGrantBytes = 8 * 1024
)

var (
	// ErrMissingSignedPrincipal identifies an older Platform API while retaining
	// the ErrInvalidAssertion contract for callers that do not need the detail.
	ErrMissingSignedPrincipal = fmt.Errorf("%w: missing signed principal (appthrust.io/principal); Platform API must include #7087", ErrInvalidAssertion)

	sessionPrincipalPattern  = regexp.MustCompile(`^u_[A-Za-z0-9_-]{43}$`)
	sessionGroupPattern      = regexp.MustCompile(`^g_[A-Za-z0-9_-]{43}$`)
	sessionPermissionPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*(:[a-z][a-z0-9-]*)?$`)
)

// SessionBinding binds an SDK-internal assertion to a verified OIDC user and
// this app installation. InstallationUID is optional; all other fields are required.
type SessionBinding struct {
	Audience string
	// Original OIDC identity used for binding. Store SessionClaims.Principal instead.
	Subject, SubjectIssuer                 string
	Project, Installation, InstallationUID string
}

// GroupGrant contains a signed per-app durable group key and its permissions.
type GroupGrant struct {
	Group       string   `json:"group"`
	Permissions []string `json:"permissions"`
}

// SessionClaims contains verified person identity, grants and their validity window.
// Session assertions must never be accepted as network bearer credentials.
type SessionClaims struct {
	// Principal is the platform-signed durable person key to store for authors/owners.
	Principal           string
	GroupGrants         []GroupGrant
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
		Issuer          string          `json:"iss"`
		Subject         string          `json:"sub"`
		Audience        []string        `json:"aud"`
		Scope           string          `json:"scope"`
		Project         string          `json:"appthrust.io/project"`
		Installation    string          `json:"appthrust.io/installation"`
		InstallationUID string          `json:"appthrust.io/installation_uid"`
		Credential      string          `json:"appthrust.io/credential"`
		SubjectKind     string          `json:"appthrust.io/subject_kind"`
		SubjectIssuer   string          `json:"appthrust.io/subject_issuer"`
		Principal       string          `json:"appthrust.io/principal"`
		GroupGrants     json.RawMessage `json:"appthrust.io/group_grants"`
		IssuedAt        int64           `json:"iat"`
		ExpiresAt       int64           `json:"exp"`
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
	if wire.Principal == "" {
		return SessionClaims{}, ErrMissingSignedPrincipal
	}
	if !sessionPrincipalPattern.MatchString(wire.Principal) {
		return SessionClaims{}, fmt.Errorf("%w: invalid signed principal (appthrust.io/principal)", ErrInvalidAssertion)
	}
	var grants []GroupGrant
	if len(wire.GroupGrants) > maxSessionGroupGrantBytes || json.Unmarshal(wire.GroupGrants, &grants) != nil ||
		grants == nil || len(grants) > maxSessionGroupGrants {
		return SessionClaims{}, fmt.Errorf("%w: invalid signed group grants (appthrust.io/group_grants)", ErrInvalidAssertion)
	}
	for _, grant := range grants {
		if !sessionGroupPattern.MatchString(grant.Group) || grant.Permissions == nil {
			return SessionClaims{}, fmt.Errorf("%w: invalid signed group grants (appthrust.io/group_grants)", ErrInvalidAssertion)
		}
		for _, permission := range grant.Permissions {
			if len(permission) > 64 || !sessionPermissionPattern.MatchString(permission) {
				return SessionClaims{}, fmt.Errorf("%w: invalid signed group grants (appthrust.io/group_grants)", ErrInvalidAssertion)
			}
		}
	}
	return SessionClaims{Principal: wire.Principal, GroupGrants: grants,
		Scopes: strings.Fields(wire.Scope), IssuedAt: issued, ExpiresAt: expires}, nil
}
