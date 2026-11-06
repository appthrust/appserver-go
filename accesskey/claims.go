package accesskey

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	IssuerSuffix    = "/access"
	AssertionType   = "appthrust-access+jwt"
	MaxAssertionTTL = 5 * time.Minute
)

func IssuerURL(dashboardOrigin string) string {
	return strings.TrimRight(dashboardOrigin, "/") + IssuerSuffix
}

func JWKSURL(issuer string) string {
	return strings.TrimRight(issuer, "/") + "/jwks.json"
}

// Claims is the public assertion payload. Its JSON form uses JWT numeric dates,
// one audience, a space-delimited scope string, and a kind-prefixed subject.
type Claims struct {
	Issuer              string
	Subject             Subject
	Audience            string
	Scopes              []string
	Project             string
	KeyName             string
	JTI                 string
	IssuedAt, ExpiresAt time.Time
}

// NewClaims returns claims only for an allowed decision. TTLs longer than five
// minutes are clamped; nonpositive TTLs remain nonpositive (never extended).
func NewClaims(issuer, project string, d Decision, now time.Time, ttl time.Duration) Claims {
	if d.Outcome != Allow || d.Key == nil {
		return Claims{}
	}
	if ttl > MaxAssertionTTL {
		ttl = MaxAssertionTTL
	}
	var id [16]byte
	// crypto/rand.Read fills the buffer or terminates the process on failure.
	rand.Read(id[:])
	return Claims{
		Issuer: issuer, Subject: d.Key.Subject, Audience: d.Key.Audience,
		Scopes: d.Scopes, Project: project, KeyName: d.Key.Name,
		JTI:      base64.RawURLEncoding.EncodeToString(id[:]),
		IssuedAt: now, ExpiresAt: now.Add(ttl),
	}
}

type assertionClaims struct {
	Issuer      string      `json:"iss"`
	Subject     string      `json:"sub"`
	Audience    []string    `json:"aud"`
	Scope       string      `json:"scope"`
	Project     string      `json:"appthrust.io/project"`
	KeyName     string      `json:"appthrust.io/key"`
	SubjectKind SubjectKind `json:"appthrust.io/subject_kind"`
	JTI         string      `json:"jti"`
	IssuedAt    int64       `json:"iat"`
	ExpiresAt   int64       `json:"exp"`
}

func (c Claims) MarshalJSON() ([]byte, error) {
	return json.Marshal(assertionClaims{
		Issuer: c.Issuer, Subject: c.Subject.String(), Audience: []string{c.Audience},
		Scope: strings.Join(c.Scopes, " "), Project: c.Project, KeyName: c.KeyName,
		SubjectKind: c.Subject.Kind, JTI: c.JTI,
		IssuedAt: c.IssuedAt.Unix(), ExpiresAt: c.ExpiresAt.Unix(),
	})
}

func (c *Claims) UnmarshalJSON(data []byte) error {
	var wire assertionClaims
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("%w: claims encoding", ErrInvalidAssertion)
	}
	subject, err := ParseSubject(wire.Subject)
	if err != nil || subject.Kind != wire.SubjectKind {
		return fmt.Errorf("%w: subject", ErrInvalidAssertion)
	}
	if len(wire.Audience) != 1 || wire.Audience[0] == "" {
		return fmt.Errorf("%w: audience", ErrInvalidAssertion)
	}
	if wire.ExpiresAt == 0 {
		return fmt.Errorf("%w: missing expiry", ErrInvalidAssertion)
	}
	*c = Claims{
		Issuer: wire.Issuer, Subject: subject, Audience: wire.Audience[0],
		Scopes: strings.Fields(wire.Scope), Project: wire.Project, KeyName: wire.KeyName,
		JTI: wire.JTI, IssuedAt: time.Unix(wire.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(wire.ExpiresAt, 0).UTC(),
	}
	return nil
}
