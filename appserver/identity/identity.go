package identity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/appthrust/appserver-go/accesskey"
	"github.com/appthrust/appserver-go/appserver/platformenv"
	"github.com/coreos/go-oidc/v3/oidc"
)

// Identity retains user-only profile fields beside the shared principal.
type Identity struct {
	Principal accesskey.Principal
	Email     string
	Name      string
	Access    *AppAccess
}

type Trust struct {
	OIDCIssuer     string
	OIDCCAPEM      string
	OIDCAudiences  []string
	AccessIssuer   string
	AccessAudience string
	// AppAccess enables user-permission exchange; nil preserves legacy behavior.
	AppAccess *AppAccessConfig
}

// FromEnv reads platform connection trust and audience configuration for a built-in app.
// An absent access audience disables assertion authentication for this built-in app.
func FromEnv(prefix string) Trust {
	return Trust{
		OIDCIssuer:     os.Getenv("PLATFORM_OIDC_ISSUER"),
		OIDCCAPEM:      os.Getenv("PLATFORM_OIDC_ISSUER_CA_PEM"),
		OIDCAudiences:  strings.Split(os.Getenv(prefix+"_OIDC_AUDIENCES"), ","),
		AccessIssuer:   os.Getenv("PLATFORM_ACCESS_ISSUER"),
		AccessAudience: os.Getenv(prefix + "_ACCESS_AUDIENCE"),
	}
}

type userClaims struct {
	Subject           string   `json:"sub"`
	Issuer            string   `json:"iss"`
	AuthorizedParty   string   `json:"azp"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	ExpiresAt         int64    `json:"exp"`
	NotBefore         int64    `json:"nbf"`
	Groups            []string `json:"groups"`
}

const discoveryBackoff = 5 * time.Second

var (
	ErrUnavailable       = errors.New("identity unavailable")
	ErrRawKeyNotAccepted = errors.New("raw_key_not_accepted")
)

type Authenticator struct {
	trust     Trust
	http      *http.Client
	mu        sync.Mutex
	verifiers []*oidc.IDTokenVerifier
	access    *accesskey.Verifier
	appAccess *appAccessClient
	// inflight is non-nil while one caller runs discovery; it is closed when
	// that attempt ends so concurrent callers wait for its result instead of
	// failing. Discovery is driven by the first authenticated request to a
	// fresh Pod, and a SPA fires several in parallel; failing all but one
	// surfaced as a single 503 on every built-in app rollout (ink, 2026-10-14).
	inflight chan struct{}
	retryAt  time.Time
}

// New validates local trust configuration without contacting the issuer.
// An empty issuer retains the unverified local-development mode.
func New(trust Trust) (*Authenticator, error) {
	client, err := httpClient(trust.OIDCCAPEM)
	if err != nil {
		return nil, err
	}
	audiences := make([]string, 0, len(trust.OIDCAudiences))
	for _, audience := range trust.OIDCAudiences {
		if audience = strings.TrimSpace(audience); audience != "" {
			audiences = append(audiences, audience)
		}
	}
	trust.OIDCAudiences = audiences
	if trust.OIDCIssuer != "" && len(audiences) == 0 {
		return nil, errors.New("OIDC audiences are required when OIDC issuer is configured")
	}
	if trust.AccessAudience != "" && trust.AccessIssuer == "" {
		return nil, errors.New("access issuer is required when access audience is configured")
	}
	if trust.AccessIssuer != "" && trust.AccessIssuer == trust.OIDCIssuer {
		return nil, errors.New("OIDC and access issuers must be distinct")
	}
	a := &Authenticator{trust: trust, http: client}
	var assertions *accesskey.Verifier
	if trust.AppAccess != nil && (trust.OIDCIssuer == "" || trust.AccessIssuer == "") {
		return nil, errors.New("OIDC and access issuers are required for app access")
	}
	if trust.AccessIssuer != "" && (trust.AccessAudience != "" || trust.AppAccess != nil) {
		assertions = accesskey.NewVerifier(trust.AccessIssuer, accesskey.NewHTTPJWKSSource(accesskey.JWKSURL(trust.AccessIssuer), client, 5*time.Minute))
	}
	if trust.AccessAudience != "" {
		a.access = assertions
	}
	if trust.AppAccess != nil {
		a.appAccess, err = newAppAccessClient(*trust.AppAccess, client, assertions)
		if err != nil {
			return nil, err
		}
	}
	if trust.OIDCIssuer == "" {
		log.Print("WARNING: OIDC issuer is unset; bearer claims are UNVERIFIED (local development only)")
	}
	return a, nil
}

// HTTPClient shares the configured trust roots with other platform requests.
// Callers must not modify the returned client or its transport.
func (a *Authenticator) HTTPClient() *http.Client {
	if a.http != nil {
		return a.http
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (a *Authenticator) getVerifier(ctx context.Context, audience int) (*oidc.IDTokenVerifier, error) {
	for {
		a.mu.Lock()
		if a.verifiers != nil {
			verifier := a.verifiers[audience]
			a.mu.Unlock()
			return verifier, nil
		}
		if wait := a.inflight; wait != nil {
			a.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ErrUnavailable
			}
		}
		if time.Now().Before(a.retryAt) {
			a.mu.Unlock()
			return nil, ErrUnavailable
		}
		done := make(chan struct{})
		a.inflight = done
		a.mu.Unlock()
		// The leader's ctx bounds the attempt; waiters that time out earlier
		// leave on their own ctx above.
		provider, err := oidc.NewProvider(oidc.ClientContext(ctx, a.http), a.trust.OIDCIssuer)
		a.mu.Lock()
		a.inflight = nil
		if err != nil {
			a.retryAt = time.Now().Add(discoveryBackoff)
			log.Printf("console identity discovery failed; retrying after %s: %v", discoveryBackoff, err)
		} else {
			// Every verifier enforces a configured audience as well as issuer,
			// signature and expiry. Discovery and JWKS are shared and cached.
			a.verifiers = make([]*oidc.IDTokenVerifier, len(a.trust.OIDCAudiences))
			for i, clientID := range a.trust.OIDCAudiences {
				a.verifiers[i] = provider.Verifier(&oidc.Config{ClientID: clientID})
			}
		}
		var verifier *oidc.IDTokenVerifier
		if err == nil {
			verifier = a.verifiers[audience]
		}
		a.mu.Unlock()
		close(done)
		if err != nil {
			return nil, ErrUnavailable
		}
		return verifier, nil
	}
}

func (a *Authenticator) Authenticate(ctx context.Context, header string) (Identity, string, error) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return Identity{}, "", errors.New("bearer token required")
	}
	raw := fields[1]
	if accesskey.IsSecret(raw) {
		return Identity{}, "", ErrRawKeyNotAccepted
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Identity{}, "", errors.New("invalid JWT")
	}
	jwtHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	var algorithm struct {
		Algorithm string `json:"alg"`
	}
	if err != nil || json.Unmarshal(jwtHeader, &algorithm) != nil || algorithm.Algorithm == "" {
		return Identity{}, "", errors.New("invalid JWT header")
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		return Identity{}, "", errors.New("invalid JWT signature encoding")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	var routing struct {
		Issuer     string          `json:"iss"`
		Audience   json.RawMessage `json:"aud"`
		Credential string          `json:"appthrust.io/credential"`
	}
	if err != nil || json.Unmarshal(body, &routing) != nil {
		return Identity{}, "", errors.New("invalid JWT claims")
	}
	// Even in local-development mode, SDK-internal assertions are never network credentials.
	if routing.Credential == "session" {
		return Identity{}, "", errors.New("session assertions are not accepted as bearer tokens")
	}
	// Unverified issuer and audience select trust, never establish identity.
	if a.trust.AccessIssuer != "" && routing.Issuer == a.trust.AccessIssuer {
		if a.access == nil {
			return Identity{}, "", errors.New("access assertions are not accepted")
		}
		claims, err := a.access.Verify(ctx, raw, a.trust.AccessAudience)
		if err != nil {
			return Identity{}, "", err
		}
		return Identity{Principal: claims.Principal()}, "Bearer " + raw, nil
	}
	var claims userClaims
	if a.trust.OIDCIssuer != "" {
		if routing.Issuer != a.trust.OIDCIssuer {
			return Identity{}, "", errors.New("untrusted JWT issuer")
		}
		var audiences []string
		if err := json.Unmarshal(routing.Audience, &audiences); err != nil {
			var audience string
			if json.Unmarshal(routing.Audience, &audience) != nil {
				return Identity{}, "", errors.New("invalid JWT audience")
			}
			audiences = []string{audience}
		}
		matched := -1
		for i, expected := range a.trust.OIDCAudiences {
			for _, audience := range audiences {
				if audience == expected {
					matched = i
					break
				}
			}
			if matched >= 0 {
				break
			}
		}
		if matched < 0 {
			return Identity{}, "", errors.New("untrusted JWT audience")
		}
		verifier, err := a.getVerifier(ctx, matched)
		if err != nil {
			return Identity{}, "", err
		}
		token, err := verifier.Verify(ctx, raw)
		if err != nil {
			return Identity{}, "", err
		}
		if err := token.Claims(&claims); err != nil {
			return Identity{}, "", err
		}
	} else if err := json.Unmarshal(body, &claims); err != nil {
		return Identity{}, "", errors.New("invalid JWT claims")
	}
	bearerSubject := claims.Subject
	claims.Subject = strings.TrimSpace(claims.Subject)
	claims.Email = strings.ToLower(strings.TrimSpace(claims.Email))
	address, err := mail.ParseAddress(claims.Email)
	if claims.Subject == "" || err != nil || address.Address != claims.Email {
		return Identity{}, "", errors.New("subject and email claims required")
	}
	now := time.Now().Unix()
	if claims.ExpiresAt != 0 && now >= claims.ExpiresAt || claims.NotBefore != 0 && now < claims.NotBefore {
		return Identity{}, "", errors.New("token is not currently valid")
	}
	claims.Name = strings.TrimSpace(claims.Name)
	if claims.Name == "" {
		claims.Name = strings.TrimSpace(claims.PreferredUsername)
	}
	if claims.Name == "" {
		claims.Name = claims.Email
	}
	result := Identity{
		Principal: accesskey.Principal{Kind: "user", Subject: claims.Subject, Groups: claims.Groups},
		Email:     claims.Email, Name: claims.Name,
	}
	if a.appAccess != nil {
		access, err := a.appAccess.resolve(ctx, appAccessKey{issuer: claims.Issuer, subject: bearerSubject, audience: claims.AuthorizedParty}, "Bearer "+raw)
		if err != nil {
			return Identity{}, "", err
		}
		result.Principal.Scopes = access.scopes
		result.Principal.Project = a.appAccess.config.Project
		result.Access = &access.access
		if a.appAccess.config.RequirePermissions {
			if err := checkAppAccess(result); err != nil {
				return Identity{}, "", err
			}
		}
	}
	return result, "Bearer " + raw, nil
}

// httpClient bounds discovery and remote key retrieval, including key rotation.
// A configured PEM bundle augments (never replaces) the system trust roots.
func httpClient(caPEM string) (*http.Client, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	if caPEM == "" {
		return client, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system roots for OIDC CA PEM: %w", err)
	}
	if err := platformenv.AppendCAPEM(roots, caPEM); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	client.Transport = transport
	return client, nil
}
