// Package platformenv reads the public configuration supplied by a platform
// ComponentConnection. AppInstallation-specific audiences and release metadata stay with
// the consuming server.
package platformenv

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

type Platform struct {
	APIURL          string
	ProjectID       string
	OIDCIssuer      string
	OIDCIssuerCAPEM string
	AccessIssuer    string
}

// FromEnv validates local configuration without contacting the platform or issuer.
// An empty issuer is permitted for loopback development; authenticated servers
// must also call ValidateIdentityListen before binding their listener.
func FromEnv() (Platform, error) {
	platform := Platform{
		APIURL:          os.Getenv("PLATFORM_API_URL"),
		ProjectID:       os.Getenv("PLATFORM_PROJECT_ID"),
		OIDCIssuer:      os.Getenv("PLATFORM_OIDC_ISSUER"),
		OIDCIssuerCAPEM: os.Getenv("PLATFORM_OIDC_ISSUER_CA_PEM"),
		AccessIssuer:    os.Getenv("PLATFORM_ACCESS_ISSUER"),
	}
	if _, err := Validate(platform.APIURL, platform.ProjectID); err != nil {
		return Platform{}, err
	}
	if err := AppendCAPEM(nil, platform.OIDCIssuerCAPEM); err != nil {
		return Platform{}, err
	}
	return platform, nil
}

// Validate checks the platform origin and project scope used by server handlers.
// A trailing slash is accepted and removed from the returned origin.
func Validate(apiURL, projectID string) (*url.URL, error) {
	if len(validation.IsDNS1123Label(projectID)) != 0 {
		return nil, errors.New("PLATFORM_PROJECT_ID must be a non-empty DNS label (at most 63 lowercase alphanumeric or hyphen characters, starting and ending with alphanumeric)")
	}
	u, err := url.Parse(apiURL)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || strings.Contains(apiURL, "#") || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname()))) {
		return nil, errors.New("PLATFORM_API_URL must be an HTTPS origin (HTTP is allowed only for loopback hosts)")
	}
	u.Path, u.RawPath = "", ""
	return u, nil
}

// ValidateIdentityListen restricts unverified bearer claims to local development.
func ValidateIdentityListen(listen, issuer string) error {
	if issuer != "" {
		return nil
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil || !isLoopback(host) {
		return errors.New("PLATFORM_OIDC_ISSUER is required unless --listen uses a loopback host")
	}
	return nil
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

// AppendCAPEM strictly parses a certificate-only bundle and adds its certificates
// to roots. A nil pool validates without retaining certificates; an empty bundle
// leaves the system-root-only configuration unchanged.
func AppendCAPEM(roots *x509.CertPool, caPEM string) error {
	if caPEM == "" {
		return nil
	}
	remaining := bytes.TrimSpace([]byte(caPEM))
	const endMarker = "-----END CERTIFICATE-----"
	for {
		end := bytes.Index(remaining, []byte(endMarker))
		if end < 0 || !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("OIDC CA PEM must contain only PEM certificates")
		}
		end += len(endMarker)
		block, rest := pem.Decode(remaining[:end])
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 {
			return errors.New("OIDC CA PEM must contain only PEM certificates")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse OIDC CA PEM certificate: %w", err)
		}
		if roots != nil {
			roots.AddCert(certificate)
		}
		remaining = bytes.TrimSpace(remaining[end:])
		if len(remaining) == 0 {
			return nil
		}
	}
}
