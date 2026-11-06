package platformenv

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func platformEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("PLATFORM_API_URL", "https://platform.example")
	t.Setenv("PLATFORM_PROJECT_ID", "pj-test")
	t.Setenv("PLATFORM_OIDC_ISSUER", "")
	t.Setenv("PLATFORM_OIDC_ISSUER_CA_PEM", "")
	t.Setenv("PLATFORM_ACCESS_ISSUER", "")
}

func TestFromEnvReadsPlatformConnection(t *testing.T) {
	platformEnvironment(t)
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	t.Setenv("PLATFORM_OIDC_ISSUER", server.URL+"/realms/platform")
	t.Setenv("PLATFORM_OIDC_ISSUER_CA_PEM", caPEM)
	t.Setenv("PLATFORM_ACCESS_ISSUER", "https://platform.example/access")
	platform, err := FromEnv()
	require.NoError(t, err)
	require.Equal(t, Platform{
		APIURL:          "https://platform.example",
		ProjectID:       "pj-test",
		OIDCIssuer:      server.URL + "/realms/platform",
		OIDCIssuerCAPEM: caPEM,
		AccessIssuer:    "https://platform.example/access",
	}, platform)
}

func TestFromEnvValidatesOriginAndProject(t *testing.T) {
	for _, raw := range []string{"", "not a URL", "http://platform.example", "ftp://localhost", "https:///api", "https://user:pass@example.com", "https://example.com/api", "https://example.com?x=1", "https://example.com?", "https://example.com#fragment", "https://example.com#"} {
		t.Run("origin "+raw, func(t *testing.T) {
			platformEnvironment(t)
			t.Setenv("PLATFORM_API_URL", raw)
			platform, err := FromEnv()
			require.EqualError(t, err, "PLATFORM_API_URL must be an HTTPS origin (HTTP is allowed only for loopback hosts)")
			require.Zero(t, platform)
		})
	}
	for _, project := range []string{"", " ", "UPPERCASE", "project_id", "-project", "project-", strings.Repeat("a", 64)} {
		t.Run("project "+project, func(t *testing.T) {
			platformEnvironment(t)
			t.Setenv("PLATFORM_PROJECT_ID", project)
			platform, err := FromEnv()
			require.EqualError(t, err, "PLATFORM_PROJECT_ID must be a non-empty DNS label (at most 63 lowercase alphanumeric or hyphen characters, starting and ending with alphanumeric)")
			require.Zero(t, platform)
		})
	}
	for _, raw := range []string{"https://platform.example", "https://platform.example/", "http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"} {
		t.Run("valid origin "+raw, func(t *testing.T) {
			platformEnvironment(t)
			t.Setenv("PLATFORM_API_URL", raw)
			platform, err := FromEnv()
			require.NoError(t, err)
			require.Equal(t, raw, platform.APIURL)
			origin, err := Validate(raw, "pj-test")
			require.NoError(t, err)
			require.Empty(t, origin.Path)
		})
	}
	for _, project := range []string{"a", "pj-test", strings.Repeat("a", 63)} {
		platformEnvironment(t)
		t.Setenv("PLATFORM_PROJECT_ID", project)
		_, err := FromEnv()
		require.NoError(t, err)
	}
}

func TestFromEnvValidatesPEMBeforeIdentityDiscovery(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	malformed := "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n"
	for name, bundle := range map[string]string{
		"text":              "invalid PEM",
		"whitespace":        " \n",
		"malformed":         malformed,
		"invalid DER":       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")})),
		"non-certificate":   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("key")})),
		"headers":           string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Unexpected": "header"}, Bytes: server.Certificate().Raw})),
		"valid then broken": caPEM + malformed,
		"broken then valid": malformed + caPEM,
		"trailing text":     caPEM + "invalid PEM",
	} {
		t.Run(name, func(t *testing.T) {
			platformEnvironment(t)
			t.Setenv("PLATFORM_OIDC_ISSUER_CA_PEM", bundle)
			platform, err := FromEnv()
			require.ErrorContains(t, err, "OIDC CA PEM")
			require.Zero(t, platform)
		})
	}
	platformEnvironment(t)
	t.Setenv("PLATFORM_OIDC_ISSUER_CA_PEM", "\n"+caPEM+caPEM+"\n")
	_, err := FromEnv()
	require.NoError(t, err)
}

func TestTrustedClaimsRequireLoopbackListen(t *testing.T) {
	platformEnvironment(t)
	platform, err := FromEnv()
	require.NoError(t, err)
	for _, listen := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		require.NoError(t, ValidateIdentityListen(listen, platform.OIDCIssuer), listen)
	}
	for _, listen := range []string{":8080", "0.0.0.0:8080", "[::]:8080", "192.0.2.1:8080", "invalid"} {
		require.EqualError(t, ValidateIdentityListen(listen, platform.OIDCIssuer), "PLATFORM_OIDC_ISSUER is required unless --listen uses a loopback host", listen)
	}
	t.Setenv("PLATFORM_OIDC_ISSUER", "https://identity.example/realms/platform")
	platform, err = FromEnv()
	require.NoError(t, err)
	require.NoError(t, ValidateIdentityListen(":8080", platform.OIDCIssuer))
}
