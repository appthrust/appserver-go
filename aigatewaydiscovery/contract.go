// Package aigatewaydiscovery defines the workload-only AI Gateway discovery
// boundary shared by its credential issuer, Platform API, and Gateway client.
// It intentionally has no imports so partial-workspace images can copy it alone.
package aigatewaydiscovery

const (
	Audience = "ai-gateway-discovery"
	Scope    = "links:read"
	Path     = "/api/v1/ai-gateway/links"
	KeyEnv   = "PLATFORM_AI_GATEWAY_DISCOVERY_KEY"
)
