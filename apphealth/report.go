// Package apphealth defines the dependency-free application health wire contract.
package apphealth

import (
	"fmt"
	"time"
)

const (
	// PublicRouteHeader is overwritten by HTTPPublish on public Gateway routes.
	// Unlike K-Original-Host, Knative does not consume this application header.
	PublicRouteHeader = "X-Appthrust-Public-Route"

	StateServing  = "Serving"
	StateDegraded = "Degraded"
	StateFailing  = "Failing"
	StateUnknown  = "Unknown"

	ReasonDependencyUnavailable = "DependencyUnavailable"
	ReasonUpstreamUnavailable   = "UpstreamUnavailable"
	ReasonUpstreamDenied        = "UpstreamDenied"
	ReasonResourceExhausted     = "ResourceExhausted"
	ReasonInitialising          = "Initialising"
	ReasonNoEvidence            = "NoEvidence"
)

type Release struct {
	ArtifactDigest string `json:"artifactDigest"`
	ReleaseVersion string `json:"releaseVersion"`
}

type Capability struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type Report struct {
	Release      Release      `json:"release"`
	ObservedAt   time.Time    `json:"observedAt"`
	Capabilities []Capability `json:"capabilities"`
}

// Validate checks the wire enums, bounded messages and completeness. Undeclared
// capabilities are allowed for rolling upgrades, but must still be well formed.
func (r Report) Validate(declared []string) error {
	seen := make(map[string]bool, len(r.Capabilities))
	for _, c := range r.Capabilities {
		if c.Name == "" || seen[c.Name] {
			return fmt.Errorf("invalid or duplicate capability name %q", c.Name)
		}
		seen[c.Name] = true
		switch c.State {
		case StateServing, StateDegraded, StateFailing, StateUnknown:
		default:
			return fmt.Errorf("capability %q has unknown state %q", c.Name, c.State)
		}
		switch c.Reason {
		case "", ReasonDependencyUnavailable, ReasonUpstreamUnavailable, ReasonUpstreamDenied, ReasonResourceExhausted, ReasonInitialising, ReasonNoEvidence:
		default:
			return fmt.Errorf("capability %q has unknown reason %q", c.Name, c.Reason)
		}
		if len(c.Message) > 256 {
			return fmt.Errorf("capability %q message exceeds 256 bytes", c.Name)
		}
	}
	for _, name := range declared {
		if !seen[name] {
			return fmt.Errorf("missing declared capability %q", name)
		}
	}
	return nil
}
