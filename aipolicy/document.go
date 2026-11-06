// Package aipolicy defines the dependency-free runtime AI policy contract.
package aipolicy

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	APIVersion        = "aipolicy.appthrust.io/v1"
	EnvMode           = "AI_POLICY_MODE"
	EnvDocument       = "AI_POLICY_DOCUMENT"
	OutputKeyMode     = "MODE"
	OutputKeyDocument = "DOCUMENT"
	ConnectionName    = "ai-policy"
)

type Mode string

const (
	ModeUnrestricted Mode = "Unrestricted"
	ModeEnforced     Mode = "Enforced"
	ModePending      Mode = "Pending"
)

// Document is the value of AI_POLICY_DOCUMENT. Enforced with no providers denies all.
type Document struct {
	APIVersion string     `json:"apiVersion"`
	Mode       Mode       `json:"mode"`
	Policy     *PolicyRef `json:"policy,omitempty"`
	Providers  []Provider `json:"providers"`
	Logging    *Logging   `json:"logging,omitempty"`
}

type PolicyRef struct {
	Group      string `json:"group"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
}

type Provider struct {
	Name        string      `json:"name"`
	Endpoint    string      `json:"endpoint"`
	ModelRules  []ModelRule `json:"modelRules"`
	Credentials string      `json:"credentials"`
}

// ModelRule is a union of anchored globs. Only '*' and '?' are special;
// like AgentPolicy expressions, wildcards match Unicode runes except newlines.
// A model must match at least one pattern in every rule of its provider.
type ModelRule struct {
	Patterns []string `json:"patterns"`
}

type Logging struct {
	Conversation string `json:"conversation"`
	ToolCalls    string `json:"toolCalls"`
	Retention    string `json:"retention"`
}

type Decision struct {
	Allowed bool
	Reason  string
}

// Reasons are shared by the gateway (403 bodies) and Platform API (412
// details.reason) so one vocabulary explains every policy verdict.
const (
	ReasonModelDenied          = "ai_model_denied"
	ReasonPolicyPending        = "ai_policy_pending"
	ReasonPolicyDenied         = "ai_policy_denied"
	ReasonModelUnresolved      = "ai_model_unresolved"
	ReasonApprovalPolicyDenied = "ai_approval_policy_denied"
)

// Decode reads the duplicated environment mode and versioned document, rejecting
// disagreement. Missing documents are permitted only for Unrestricted/Pending;
// an absent or unknown mode never silently disables enforcement.
func Decode(mode, documentJSON string) (Document, error) {
	selected := Mode(mode)
	if selected != ModeUnrestricted && selected != ModeEnforced && selected != ModePending {
		return Document{}, errors.New("invalid AI policy mode")
	}
	if documentJSON == "" && selected != ModeEnforced {
		return Document{APIVersion: APIVersion, Mode: selected}, nil
	}
	var document Document
	if err := json.Unmarshal([]byte(documentJSON), &document); err != nil {
		return Document{}, errors.New("invalid AI policy document")
	}
	if document.APIVersion != APIVersion {
		return Document{}, errors.New("unsupported AI policy apiVersion")
	}
	if document.Mode != selected {
		return Document{}, errors.New("AI policy mode does not match document")
	}
	return document, nil
}

func (d Document) Allows(provider, model string) Decision {
	switch d.Mode {
	case ModeUnrestricted:
		return Decision{Allowed: true}
	case ModePending:
		return Decision{Reason: ReasonPolicyPending}
	case ModeEnforced:
		for i := range d.Providers {
			if d.Providers[i].Name == provider {
				if providerAllows(d.Providers[i], model) {
					return Decision{Allowed: true}
				}
				break
			}
		}
	}
	return Decision{Reason: ReasonModelDenied}
}

func providerAllows(provider Provider, model string) bool {
	if len(provider.ModelRules) == 0 {
		return false
	}
	for _, rule := range provider.ModelRules {
		matched := false
		for _, pattern := range rule.Patterns {
			if match(pattern, model) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// DefaultModel returns the first explicit model in provider/rule/pattern order
// that is allowed by every rule. Patterns containing '*' or '?' cannot identify
// a concrete default and are skipped, not expanded. If there is no allowed
// literal (including Pending/Unrestricted), both return values are empty.
func (d Document) DefaultModel() (provider, model string) {
	if d.Mode != ModeEnforced {
		return "", ""
	}
	for _, candidate := range d.Providers {
		for _, rule := range candidate.ModelRules {
			for _, pattern := range rule.Patterns {
				if pattern != "" && !strings.ContainsAny(pattern, "*?") && d.Allows(candidate.Name, pattern).Allowed {
					return candidate.Name, pattern
				}
			}
		}
	}
	return "", ""
}

// DefaultModelFor returns the first explicit model literal of the named
// provider that every rule of that provider allows, or "" when the policy is
// not Enforced, the provider is absent, or only wildcard patterns remain.
func (d Document) DefaultModelFor(provider string) string {
	if d.Mode != ModeEnforced {
		return ""
	}
	for i := range d.Providers {
		if d.Providers[i].Name != provider {
			continue
		}
		for _, rule := range d.Providers[i].ModelRules {
			for _, pattern := range rule.Patterns {
				if pattern != "" && !strings.ContainsAny(pattern, "*?") && providerAllows(d.Providers[i], pattern) {
					return pattern
				}
			}
		}
		return ""
	}
	return ""
}

// match implements anchored glob matching without compiling a regexp or
// allocating rune slices on each invocation. A star retries at rune boundaries.
func match(pattern, value string) bool {
	p, v, star, retry := 0, 0, -1, 0
	for v < len(value) {
		if p < len(pattern) && pattern[p] == '*' {
			star, retry = p, v
			p++
			continue
		}
		vr, vs := utf8.DecodeRuneInString(value[v:])
		if p < len(pattern) {
			pr, ps := utf8.DecodeRuneInString(pattern[p:])
			if pr == vr || pr == '?' && vr != '\n' {
				p += ps
				v += vs
				continue
			}
		}
		if star < 0 || retry >= len(value) {
			return false
		}
		r, size := utf8.DecodeRuneInString(value[retry:])
		if r == '\n' {
			return false
		}
		retry += size
		p, v = star+1, retry
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
