package aipolicy

// Outcome records the gateway's result without carrying request/response text.
type Outcome string

const (
	OutcomeAllowed Outcome = "Allowed"
	OutcomeDenied  Outcome = "Denied"
	OutcomeError   Outcome = "Error"
)

// InvocationRecord is the Platform API AI-invocation request. Digests, when
// present, are hexadecimal SHA-256 without a prefix. Policy is nil when no
// policy is bound; Usage is nil when the provider reports no token counts.
type InvocationRecord struct {
	Provider         string             `json:"provider"`
	Model            string             `json:"model"`
	Policy           *PolicyRef         `json:"policy,omitempty"`
	Outcome          Outcome            `json:"outcome"`
	Status           int                `json:"status"`
	Reason           string             `json:"reason,omitempty"`
	Usage            *Usage             `json:"usage,omitempty"`
	RequestDigest    string             `json:"requestDigest,omitempty"`
	CompletionDigest string             `json:"completionDigest,omitempty"`
	Logging          *InvocationLogging `json:"logging,omitempty"`
	DurationMs       int64              `json:"durationMs"`
}

type Usage struct {
	PromptTokens     int64 `json:"promptTokens"`
	CompletionTokens int64 `json:"completionTokens"`
}

type InvocationLogging struct {
	Conversation string `json:"conversation"`
	ToolCalls    string `json:"toolCalls"`
}
