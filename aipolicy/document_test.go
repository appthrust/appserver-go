package aipolicy

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func TestAllows(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     Mode
		rules    []ModelRule
		provider string
		model    string
		want     Decision
	}{
		{"unrestricted", ModeUnrestricted, nil, "unknown", "anything", Decision{Allowed: true}},
		{"pending", ModePending, nil, "openai", "gpt-5-mini", Decision{Reason: ReasonPolicyPending}},
		{"invalid mode", "", nil, "openai", "gpt-5-mini", Decision{Reason: ReasonModelDenied}},
		{"both rules", ModeEnforced, []ModelRule{{[]string{"gpt-*"}}, {[]string{"gpt-5-mini", "other"}}}, "openai", "gpt-5-mini", Decision{Allowed: true}},
		{"only first rule", ModeEnforced, []ModelRule{{[]string{"gpt-*"}}, {[]string{"gpt-5-mini"}}}, "openai", "gpt-4o-mini", Decision{Reason: ReasonModelDenied}},
		{"only second rule", ModeEnforced, []ModelRule{{[]string{"gpt-*"}}, {[]string{"other"}}}, "openai", "other", Decision{Reason: ReasonModelDenied}},
		{"unknown provider", ModeEnforced, []ModelRule{{[]string{"*"}}}, "other", "gpt-5-mini", Decision{Reason: ReasonModelDenied}},
		{"empty rule", ModeEnforced, []ModelRule{{}}, "openai", "gpt-5-mini", Decision{Reason: ReasonModelDenied}},
		{"no rules", ModeEnforced, nil, "openai", "gpt-5-mini", Decision{Reason: ReasonModelDenied}},
		{"question mark", ModeEnforced, []ModelRule{{[]string{"gpt-?-mini"}}}, "openai", "gpt-5-mini", Decision{Allowed: true}},
		{"literal regexp", ModeEnforced, []ModelRule{{[]string{"model.[x]+(a)|^$\\"}}}, "openai", "model.[x]+(a)|^$\\", Decision{Allowed: true}},
		{"anchored", ModeEnforced, []ModelRule{{[]string{"gpt-5"}}}, "openai", "prefix-gpt-5", Decision{Reason: ReasonModelDenied}},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := Document{Mode: test.mode, Providers: []Provider{{Name: "openai", ModelRules: test.rules}}}
			if got := document.Allows(test.provider, test.model); got != test.want {
				t.Fatalf("Allows() = %+v, want %+v", got, test.want)
			}
		})
	}
	if got := (Document{Mode: ModeEnforced}).Allows("openai", "gpt-5-mini"); got != (Decision{Reason: ReasonModelDenied}) {
		t.Fatalf("empty providers must deny: %+v", got)
	}
}

func TestGlobMatchesAgentPolicyExpression(t *testing.T) {
	// Independent oracle: the exact QuoteMeta/*/? expression used by AgentPolicy.
	patterns := []string{"", "*", "?", "a*", "a?", "*a*b?", "a**b", "*?*", "model.[x]+(a)|^$\\", "雪?*", "*\na", "a\n*"}
	values := []string{"", "a", "ab", "abc", "aaabbx", "model.[x]+(a)|^$\\", "雪山", "雪山川", "\n", "a\n", "\na", "a\nb", "?"}
	for _, pattern := range patterns {
		expression := regexp.QuoteMeta(pattern)
		expression = strings.ReplaceAll(expression, `\*`, ".*")
		expression = strings.ReplaceAll(expression, `\?`, ".")
		oracle := regexp.MustCompile("^(" + expression + ")$")
		for _, value := range values {
			if got, want := match(pattern, value), oracle.MatchString(value); got != want {
				t.Errorf("match(%q, %q) = %t, want %t", pattern, value, got, want)
			}
		}
	}
}

func TestDecode(t *testing.T) {
	for _, test := range []struct {
		name, mode, document, wantError string
	}{
		{"enforced", "Enforced", `{"apiVersion":"aipolicy.appthrust.io/v1","mode":"Enforced","providers":[]}`, ""},
		{"unrestricted without document", "Unrestricted", "", ""},
		{"pending without document", "Pending", "", ""},
		{"missing mode", "", "", "invalid AI policy mode"},
		{"unknown mode", "enforced", "", "invalid AI policy mode"},
		{"enforced without document", "Enforced", "", "invalid AI policy document"},
		{"malformed", "Enforced", "{", "invalid AI policy document"},
		{"unsupported version", "Enforced", `{"apiVersion":"v2","mode":"Enforced"}`, "unsupported AI policy apiVersion"},
		{"missing version", "Enforced", `{"mode":"Enforced"}`, "unsupported AI policy apiVersion"},
		{"mode mismatch", "Enforced", `{"apiVersion":"aipolicy.appthrust.io/v1","mode":"Unrestricted"}`, "AI policy mode does not match document"},
		{"trailing document", "Enforced", `{} {}`, "invalid AI policy document"},
	} {
		t.Run(test.name, func(t *testing.T) {
			document, err := Decode(test.mode, test.document)
			if test.wantError != "" {
				if err == nil || err.Error() != test.wantError {
					t.Fatalf("Decode() error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil || document.Mode != Mode(test.mode) || document.APIVersion != APIVersion {
				t.Fatalf("Decode() = %+v, %v", document, err)
			}
		})
	}
}

func TestDefaultModel(t *testing.T) {
	for _, test := range []struct {
		name     string
		document Document
		provider string
		model    string
	}{
		{"unrestricted", Document{Mode: ModeUnrestricted}, "", ""},
		{"pending", Document{Mode: ModePending}, "", ""},
		{"empty providers", Document{Mode: ModeEnforced}, "", ""},
		{"glob only", Document{Mode: ModeEnforced, Providers: []Provider{{Name: "first", ModelRules: []ModelRule{{[]string{"gpt-*", "gpt-?"}}}}}}, "", ""},
		{"intersection", Document{Mode: ModeEnforced, Providers: []Provider{{Name: "first", ModelRules: []ModelRule{{[]string{"denied", "gpt-*"}}, {[]string{"gpt-5-mini", "gpt-5"}}}}}}, "first", "gpt-5-mini"},
		{"provider ordering", Document{Mode: ModeEnforced, Providers: []Provider{{Name: "first", ModelRules: []ModelRule{{[]string{"gpt-5"}}}}, {Name: "second", ModelRules: []ModelRule{{[]string{"gpt-5-mini"}}}}}}, "first", "gpt-5"},
		{"skip denied provider", Document{Mode: ModeEnforced, Providers: []Provider{{Name: "first", ModelRules: []ModelRule{{[]string{"a"}}, {[]string{"b"}}}}, {Name: "second", ModelRules: []ModelRule{{[]string{"model.v1"}}}}}}, "second", "model.v1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider, model := test.document.DefaultModel()
			if provider != test.provider || model != test.model {
				t.Fatalf("DefaultModel() = %q, %q; want %q, %q", provider, model, test.provider, test.model)
			}
		})
	}
}

func TestDefaultModelFor(t *testing.T) {
	for _, test := range []struct {
		name     string
		document Document
		provider string
		model    string
	}{
		{"unrestricted", Document{Mode: ModeUnrestricted, Providers: []Provider{{Name: "openai", ModelRules: []ModelRule{{[]string{"gpt-5-mini"}}}}}}, "openai", ""},
		{"pending", Document{Mode: ModePending}, "openai", ""},
		{"provider mismatch", Document{Mode: ModeEnforced, Providers: []Provider{{Name: "anthropic", ModelRules: []ModelRule{{[]string{"claude-sonnet"}}}}}}, "openai", ""},
		{"wildcards only", Document{Mode: ModeEnforced, Providers: []Provider{{Name: "openai", ModelRules: []ModelRule{{[]string{"gpt-*", "gpt-?"}}}}}}, "openai", ""},
		{"both rules", Document{Mode: ModeEnforced, Providers: []Provider{{Name: "openai", ModelRules: []ModelRule{{[]string{"denied", "gpt-*"}}, {[]string{"gpt-5-mini", "gpt-5"}}}}}}, "openai", "gpt-5-mini"},
		{"disjoint rules", Document{Mode: ModeEnforced, Providers: []Provider{{Name: "openai", ModelRules: []ModelRule{{[]string{"gpt-4"}}, {[]string{"gpt-5-mini"}}}}}}, "openai", ""},
		{"requested provider only", Document{Mode: ModeEnforced, Providers: []Provider{{Name: "anthropic", ModelRules: []ModelRule{{[]string{"claude-sonnet"}}}}, {Name: "openai", ModelRules: []ModelRule{{[]string{"gpt-5-mini"}}}}}}, "openai", "gpt-5-mini"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.document.DefaultModelFor(test.provider); got != test.model {
				t.Fatalf("DefaultModelFor(%q) = %q, want %q", test.provider, got, test.model)
			}
		})
	}
}

func TestInvocationRecordWire(t *testing.T) {
	record := InvocationRecord{Provider: "openai", Model: "gpt-5-mini", Outcome: OutcomeAllowed, Status: 200, Usage: &Usage{PromptTokens: 1, CompletionTokens: 2}, Logging: &InvocationLogging{Conversation: "HashOnly", ToolCalls: "Off"}, DurationMs: 3}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"provider":"openai","model":"gpt-5-mini","outcome":"Allowed","status":200,"usage":{"promptTokens":1,"completionTokens":2},"logging":{"conversation":"HashOnly","toolCalls":"Off"},"durationMs":3}`
	if string(data) != want {
		t.Fatalf("invocation wire = %s, want %s", data, want)
	}
}
