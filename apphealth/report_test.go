package apphealth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name         string
		capabilities []Capability
		declared     []string
		want         string
	}{
		{"serving", []Capability{{Name: "search", State: StateServing}}, []string{"search"}, ""},
		{"unknown state", []Capability{{Name: "search", State: "Ready"}}, nil, "unknown state"},
		{"unknown reason", []Capability{{Name: "search", State: StateUnknown, Reason: "SecretError"}}, nil, "unknown reason"},
		{"missing", []Capability{{Name: "search", State: StateServing}}, []string{"search", "ask"}, "missing declared capability"},
		{"oversize", []Capability{{Name: "search", State: StateFailing, Message: strings.Repeat("界", 86)}}, nil, "exceeds 256 bytes"},
		{"duplicate", []Capability{{Name: "search", State: StateServing}, {Name: "search", State: StateFailing}}, nil, "duplicate"},
		{"undeclared allowed", []Capability{{Name: "future", State: StateUnknown, Reason: ReasonNoEvidence}}, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := (Report{Capabilities: tc.capabilities}).Validate(tc.declared)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestReportJSON(t *testing.T) {
	r := Report{Release: Release{ArtifactDigest: "sha256:digest", ReleaseVersion: "v1"}, ObservedAt: time.Date(2026, 10, 25, 1, 40, 0, 0, time.UTC), Capabilities: []Capability{{Name: "search", State: StateServing}}}
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"release":{"artifactDigest":"sha256:digest","releaseVersion":"v1"},"observedAt":"2026-10-25T01:40:00Z","capabilities":[{"name":"search","state":"Serving"}]}`
	if string(body) != want {
		t.Fatalf("report = %s", body)
	}
}
