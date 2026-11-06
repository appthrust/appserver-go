package chatcompletions

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/appthrust/appserver-go/appserver/link"
)

type contractSchema struct {
	Ref                  string                    `json:"$ref"`
	Type                 string                    `json:"type"`
	Required             []string                  `json:"required"`
	Properties           map[string]contractSchema `json:"properties"`
	Items                *contractSchema           `json:"items"`
	AdditionalProperties bool                      `json:"additionalProperties"`
}

func TestCapabilityDocumentAndOperations(t *testing.T) {
	var doc struct {
		Capability string `json:"x-appthrust-capability"`
		Definition string `json:"x-appthrust-definition"`
		Servers    []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Security []any `json:"security"`
		Paths    map[string]map[string]struct {
			ID        string `json:"operationId"`
			Link      bool   `json:"x-appthrust-link"`
			Responses map[string]struct {
				Content map[string]struct {
					Schema contractSchema `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"paths"`
		Components struct {
			Schemas map[string]contractSchema `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(Document, &doc); err != nil {
		t.Fatal(err)
	}
	if Capability != "chat-completions.openai/v1" || doc.Capability != Capability || doc.Definition != "" || len(doc.Security) != 0 {
		t.Fatalf("incorrect capability identity/auth: %+v", doc)
	}
	if len(doc.Servers) != 1 || doc.Servers[0].URL != "" || len(doc.Paths) != 4 {
		t.Fatalf("incorrect provider root/routes: %+v", doc)
	}
	chat := doc.Paths["/v1/chat/completions"]["post"]
	if chat.ID != "createChatCompletion" || !chat.Link {
		t.Fatalf("chat operation = %+v", chat)
	}
	if chat.Responses["200"].Content["application/json"].Schema.Ref != "#/components/schemas/ChatCompletion" || chat.Responses["200"].Content["text/event-stream"].Schema.Type != "string" {
		t.Fatalf("chat response media = %+v", chat.Responses)
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		if _, ok := doc.Paths[path]["get"].Responses["200"]; !ok {
			t.Fatalf("missing probe %s", path)
		}
	}
	if !slices.Equal(doc.Components.Schemas["ChatRequest"].Required, []string{"messages"}) {
		t.Fatal("model must remain optional")
	}
	if len(doc.Components.Schemas["Delta"].Required) != 0 {
		t.Fatal("a content delta must not require a role")
	}
	model := doc.Components.Schemas["Model"]
	if !model.AdditionalProperties {
		t.Fatal("model entries must allow provider extensions")
	}
	for _, field := range []string{"context_window", "appthrust.io/maxPromptTokens"} {
		if model.Properties[field].Type != "integer" || slices.Contains(model.Required, field) {
			t.Fatalf("model field %q must be an optional integer", field)
		}
	}
	want := []link.Operation{
		{Capability: Capability, ID: "createChatCompletion", Method: "POST", Path: "/v1/chat/completions", Params: []link.Param{
			{Name: "messages", In: "body", Type: "array", Required: true},
			{Name: "model", In: "body", Type: "string"},
			{Name: "stream", In: "body", Type: "boolean"},
			{Name: "stream_options", In: "body", Type: "object"},
		}},
		{Capability: Capability, ID: "listModels", Method: "GET", Path: "/v1/models", ResultPath: "data", Params: []link.Param{}},
	}
	if !reflect.DeepEqual(Operations, want) || !reflect.DeepEqual(CreateChatCompletion, want[0]) || !reflect.DeepEqual(ListModels, want[1]) {
		t.Fatalf("generated operations = %+v", Operations)
	}
}

func TestGeneratedOpenAIWireShapes(t *testing.T) {
	request := ChatRequest{Messages: []Message{{Role: "user", Content: "hello"}}}
	request.Set("temperature", 0.5)
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, present := fields["model"]; present || len(fields) != 2 || string(fields["temperature"]) != "0.5" {
		t.Fatalf("optional model/additional fields = %s", encoded)
	}
	var roundTrip ChatRequest
	if err := json.Unmarshal(encoded, &roundTrip); err != nil || !reflect.DeepEqual(request, roundTrip) {
		t.Fatalf("request round trip = %+v, %v", roundTrip, err)
	}
	var completion ChatCompletion
	if err := json.Unmarshal([]byte(`{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`), &completion); err != nil {
		t.Fatal(err)
	}
	if completion.ID != "c1" || completion.Usage == nil || completion.Usage.TotalTokens != 3 || completion.Choices[0].Message.Content != "hello" {
		t.Fatalf("completion = %+v", completion)
	}
	var chunk ChatCompletionChunk
	if err := json.Unmarshal([]byte(`{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":null}]}`), &chunk); err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(chunk.Choices[0].Delta)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"content":"hi"}` {
		t.Fatalf("delta must not invent role: %s", encoded)
	}
	list := ModelList{Object: "list", Data: []Model{{ID: "m", Object: "model", Created: 0, OwnedBy: "local"}}}
	encoded, err = json.Marshal(list)
	if err != nil || string(encoded) != `{"data":[{"created":0,"id":"m","object":"model","owned_by":"local"}],"object":"list"}` {
		t.Fatalf("models wire = %s, %v", encoded, err)
	}
}

func TestGeneratedModelExtensions(t *testing.T) {
	const raw = `{"appthrust.io/maxPromptTokens":3000,"context_window":16384,"created":0,"id":"local-model","object":"model","owned_by":"appthrust","vendor":{"feature":true}}`
	var model Model
	if err := json.Unmarshal([]byte(raw), &model); err != nil {
		t.Fatal(err)
	}
	if model.ContextWindow == nil || *model.ContextWindow != 16384 || model.MaxPromptTokens == nil || *model.MaxPromptTokens != 3000 {
		t.Fatalf("model capabilities=%+v", model)
	}
	if value, ok := model.Get("vendor"); !ok || !reflect.DeepEqual(value, map[string]any{"feature": true}) {
		t.Fatalf("unknown model extension=%v present=%t", value, ok)
	}
	encoded, err := json.Marshal(model)
	if err != nil || string(encoded) != raw {
		t.Fatalf("model round trip=%s err=%v", encoded, err)
	}
}
