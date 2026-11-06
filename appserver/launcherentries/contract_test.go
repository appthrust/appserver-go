package launcherentries

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/appthrust/appserver-go/appserver/link"
)

type contractSchema struct {
	Ref        string                    `json:"$ref"`
	Type       string                    `json:"type"`
	Required   []string                  `json:"required"`
	Properties map[string]contractSchema `json:"properties"`
	Enum       []string                  `json:"enum"`
	Items      *contractSchema           `json:"items"`
	MaxLength  int                       `json:"maxLength"`
}

func TestEntryJSONMatchesDocument(t *testing.T) {
	var doc struct {
		Components struct {
			Schemas map[string]contractSchema `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(Document, &doc); err != nil {
		t.Fatal(err)
	}
	entrySchema := doc.Components.Schemas["Entry"]
	if !slices.Equal(entrySchema.Properties["state"].Enum, []string{string(Ready), string(Preparing), string(Restricted)}) {
		t.Fatalf("state enum differs from generated values: %v", entrySchema.Properties["state"].Enum)
	}
	if !slices.Equal(entrySchema.Properties["relation"].Enum, []string{string(Owner), string(Group), string(Project)}) {
		t.Fatalf("relation enum differs from generated values: %v", entrySchema.Properties["relation"].Enum)
	}
	if !slices.Equal(entrySchema.Required, []string{"id", "name", "description", "icon", "state", "relation", "tags"}) {
		t.Fatalf("required entry fields = %v", entrySchema.Required)
	}
	entry := Entry{
		ID:          "app-1",
		Name:        "Expenses",
		Description: "Submit expenses",
		Icon:        "receipt",
		URL:         "https://expenses.example.test",
		DetailURL:   "https://console.example.test/finance/expenses",
		State:       Ready,
		Relation:    Group,
		Group:       &GroupRef{ID: "finance", Name: "Finance", Path: "/finance"},
		Tags:        []string{"finance"},
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	fields := assertSchemaKeys(t, encoded, entrySchema, false)
	if string(fields["state"]) != `"ready"` || string(fields["relation"]) != `"group"` {
		t.Fatalf("unexpected enum JSON: %s", encoded)
	}
	assertSchemaKeys(t, fields["group"], doc.Components.Schemas["GroupRef"], false)
	if entrySchema.Properties["group"].Ref != "#/components/schemas/GroupRef" {
		t.Fatalf("group schema = %+v", entrySchema.Properties["group"])
	}
	if tags := entrySchema.Properties["tags"]; tags.Type != "array" || tags.Items == nil || tags.Items.Type != "string" {
		t.Fatalf("tags schema = %+v", tags)
	}
	entry.URL, entry.DetailURL, entry.Group = "", "", nil
	entry.State, entry.Relation, entry.Tags = Preparing, Owner, []string{}
	encoded, err = json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	fields = assertSchemaKeys(t, encoded, entrySchema, true)
	if string(fields["tags"]) != "[]" || string(fields["state"]) != `"preparing"` || string(fields["relation"]) != `"owner"` {
		t.Fatalf("unexpected minimal entry JSON: %s", encoded)
	}
	listJSON, err := json.Marshal(EntryList{Items: []Entry{entry}})
	if err != nil {
		t.Fatal(err)
	}
	assertSchemaKeys(t, listJSON, doc.Components.Schemas["EntryList"], false)
	items := doc.Components.Schemas["EntryList"].Properties["items"]
	if items.Type != "array" || items.Items == nil || items.Items.Ref != "#/components/schemas/Entry" {
		t.Fatalf("items schema = %+v", items)
	}
	var roundTrip EntryList
	if err := json.Unmarshal(listJSON, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(roundTrip.Items, []Entry{entry}) {
		t.Fatalf("entry round trip = %+v", roundTrip.Items)
	}
	errorJSON, err := json.Marshal(Error{Error: "forbidden", Message: "Access denied"})
	if err != nil {
		t.Fatal(err)
	}
	assertSchemaKeys(t, errorJSON, doc.Components.Schemas["Error"], false)
}

func assertSchemaKeys(t *testing.T, encoded []byte, schema contractSchema, requiredOnly bool) map[string]json.RawMessage {
	t.Helper()
	if schema.Type != "object" {
		t.Fatalf("expected an object schema, got %+v", schema)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	var got, want []string
	for key := range fields {
		got = append(got, key)
	}
	for key := range schema.Properties {
		if !requiredOnly || slices.Contains(schema.Required, key) {
			want = append(want, key)
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("JSON keys = %v; schema keys = %v", got, want)
	}
	for _, key := range schema.Required {
		if _, ok := fields[key]; !ok {
			t.Fatalf("missing required property %q", key)
		}
	}
	return fields
}

func TestCapabilityDocumentAndOperation(t *testing.T) {
	var doc struct {
		Capability string `json:"x-appthrust-capability"`
		Definition string `json:"x-appthrust-definition"`
		Servers    []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Paths map[string]map[string]struct {
			ID         string `json:"operationId"`
			Link       bool   `json:"x-appthrust-link"`
			ResultPath string `json:"x-appthrust-result-path"`
			Parameters []struct {
				Name     string         `json:"name"`
				In       string         `json:"in"`
				Required bool           `json:"required"`
				Schema   contractSchema `json:"schema"`
			} `json:"parameters"`
			Responses map[string]struct {
				Content map[string]struct {
					Schema contractSchema `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(Document, &doc); err != nil {
		t.Fatal(err)
	}
	if Capability != "launcher.entries/v1" || doc.Capability != Capability || doc.Definition != "" {
		t.Fatalf("unexpected contract identity: capability=%q definition=%q", doc.Capability, doc.Definition)
	}
	if len(doc.Servers) != 1 || doc.Servers[0].URL != "" {
		t.Fatalf("capability must target the provider root: %+v", doc.Servers)
	}
	if len(doc.Paths) != 1 || len(doc.Paths["/launcher/entries"]) != 1 {
		t.Fatalf("unexpected paths: %+v", doc.Paths)
	}
	op, ok := doc.Paths["/launcher/entries"]["get"]
	if !ok || op.ID != "listEntries" || !op.Link || op.ResultPath != "items" {
		t.Fatalf("unexpected operation: %+v", op)
	}
	if len(op.Parameters) != 1 {
		t.Fatalf("unexpected parameters: %+v", op.Parameters)
	}
	q := op.Parameters[0]
	if q.Name != "q" || q.In != "query" || q.Required || q.Schema.Type != "string" || q.Schema.MaxLength != 128 {
		t.Fatalf("unexpected query contract: %+v", q)
	}
	for status, model := range map[string]string{"200": "EntryList", "400": "Error", "401": "Error", "403": "Error", "503": "Error"} {
		if ref := op.Responses[status].Content["application/json"].Schema.Ref; ref != "#/components/schemas/"+model {
			t.Errorf("%s response schema = %q", status, ref)
		}
	}
	want := link.Operation{
		Capability: Capability,
		ID:         "listEntries",
		Method:     "GET",
		Base:       "",
		Path:       "/launcher/entries",
		ResultPath: "items",
		Params:     []link.Param{{Name: "q", In: "query", Type: "string"}},
	}
	if !reflect.DeepEqual(ListEntries, want) || !reflect.DeepEqual(Operations, []link.Operation{want}) {
		t.Fatalf("generated operation differs from the capability contract: %+v", ListEntries)
	}
}
