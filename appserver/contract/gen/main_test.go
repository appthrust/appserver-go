package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperationInventory(t *testing.T) {
	document := []byte(`{"openapi":"3.0.3","x-appthrust-definition":"builder-console","servers":[{"url":"/api/console"}],"paths":{"/apps/{id}":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"get":{"operationId":"getApp","x-appthrust-link":true,"summary":"Get app","parameters":[{"$ref":"#/components/parameters/Query"}]}},"/hidden":{"get":{"operationId":"hidden"}},"/search":{"post":{"operationId":"search","x-appthrust-link":true,"x-appthrust-result-path":"items","requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Search"}}}}}}},"components":{"parameters":{"Query":{"name":"q","in":"query","schema":{"type":"string"}}},"schemas":{"Search":{"type":"object","required":["query"],"properties":{"topK":{"type":"integer"},"query":{"type":"string"}}}}}}`)
	first, err := emitOperations("console", document)
	if err != nil {
		t.Fatal(err)
	}
	second, err := emitOperations("console", document)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("generation is not deterministic")
	}
	for _, expected := range []string{`var GetApp = link.Operation{Definition: "builder-console"`, `Base: "/api/console"`, `Path: "/apps/{id}"`, `{Name: "id", In: "path", Type: "string", Required: true}`, `{Name: "query", In: "body", Type: "string", Required: true}`, `ResultPath: "items"`, `var Operations = []link.Operation{GetApp, Search}`, `//go:embed openapi.json`} {
		if !strings.Contains(string(first), expected) {
			t.Errorf("missing %s in %s", expected, first)
		}
	}
	if strings.Contains(string(first), "Hidden") {
		t.Error("non-link operation emitted")
	}
}

func TestInvalidContract(t *testing.T) {
	for _, doc := range []string{
		`{}`,
		`{"x-appthrust-definition":"directory","servers":[{"url":"https://elsewhere"}]}`,
		`{"x-appthrust-definition":"directory","servers":[{"url":"/api/directory/v1"}],"paths":{"/one":{"get":{"operationId":"","x-appthrust-link":true}}}}`,
		`{"x-appthrust-definition":"directory","servers":[{"url":"/api/directory/v1"}],"paths":{"/one":{"get":{"operationId":"same","x-appthrust-link":true},"post":{"operationId":"same","x-appthrust-link":true}}}}`,
	} {
		if _, err := emitOperations("directory", []byte(doc)); err == nil {
			t.Fatalf("accepted %s", doc)
		}
	}
}

func TestDefinitionOperationInventoryUnchanged(t *testing.T) {
	for _, pkg := range []string{"console", "directory"} {
		t.Run(pkg, func(t *testing.T) {
			doc, err := os.ReadFile(filepath.Join("..", pkg, "openapi.json"))
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("..", pkg, "ops.gen.go"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := emitOperations(pkg, doc)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("definition-mode output differs from committed %s/ops.gen.go:\n%s", pkg, got)
			}
		})
	}
}

func TestCapabilityOperationInventory(t *testing.T) {
	for _, base := range []string{"", "/api/entries/v1"} {
		t.Run(fmt.Sprintf("base=%q", base), func(t *testing.T) {
			doc := []byte(fmt.Sprintf(`{"x-appthrust-capability":"launcher.entries/v1","servers":[{"url":%q}],"paths":{"/launcher/entries":{"get":{"operationId":"listEntries","x-appthrust-link":true,"x-appthrust-result-path":"items","parameters":[{"name":"q","in":"query","schema":{"type":"string","maxLength":128}}]}}}}`, base))
			first, err := emitOperations("launcherentries", doc)
			if err != nil {
				t.Fatal(err)
			}
			second, err := emitOperations("launcherentries", doc)
			if err != nil || !bytes.Equal(first, second) {
				t.Fatal("capability generation is not deterministic")
			}
			for _, expected := range []string{
				`const Capability = "launcher.entries/v1"`,
				`var ListEntries = link.Operation{Capability: "launcher.entries/v1"`,
				`ID: "listEntries", Method: "GET"`,
				fmt.Sprintf("Base: %q", base),
				`Path: "/launcher/entries", ResultPath: "items"`,
				`{Name: "q", In: "query", Type: "string", Required: false}`,
				`var Operations = []link.Operation{ListEntries}`,
			} {
				if !strings.Contains(string(first), expected) {
					t.Errorf("missing %s in %s", expected, first)
				}
			}
			if strings.Contains(string(first), "Definition:") {
				t.Errorf("capability operation contains a definition: %s", first)
			}
		})
	}
}

func TestInvalidCapabilityContract(t *testing.T) {
	for _, doc := range []string{
		`{"x-appthrust-definition":"directory","servers":[{"url":""}]}`,
		`{"x-appthrust-definition":"directory","x-appthrust-capability":"launcher.entries/v1","servers":[{"url":"/api"}]}`,
		`{"x-appthrust-capability":true,"servers":[{"url":""}]}`,
		`{"x-appthrust-capability":"","servers":[{"url":""}]}`,
		`{"x-appthrust-capability":"launcher.entries/v1"}`,
		`{"x-appthrust-capability":"launcher.entries/v1","servers":[{"url":"https://elsewhere"}]}`,
		`{"x-appthrust-capability":"launcher.entries/v1","servers":[{"url":"//elsewhere"}]}`,
		`{"x-appthrust-capability":"launcher.entries/v1","servers":[{"url":"api/entries"}]}`,
		`{"x-appthrust-capability":"launcher.entries/v1","servers":[{"url":"/api?query"}]}`,
		`{"x-appthrust-capability":"launcher.entries/v1","servers":[{"url":"/api#fragment"}]}`,
		`{"x-appthrust-capability":"launcher.entries/v1","servers":[{"url":"/api/{version}"}]}`,
		`{"x-appthrust-capability":"launcher.entries/v1","servers":[{"url":""}],"paths":{"/launcher/entries":{"get":{"operationId":"capability","x-appthrust-link":true}}}}`,
	} {
		if _, err := emitOperations("launcherentries", []byte(doc)); err == nil {
			t.Fatalf("accepted %s", doc)
		}
	}
}
