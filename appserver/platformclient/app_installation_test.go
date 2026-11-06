package platformclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestAppInstallationReadModel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/api/v1/projects/pj-test/app-installations/caller%2Fid" || r.Header.Get("Authorization") != "Bearer viewer" {
			t.Errorf("unexpected request %s %v", r.URL, r.Header)
		}
		fmt.Fprint(w, `{"id":"caller/id","definitionId":"caller","phase":"Ready","url":"https://caller.example","version":"1.4.0","display":{"name":"Caller","description":"An installed app","icon":"caller"},"dependencies":[{"definitionId":"directory","resolved":false,"reason":"DependencyNotReady"}],"dependents":["portal"],"capabilities":["launcher.entries/v1"],"links":[{"definitionId":"directory","required":true,"capabilities":["launcher.entries/v1"],"state":"Ready","internalUrl":"http://directory.internal","publicUrl":"https://directory.example"}]}`)
	}))
	defer server.Close()
	installation, err := New(server.URL, "pj-test").AppInstallation(context.Background(), "Bearer viewer", "caller/id")
	if err != nil || installation.ID != "caller/id" || installation.DefinitionID != "caller" || installation.Phase != "Ready" || installation.URL != "https://caller.example" || installation.Version != "1.4.0" || len(installation.Links) != 1 {
		t.Fatalf("installation=%+v err=%v", installation, err)
	}
	if installation.Display.Name != "Caller" || !slices.Equal(installation.Dependents, []string{"portal"}) || !slices.Equal(installation.Capabilities, []string{"launcher.entries/v1"}) || len(installation.Dependencies) != 1 || installation.Dependencies[0].Resolved || installation.Dependencies[0].Reason != "DependencyNotReady" {
		t.Fatalf("installation observations=%+v", installation)
	}
	binding := installation.Links[0]
	if binding.DefinitionID != "directory" || !binding.Required || !slices.Equal(binding.Capabilities, []string{"launcher.entries/v1"}) || binding.State != "Ready" || binding.InternalURL != "http://directory.internal" || binding.PublicURL != "https://directory.example" {
		t.Fatalf("link=%+v", binding)
	}
}

func TestAppInstallationRetainsPlatformHTTPStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer server.Close()
	_, err := New(server.URL, "pj-test").AppInstallation(context.Background(), "Bearer viewer", "caller")
	var response *HTTPError
	if !errors.As(err, &response) || response.StatusCode != http.StatusForbidden {
		t.Fatalf("error=%v", err)
	}
}
