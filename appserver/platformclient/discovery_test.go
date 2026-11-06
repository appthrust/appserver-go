package platformclient

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/appthrust/appserver-go/aigatewaydiscovery"
	"github.com/stretchr/testify/require"
)

func TestGatewayDiscoveryNeverUsesCallerAuthority(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		require.Equal(t, aigatewaydiscovery.Path, r.URL.Path)
		require.Equal(t, "pj-test", r.URL.Query().Get("projectId"))
		require.Equal(t, "Bearer workload", r.Header.Get("Authorization"))
		fmt.Fprint(w, `{"links":[{"definitionId":"inference","state":"Ready","internalUrl":"http://production.pj-test.svc"}]}`)
	}))
	defer server.Close()
	client := NewGatewayDiscovery(server.URL, "pj-test", "workload")
	for _, bearer := range []string{"", "Bearer caller-knowledge-assertion", "Bearer another-user"} {
		result, err := client.AppInstallation(t.Context(), bearer, "ai-gateway")
		require.NoError(t, err)
		require.Len(t, result.Links, 1)
	}
	_, err := client.AppInstallation(t.Context(), "Bearer caller", "knowledge")
	require.Error(t, err)
	_, err = NewGatewayDiscovery(server.URL, "pj-test", "").AppInstallation(t.Context(), "Bearer caller", "ai-gateway")
	require.Error(t, err)
	require.Equal(t, 3, calls)
}
