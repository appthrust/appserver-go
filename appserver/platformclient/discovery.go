package platformclient

import (
	"context"
	"errors"
	"net/url"

	"github.com/appthrust/appserver-go/aigatewaydiscovery"
)

type GatewayDiscovery struct {
	client *Client
	key    string
}

func NewGatewayDiscovery(origin, projectID, key string, opts ...Option) *GatewayDiscovery {
	return &GatewayDiscovery{client: New(origin, projectID, opts...), key: key}
}

// AppInstallation deliberately ignores the caller bearer. The only permitted
// projection is the same-Project Gateway's links; no user-token fallback exists.
func (d *GatewayDiscovery) AppInstallation(ctx context.Context, _ string, definition string) (AppInstallation, error) {
	if definition != "ai-gateway" || d.key == "" || d.client.ProjectID == "" {
		return AppInstallation{}, errors.New("gateway discovery workload credential is required")
	}
	var result AppInstallation
	err := d.client.get(ctx, "Bearer "+d.key, aigatewaydiscovery.Path+"?projectId="+url.QueryEscape(d.client.ProjectID), &result)
	return result, err
}
