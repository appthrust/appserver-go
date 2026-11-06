package platformclient

import (
	"context"
	"net/url"
)

type AppInstallationLink struct {
	DefinitionID string   `json:"definitionId"`
	Required     bool     `json:"required"`
	Capabilities []string `json:"capabilities"`
	State        string   `json:"state"`
	InternalURL  string   `json:"internalUrl,omitempty"`
	PublicURL    string   `json:"publicUrl,omitempty"`
}

func (c *Client) AppInstallation(ctx context.Context, bearer, installationID string) (AppInstallation, error) {
	var installation AppInstallation
	err := c.get(ctx, bearer, "/api/v1/projects/"+url.PathEscape(c.ProjectID)+"/app-installations/"+url.PathEscape(installationID), &installation)
	return installation, err
}
