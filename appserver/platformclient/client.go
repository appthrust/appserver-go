package platformclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

type Roles struct {
	IsConsoleAdmin bool `json:"isConsoleAdmin"`
	CanCreateApps  bool `json:"canCreateApps"`
}

type TeamAccess struct {
	Roles
	TeamID    string
	TeamSlug  string
	NotMember bool
}

type HTTPError struct {
	Path       string
	StatusCode int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("platform %s: HTTP %d", e.Path, e.StatusCode)
}

type cachedAccess struct {
	access  TeamAccess
	expires time.Time
}

type Client struct {
	origin    string
	ProjectID string
	http      *http.Client
	mu        sync.Mutex
	cache     map[string]cachedAccess
	teamSlug  string
}

// Option configures a Platform API client.
type Option func(*Client)

// WithHTTPClient reuses the client's transport and trust roots, not its timeout,
// redirect policy, or cookie jar. A nil transport uses a cloned default transport.
func WithHTTPClient(c *http.Client) Option {
	return func(client *Client) {
		client.http.Transport = c.Transport
		if client.http.Transport == nil {
			client.http.Transport = http.DefaultTransport.(*http.Transport).Clone()
		}
	}
}

func New(origin, projectID string, opts ...Option) *Client {
	client := &Client{origin: strings.TrimRight(origin, "/"), ProjectID: projectID,
		http:  &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		cache: map[string]cachedAccess{}}
	for _, opt := range opts {
		opt(client)
	}
	return client
}

func (c *Client) get(ctx context.Context, bearer, path string, target any) error {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+path, nil)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", bearer)
	r.Header.Set("Accept", "application/json")
	response, err := c.http.Do(r)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return &HTTPError{Path: path, StatusCode: response.StatusCode}
	}
	return json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(target)
}

type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Project reads the Project's display identity as the bearer's user.
func (c *Client) Project(ctx context.Context, bearer string) (Project, error) {
	var project Project
	if err := c.get(ctx, bearer, "/api/v1/projects/"+url.PathEscape(c.ProjectID), &project); err != nil {
		return Project{}, err
	}
	return project, nil
}

func (c *Client) Access(ctx context.Context, subject, bearer string) (TeamAccess, error) {
	c.mu.Lock()
	entry, found := c.cache[subject]
	teamSlug := c.teamSlug
	c.mu.Unlock()
	if found && time.Now().Before(entry.expires) {
		if entry.access.NotMember {
			entry.access.TeamSlug = teamSlug
		}
		return entry.access, nil
	}
	var project struct {
		TeamSlug string `json:"teamSlug"`
	}
	if err := c.get(ctx, bearer, "/api/v1/projects/"+url.PathEscape(c.ProjectID), &project); err != nil {
		var responseError *HTTPError
		if !errors.As(err, &responseError) ||
			(responseError.StatusCode != http.StatusUnauthorized && responseError.StatusCode != http.StatusForbidden && responseError.StatusCode != http.StatusNotFound) {
			return TeamAccess{}, err
		}
		access := TeamAccess{TeamSlug: teamSlug, NotMember: true}
		c.cacheAccess(subject, access)
		return access, nil
	}
	c.mu.Lock()
	c.teamSlug = project.TeamSlug
	c.mu.Unlock()
	var teams struct {
		Items []struct{ ID, Slug, Role string } `json:"items"`
	}
	if err := c.get(ctx, bearer, "/api/v1/teams", &teams); err != nil {
		return TeamAccess{}, err
	}
	if teams.Items == nil {
		return TeamAccess{}, fmt.Errorf("platform teams response has no items")
	}
	access := TeamAccess{TeamSlug: project.TeamSlug}
	for _, team := range teams.Items {
		if team.Slug == project.TeamSlug && project.TeamSlug != "" {
			access.TeamID = team.ID
			access.IsConsoleAdmin = team.Role == "Admin"
			access.CanCreateApps = access.IsConsoleAdmin || team.Role == "Editor"
			break
		}
	}
	c.cacheAccess(subject, access)
	return access, nil
}

func (c *Client) cacheAccess(subject string, access TeamAccess) {
	c.mu.Lock()
	now := time.Now()
	for key, cached := range c.cache {
		if !now.Before(cached.expires) {
			delete(c.cache, key)
		}
	}
	c.cache[subject] = cachedAccess{access: access, expires: now.Add(60 * time.Second)}
	c.mu.Unlock()
}

type DirectoryPerson struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
}

func (c *Client) Directory(ctx context.Context, bearer string, access TeamAccess, query string) ([]DirectoryPerson, error) {
	result := []DirectoryPerson{}
	if access.TeamID == "" {
		return result, nil
	}
	known := map[string]bool{}
	for _, suffix := range []string{"/members", "/directory-users"} {
		var response struct {
			Items []struct{ ID, Email, Name string } `json:"items"`
		}
		if err := c.get(ctx, bearer, "/api/v1/teams/"+url.PathEscape(access.TeamID)+suffix, &response); err != nil {
			return nil, err
		}
		if response.Items == nil {
			return nil, fmt.Errorf("platform directory response has no items")
		}
		for _, person := range response.Items {
			email := strings.ToLower(strings.TrimSpace(person.Email))
			if email == "" || known[email] || !strings.Contains(strings.ToLower(email+" "+person.Name), strings.ToLower(query)) {
				continue
			}
			known[email] = true
			result = append(result, DirectoryPerson{ID: person.ID, Email: email, DisplayName: person.Name})
		}
	}
	slices.SortFunc(result, func(a, b DirectoryPerson) int { return strings.Compare(a.Email, b.Email) })
	return result, nil
}

type Connection struct {
	Connected    bool    `json:"connected"`
	ConnectionID *string `json:"connectionId"`
}

type Settings struct {
	ProjectID         string     `json:"projectId"`
	TeamSlug          *string    `json:"teamSlug"`
	GitHub            Connection `json:"github"`
	Registry          Connection `json:"registry"`
	DefaultTemplateID string     `json:"defaultTemplateId"`
}

func (c *Client) Settings(ctx context.Context, bearer string, access TeamAccess) (Settings, error) {
	settings := Settings{ProjectID: c.ProjectID, DefaultTemplateID: "nextjs-postgres"}
	if access.TeamSlug != "" {
		settings.TeamSlug = &access.TeamSlug
	}
	for _, item := range []struct {
		path   string
		target *Connection
	}{
		{"/api/v1/projects/" + url.PathEscape(c.ProjectID) + "/source-connections", &settings.GitHub},
		{"/api/v1/registry-connections", &settings.Registry},
	} {
		var response struct {
			Data []struct{ ID, Status string } `json:"data"`
		}
		if err := c.get(ctx, bearer, item.path, &response); err != nil {
			return settings, err
		}
		if response.Data == nil {
			return settings, fmt.Errorf("platform connections response has no data")
		}
		for _, connection := range response.Data {
			if connection.Status == "ready" {
				item.target.Connected = true
				item.target.ConnectionID = &connection.ID
				break
			}
		}
	}
	return settings, nil
}

// AppInstallationDisplay is the definition's display metadata on an installation.
type AppInstallationDisplay struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
}

// ApplicationStackDefinition contains the catalog fields used by launchers.
type ApplicationStackDefinition struct {
	ID          string                      `json:"id"`
	Title       string                      `json:"title"`
	Description string                      `json:"description"`
	Locales     map[string]DefinitionLocale `json:"locales,omitempty"`
}

// DefinitionLocale contains the localized catalog copy used by launchers.
type DefinitionLocale struct {
	Title   string `json:"title,omitempty"`
	Tagline string `json:"tagline,omitempty"`
}

// AppInstallation is the public installation read model. Link addresses come
// from the platform, never from caller-side Service naming conventions.
type AppInstallation struct {
	ID               string                      `json:"id"`
	ProjectID        string                      `json:"projectId"`
	DefinitionID     string                      `json:"definitionId"`
	StackID          string                      `json:"stackId"`
	Display          AppInstallationDisplay      `json:"display"`
	Version          string                      `json:"version"`
	AvailableVersion string                      `json:"availableVersion,omitempty"`
	UpdatePolicy     string                      `json:"updatePolicy"`
	Phase            string                      `json:"phase"`
	URL              string                      `json:"url"`
	Dependencies     []AppInstallationDependency `json:"dependencies"`
	Dependents       []string                    `json:"dependents"`
	Links            []AppInstallationLink       `json:"links"`
	Capabilities     []string                    `json:"capabilities"`
}

type AppInstallationDependency struct {
	DefinitionID string `json:"definitionId"`
	Installation string `json:"installation,omitempty"`
	Resolved     bool   `json:"resolved"`
	Reason       string `json:"reason,omitempty"`
}

type listMeta struct {
	Total      int    `json:"total"`
	NextCursor string `json:"nextCursor"`
}

// ApplicationStackDefinitions reads the complete public catalog as the bearer's user.
func (c *Client) ApplicationStackDefinitions(ctx context.Context, bearer string) ([]ApplicationStackDefinition, error) {
	var response struct {
		Data []ApplicationStackDefinition `json:"data"`
		Meta listMeta                     `json:"meta"`
	}
	if err := c.get(ctx, bearer, "/api/v1/application-stack-definitions", &response); err != nil {
		return nil, err
	}
	if response.Data == nil {
		return nil, errors.New("platform application stack definitions response has no data")
	}
	if response.Meta.Total > len(response.Data) || response.Meta.NextCursor != "" {
		return nil, errors.New("platform application stack definitions response is truncated")
	}
	return response.Data, nil
}

// AppInstallations reads every installed built-in app in the Project as the bearer's user.
func (c *Client) AppInstallations(ctx context.Context, bearer string) ([]AppInstallation, error) {
	var response struct {
		Data []AppInstallation `json:"data"`
		Meta listMeta          `json:"meta"`
	}
	if err := c.get(ctx, bearer, "/api/v1/projects/"+url.PathEscape(c.ProjectID)+"/app-installations", &response); err != nil {
		return nil, err
	}
	if response.Data == nil {
		return nil, errors.New("platform app installations response has no data")
	}
	if response.Meta.Total > len(response.Data) || response.Meta.NextCursor != "" {
		return nil, errors.New("platform app installations response is truncated")
	}
	return response.Data, nil
}

type ApplicationStackPublish struct {
	PublicURL  string `json:"publicUrl"`
	TailnetURL string `json:"tailnetUrl"`
}

type ApplicationStack struct {
	ID             string                   `json:"id"`
	ApplicationID  string                   `json:"applicationId"`
	BranchID       string                   `json:"branchId"`
	WebComponentID string                   `json:"webComponentId"`
	State          string                   `json:"state"`
	Publish        *ApplicationStackPublish `json:"publish"`
}

// ApplicationStacks reads the complete stack list, including published URLs,
// as the bearer's user. It never derives addresses from application identities.
func (c *Client) ApplicationStacks(ctx context.Context, bearer string) ([]ApplicationStack, error) {
	var response struct {
		Data []ApplicationStack `json:"data"`
		Meta listMeta           `json:"meta"`
	}
	if err := c.get(ctx, bearer, "/api/v1/projects/"+url.PathEscape(c.ProjectID)+"/application-stacks", &response); err != nil {
		return nil, err
	}
	if response.Data == nil {
		return nil, errors.New("platform application stacks response has no data")
	}
	if response.Meta.Total > len(response.Data) || response.Meta.NextCursor != "" {
		return nil, errors.New("platform application stacks response is truncated")
	}
	return response.Data, nil
}
