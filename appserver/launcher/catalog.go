// Package launcher exposes the Project's installed marketplace apps to app SPAs.
package launcher

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/appthrust/appserver-go/appserver/platformclient"
)

const (
	cacheTTL    = 60 * time.Second
	maxSubjects = 1024
)

// Entry joins an installed app with its catalog display metadata.
type Entry struct {
	DefinitionID string `json:"definitionId"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Icon         string `json:"icon"`
	URL          string `json:"url"`
	Phase        string `json:"phase"`
	Current      bool   `json:"current"`
}

type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Snapshot is the Project identity and its installed app read-model join.
type Snapshot struct {
	Project Project `json:"project"`
	Entries []Entry `json:"entries"`
}

type cachedSnapshot struct {
	snapshot Snapshot
	expires  time.Time
}

// Catalog caches successful read-model joins for each authenticated subject.
type Catalog struct {
	platform *platformclient.Client
	self     string
	now      func() time.Time
	mu       sync.Mutex
	cache    map[string]cachedSnapshot
}

func NewCatalog(platform *platformclient.Client, self string) *Catalog {
	return &Catalog{platform: platform, self: self, now: time.Now, cache: make(map[string]cachedSnapshot)}
}

// Load returns the Project and every installed app; URLs are copied from the read model.
// Returned entries are owned by the caller and may be modified without changing the cache.
func (c *Catalog) Load(ctx context.Context, subject, bearer string) (Snapshot, error) {
	c.mu.Lock()
	cached, found := c.cache[subject]
	if found && c.now().Before(cached.expires) {
		snapshot := cached.snapshot
		snapshot.Entries = slices.Clone(snapshot.Entries)
		c.mu.Unlock()
		return snapshot, nil
	}
	c.mu.Unlock()

	project, err := c.platform.Project(ctx, bearer)
	if err != nil {
		return Snapshot{}, classifyError(err)
	}
	if project.Name == "" {
		project.Name = project.ID
	}
	installations, err := c.platform.AppInstallations(ctx, bearer)
	if err != nil {
		return Snapshot{}, classifyError(err)
	}
	definitions, err := c.platform.ApplicationStackDefinitions(ctx, bearer)
	if err != nil {
		return Snapshot{}, classifyError(err)
	}
	byID := make(map[string]platformclient.ApplicationStackDefinition, len(definitions))
	for _, definition := range definitions {
		byID[definition.ID] = definition
	}
	entries := make([]Entry, 0, len(installations))
	for _, installation := range installations {
		display := installation.Display
		definition := byID[installation.DefinitionID]
		if display.Name == "" {
			display.Name = definition.Title
		}
		if display.Name == "" {
			display.Name = installation.DefinitionID
		}
		if display.Description == "" {
			display.Description = definition.Description
		}
		entries = append(entries, Entry{
			DefinitionID: installation.DefinitionID, Name: display.Name, Description: display.Description,
			Icon: display.Icon, URL: installation.URL, Phase: installation.Phase,
			Current: installation.DefinitionID == c.self,
		})
	}
	slices.SortFunc(entries, func(a, b Entry) int {
		if order := strings.Compare(a.Name, b.Name); order != 0 {
			return order
		}
		return strings.Compare(a.DefinitionID, b.DefinitionID)
	})

	snapshot := Snapshot{Project: Project{ID: project.ID, Name: project.Name}, Entries: entries}
	c.mu.Lock()
	if _, found := c.cache[subject]; !found && len(c.cache) >= maxSubjects {
		var oldestSubject string
		var oldestExpiry time.Time
		for key, entry := range c.cache {
			if oldestExpiry.IsZero() || entry.expires.Before(oldestExpiry) {
				oldestSubject, oldestExpiry = key, entry.expires
			}
		}
		delete(c.cache, oldestSubject)
	}
	c.cache[subject] = cachedSnapshot{
		snapshot: Snapshot{Project: snapshot.Project, Entries: slices.Clone(entries)},
		expires:  c.now().Add(cacheTTL),
	}
	c.mu.Unlock()
	return snapshot, nil
}

// Invalidate removes a subject's cached snapshot.
func (c *Catalog) Invalidate(subject string) {
	c.mu.Lock()
	delete(c.cache, subject)
	c.mu.Unlock()
}
