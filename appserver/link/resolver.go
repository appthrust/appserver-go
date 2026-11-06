package link

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/appthrust/appserver-go/appserver/platformclient"
)

const cacheTTL = 60 * time.Second

type cachedBinding struct {
	binding Binding
	expires time.Time
}

type installationReader interface {
	AppInstallation(context.Context, string, string) (platformclient.AppInstallation, error)
}

type Resolver struct {
	platform    installationReader
	self        string
	env         func(string) (string, bool)
	required    map[string]Required
	mu          sync.Mutex
	cache       map[string]cachedBinding
	definitions []string
	listExpires time.Time
	now         func() time.Time
}

func NewResolver(platform installationReader, self string, env func(string) (string, bool), required map[string]Required) *Resolver {
	if env == nil {
		env = os.LookupEnv
	}
	return &Resolver{platform: platform, self: self, env: env, required: maps.Clone(required), cache: make(map[string]cachedBinding), now: time.Now}
}

func (r *Resolver) fromEnv(definition string) (Binding, bool) {
	names, required := r.required[definition]
	if !required {
		return Binding{}, false
	}
	internal, set := r.env(names.URLEnv)
	if !set || internal == "" {
		return Binding{}, false
	}
	public, _ := r.env(names.PublicURLEnv)
	return Binding{Definition: definition, Required: true, State: StateReady, InternalURL: internal, PublicURL: public}, true
}

func (r *Resolver) Resolve(ctx context.Context, bearer, definition string) (Binding, error) {
	if binding, ok := r.fromEnv(definition); ok {
		return binding, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.cache[definition]; ok && r.now().Before(entry.expires) {
		return cloneBinding(entry.binding), nil
	}
	if err := r.refresh(ctx, bearer); err != nil {
		return Binding{}, err
	}
	if entry, ok := r.cache[definition]; ok {
		return cloneBinding(entry.binding), nil
	}
	_, required := r.required[definition]
	binding := Binding{Definition: definition, Required: required, State: StateAbsent}
	r.cache[definition] = cachedBinding{binding, r.now().Add(cacheTTL)}
	return binding, nil
}

// List includes both required dependencies and optional links. Environment-bound
// dependencies override their read-model entries, just as they do in Resolve.
func (r *Resolver) List(ctx context.Context, bearer string) ([]Binding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.now().Before(r.listExpires) {
		if err := r.refresh(ctx, bearer); err != nil {
			return nil, err
		}
	}
	definitions := slices.Clone(r.definitions)
	for definition := range r.required {
		if !slices.Contains(definitions, definition) {
			definitions = append(definitions, definition)
		}
	}
	slices.Sort(definitions)
	bindings := make([]Binding, 0, len(definitions))
	for _, definition := range definitions {
		if binding, ok := r.fromEnv(definition); ok {
			bindings = append(bindings, binding)
		} else if entry, ok := r.cache[definition]; ok {
			bindings = append(bindings, cloneBinding(entry.binding))
		} else {
			bindings = append(bindings, Binding{Definition: definition, Required: true, State: StateAbsent})
		}
	}
	return bindings, nil
}

// ByCapability includes every state of the matching read-model bindings.
// Environment-bound dependencies have no capabilities and are excluded.
func (r *Resolver) ByCapability(ctx context.Context, bearer, capability string) ([]Binding, error) {
	bindings, err := r.List(ctx, bearer)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(bindings, func(binding Binding) bool {
		return !slices.Contains(binding.Capabilities, capability)
	}), nil
}

func cloneBinding(binding Binding) Binding {
	binding.Capabilities = slices.Clone(binding.Capabilities)
	return binding
}

func (r *Resolver) Invalidate(definition string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cache, definition)
	r.listExpires = time.Time{}
}

// refresh is called with mu held so concurrent misses share one platform read.
func (r *Resolver) refresh(ctx context.Context, bearer string) error {
	if r.platform == nil {
		return ErrUnavailable
	}
	installation, err := r.platform.AppInstallation(ctx, bearer, r.self)
	if err != nil {
		var response *platformclient.HTTPError
		if errors.As(err, &response) {
			switch {
			case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
				return &DeniedError{Status: response.StatusCode}
			case response.StatusCode >= 400 && response.StatusCode < 500:
				return &RejectedError{Status: response.StatusCode}
			}
		}
		return fmt.Errorf("%w: platform lookup: %v", ErrUnavailable, err)
	}
	expires := r.now().Add(cacheTTL)
	clear(r.cache)
	r.definitions = r.definitions[:0]
	for _, item := range installation.Links {
		binding := Binding{Definition: item.DefinitionID, Required: item.Required, Capabilities: slices.Clone(item.Capabilities), State: State(item.State), InternalURL: item.InternalURL, PublicURL: item.PublicURL}
		slices.Sort(binding.Capabilities)
		r.cache[binding.Definition] = cachedBinding{binding, expires}
		r.definitions = append(r.definitions, binding.Definition)
	}
	r.listExpires = expires
	return nil
}
