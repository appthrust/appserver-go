package accesskey

import (
	"context"
	"time"
)

// Key is a storage-independent record populated by CR or database adapters.
// Space is empty when the referenced space no longer exists.
type Key struct {
	Name, Space, Audience, Project string
	Hash                           Hash
	Subject                        Subject
	Scopes                         []string
	ExpiresAt                      time.Time // Zero means no expiry.
	Enabled                        bool
	RevokedAt                      time.Time // Zero means not revoked.
	SpaceScopes, SpaceRetired      []string
}

type KeyLookup interface {
	ByHash(ctx context.Context, hash Hash) (*Key, bool, error)
}

// Verify parses before looking up a hash. Malformed credentials are NotFound,
// not lookup failures, and never reach the store.
func Verify(ctx context.Context, raw string, now time.Time, lookup KeyLookup) (Decision, error) {
	secret, err := Parse(raw)
	if err != nil {
		return Decision{Outcome: NotFound}, nil
	}
	key, found, err := lookup.ByHash(ctx, secret.Hash())
	if err != nil {
		return Decision{}, err
	}
	return Decide(key, found, now), nil
}
