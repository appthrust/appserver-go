package accesskey

import (
	"slices"
	"time"
)

type Outcome string

const (
	Allow        Outcome = "allow"
	NotFound     Outcome = "not_found"
	Disabled     Outcome = "disabled"
	Expired      Outcome = "expired"
	Revoked      Outcome = "revoked"
	SpaceGone    Outcome = "space_gone"
	ScopeRetired Outcome = "scope_retired"
	// UsageExceeded is reserved for Phase 3 quota enforcement. Decide never
	// returns it: this package performs no usage accounting.
	UsageExceeded Outcome = "usage_exceeded"
)

type Decision struct {
	Outcome Outcome
	Key     *Key
	Scopes  []string // Key scopes intersected with the space's live scopes.
}

// Decide applies lifecycle checks in precedence order, then intersects scopes.
// It does not mutate the record or any of its slices.
func Decide(key *Key, found bool, now time.Time) Decision {
	if !found || key == nil {
		return Decision{Outcome: NotFound}
	}
	d := Decision{Key: key}
	switch {
	case key.Space == "":
		d.Outcome = SpaceGone
	case !key.RevokedAt.IsZero():
		d.Outcome = Revoked
	case !key.Enabled:
		d.Outcome = Disabled
	case !key.ExpiresAt.IsZero() && !now.Before(key.ExpiresAt):
		d.Outcome = Expired
	default:
		live := make(map[string]struct{}, len(key.SpaceScopes))
		for _, scope := range key.SpaceScopes {
			live[scope] = struct{}{}
		}
		for _, scope := range key.SpaceRetired {
			delete(live, scope)
		}
		for _, scope := range key.Scopes {
			if _, ok := live[scope]; ok {
				d.Scopes = append(d.Scopes, scope)
				delete(live, scope)
			}
		}
		if len(key.Scopes) > 0 && len(d.Scopes) == 0 {
			d.Outcome = ScopeRetired
		} else {
			d.Outcome = Allow
			slices.Sort(d.Scopes)
		}
	}
	return d
}
