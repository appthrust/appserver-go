package accesskey

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"
)

func testKey() Key {
	return Key{
		Name: "ak-test", Space: "knowledge", Audience: "knowledge", Project: "pj-test",
		Subject: Subject{Kind: SubjectComponent, ID: "component-id"}, Enabled: true,
		Scopes:      []string{"search", "documents:read"},
		SpaceScopes: []string{"search", "documents:read", "documents:write"},
	}
}

func TestDecide(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		change func(*Key)
		found  bool
		want   Outcome
		scopes []string
	}{
		{"not found", nil, false, NotFound, nil},
		{"space gone before revoked", func(k *Key) { k.Space = ""; k.RevokedAt = now }, true, SpaceGone, nil},
		{"revoked before disabled", func(k *Key) { k.RevokedAt = now; k.Enabled = false }, true, Revoked, nil},
		{"disabled before expired", func(k *Key) { k.Enabled = false; k.ExpiresAt = now }, true, Disabled, nil},
		{"expired at boundary", func(k *Key) { k.ExpiresAt = now }, true, Expired, nil},
		{"expired in past", func(k *Key) { k.ExpiresAt = now.Add(-time.Second) }, true, Expired, nil},
		{"retired scopes", func(k *Key) { k.SpaceRetired = k.Scopes }, true, ScopeRetired, nil},
		{"removed scopes", func(k *Key) { k.SpaceScopes = nil }, true, ScopeRetired, nil},
		{"allow sorted", nil, true, Allow, []string{"documents:read", "search"}},
		{"future expiry", func(k *Key) { k.ExpiresAt = now.Add(time.Nanosecond) }, true, Allow, []string{"documents:read", "search"}},
		{"intersection", func(k *Key) { k.SpaceScopes = []string{"search", "other"} }, true, Allow, []string{"search"}},
		{"partly retired", func(k *Key) { k.SpaceRetired = []string{"documents:read"} }, true, Allow, []string{"search"}},
		{"duplicates", func(k *Key) { k.Scopes = []string{"search", "search"} }, true, Allow, []string{"search"}},
		{"empty key scopes", func(k *Key) { k.Scopes = nil }, true, Allow, nil},
	}
	seen := make(map[Outcome]bool)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := testKey()
			if tc.change != nil {
				tc.change(&key)
			}
			before := key
			before.Scopes = slices.Clone(key.Scopes)
			before.SpaceScopes = slices.Clone(key.SpaceScopes)
			before.SpaceRetired = slices.Clone(key.SpaceRetired)
			got := Decide(&key, tc.found, now)
			seen[got.Outcome] = true
			if got.Outcome != tc.want || !slices.Equal(got.Scopes, tc.scopes) {
				t.Fatalf("decision = %s %v, want %s %v", got.Outcome, got.Scopes, tc.want, tc.scopes)
			}
			if tc.found && got.Key != &key || !tc.found && got.Key != nil {
				t.Fatal("incorrect decision record")
			}
			if !reflect.DeepEqual(key, before) {
				t.Fatal("Decide mutated the input record")
			}
		})
	}
	for _, outcome := range []Outcome{Allow, NotFound, Disabled, Expired, Revoked, SpaceGone, ScopeRetired} {
		if !seen[outcome] {
			t.Errorf("missing coverage for %s", outcome)
		}
	}
	if UsageExceeded != "usage_exceeded" || seen[UsageExceeded] {
		t.Fatal("UsageExceeded is reserved for Phase 3 and must not be returned")
	}
	if got := Decide(nil, true, now); got.Outcome != NotFound {
		t.Fatal("nil lookup record must not authorize")
	}
}

type lookupFunc func(context.Context, Hash) (*Key, bool, error)

func (f lookupFunc) ByHash(ctx context.Context, h Hash) (*Key, bool, error) { return f(ctx, h) }

func TestVerifyKey(t *testing.T) {
	secret, err := Generate("knowl", bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	key := testKey()
	lookupErr := errors.New("store unavailable")
	for _, tc := range []struct {
		name    string
		raw     string
		found   bool
		err     error
		outcome Outcome
		calls   int
	}{
		{"malformed", "apk_bad_bad_bad", true, nil, NotFound, 0},
		{"missing", secret.String(), false, nil, NotFound, 1},
		{"allowed", secret.String(), true, nil, Allow, 1},
		{"lookup error", secret.String(), false, lookupErr, "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			ctx := context.Background()
			lookup := lookupFunc(func(gotCtx context.Context, h Hash) (*Key, bool, error) {
				calls++
				if gotCtx != ctx || !h.Equal(secret.Hash()) {
					t.Fatal("lookup must receive the context and hash, never raw secret")
				}
				return &key, tc.found, tc.err
			})
			got, err := Verify(ctx, tc.raw, time.Now(), lookup)
			if !errors.Is(err, tc.err) || got.Outcome != tc.outcome || calls != tc.calls {
				t.Fatalf("Verify = %s, %v (%d lookups)", got.Outcome, err, calls)
			}
		})
	}
}
