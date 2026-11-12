package originguard

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
)

// Options controls construction of the trusted-origin set.
type Options struct {
	// AllowLoopbackHTTP permits explicitly listed HTTP origins on localhost or
	// loopback IP addresses for local development. It does not allow arbitrary
	// HTTP hosts, localhost subdomains, or implicitly trust any origin.
	AllowLoopbackHTTP bool
}

// TrustedOrigins is an immutable exact-origin set, safe to copy and share.
// The zero value is uninitialized and trusts nothing. Use NewTrustedOrigins
// even for a ready, empty set.
type TrustedOrigins struct {
	origins           map[string]struct{}
	allowLoopbackHTTP bool
}

// NewTrustedOrigins validates and normalizes every origin before returning a
// set. Any invalid input returns an uninitialized set and an error; it never
// returns a partially trusted set. Origins must have ASCII hosts (international
// names in A-label form), HTTPS unless Options explicitly permits loopback HTTP,
// and no userinfo, path (including a trailing slash), query, fragment, wildcard,
// percent encoding, or trailing dot. Scheme and host are lower-cased, IP literals
// are canonicalized, and default ports are omitted. Input slices are not retained.
func NewTrustedOrigins(origins []string, options Options) (TrustedOrigins, error) {
	trusted := TrustedOrigins{
		origins:           make(map[string]struct{}, len(origins)),
		allowLoopbackHTTP: options.AllowLoopbackHTTP,
	}
	for i, origin := range origins {
		normalized, err := normalizeOrigin(origin, options.AllowLoopbackHTTP)
		if err != nil {
			return TrustedOrigins{}, fmt.Errorf("originguard: invalid trusted origin at index %d: %w", i, err)
		}
		trusted.origins[normalized] = struct{}{}
	}
	return trusted, nil
}

// Origins returns a sorted copy of the normalized origins, suitable for a CORS
// allowlist derived from the same snapshot. Mutating it cannot change the set.
func (t TrustedOrigins) Origins() []string {
	origins := make([]string, 0, len(t.origins))
	for origin := range t.origins {
		origins = append(origins, origin)
	}
	slices.Sort(origins)
	return origins
}

func (t TrustedOrigins) contains(origin string) bool {
	// Browser-serialized origins normally already have their canonical form.
	// Avoid parsing and allocating for the common exact-match case.
	if _, ok := t.origins[origin]; ok {
		return true
	}
	normalized, err := normalizeOrigin(origin, t.allowLoopbackHTTP)
	if err != nil {
		return false
	}
	_, ok := t.origins[normalized]
	return ok
}

var errInvalidOrigin = errors.New("expected an ASCII HTTPS origin (or explicitly enabled loopback HTTP) without userinfo, path, query, fragment, percent encoding, or trailing dot")

func normalizeOrigin(origin string, allowLoopbackHTTP bool) (string, error) {
	for i := range len(origin) {
		if origin[i] <= ' ' || origin[i] >= 127 {
			return "", errInvalidOrigin
		}
	}
	if strings.ContainsAny(origin, "%?#\\") {
		return "", errInvalidOrigin
	}
	u, err := url.Parse(origin)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" || u.Path != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errInvalidOrigin
	}
	host := strings.ToLower(u.Hostname())
	loopback := false
	if addr, err := netip.ParseAddr(host); err == nil {
		// IPv6 requires brackets; IPv4 must not have them. Zone identifiers
		// have already been excluded by the percent-encoding check.
		if addr.Is6() != strings.HasPrefix(u.Host, "[") {
			return "", errInvalidOrigin
		}
		host = addr.String()
		loopback = addr.IsLoopback()
		if addr.Is6() {
			host = "[" + host + "]"
		}
	} else {
		if strings.HasPrefix(u.Host, "[") || !validDNSHost(host) {
			return "", errInvalidOrigin
		}
		loopback = host == "localhost"
	}
	if u.Scheme == "http" && (!allowLoopbackHTTP || !loopback) {
		return "", errInvalidOrigin
	}
	port := u.Port()
	if port == "" {
		if strings.HasSuffix(u.Host, ":") {
			return "", errInvalidOrigin
		}
	} else {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return "", errInvalidOrigin
		}
		if (u.Scheme == "https" && number == 443) || (u.Scheme == "http" && number == 80) {
			port = ""
		} else {
			port = strconv.FormatUint(number, 10)
		}
	}
	if port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host, nil
}

func validDNSHost(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Source supplies one immutable trusted-origin snapshot and its readiness.
// Load must be safe for concurrent requests and should only read local state,
// not fetch configuration or call a control plane on the request path.
type Source interface {
	Load() (TrustedOrigins, bool)
}

// Snapshot atomically publishes a complete trusted-origin set. Its zero value
// is not ready. Do not copy a Snapshot after first use.
type Snapshot struct {
	value atomic.Pointer[TrustedOrigins]
}

// Load returns the current set and whether it is ready. A nil Snapshot is not
// ready. A constructed empty set is ready but denies every supplied origin.
func (s *Snapshot) Load() (TrustedOrigins, bool) {
	if s != nil {
		if trusted := s.value.Load(); trusted != nil {
			return *trusted, true
		}
	}
	return TrustedOrigins{}, false
}

// Store atomically replaces the snapshot. An uninitialized TrustedOrigins
// clears readiness, including the value returned on a construction error.
func (s *Snapshot) Store(trusted TrustedOrigins) {
	if trusted.origins == nil {
		s.Clear()
		return
	}
	s.value.Store(&trusted)
}

// Clear marks the source not ready. Use it when the authoritative configuration
// is unavailable or invalid; do not silently retain a stale trusted set.
func (s *Snapshot) Clear() {
	s.value.Store(nil)
}
