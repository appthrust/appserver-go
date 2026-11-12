// Package originguard rejects cross-origin management API mutations before
// handlers or proxies run. It is not authentication, authorization, or CORS.
// Trusted origins come from authoritative Console/Dashboard public URLs, never
// request Host/forwarded headers, domain suffixes, or preview publications.
//
// Hosts are ASCII-only: operators configure internationalized hostnames in
// A-label form. Unicode input is rejected, not IDNA-normalized; xn-- labels are
// compared byte-for-byte after ASCII lower-casing. This matches browser Origin
// serialization without adding an external IDNA dependency.
//
// GET, HEAD, and OPTIONS bypass this guard and must not implement mutations.
// WebSocket authorization must check Origin in the handshake separately using
// CheckOrigin; a WebSocket upgrade GET is deliberately allowed by Guard.
// This SDK does not implement method override headers or parameters. Consumers
// that add overrides must resolve the effective request Method before Guard.
// Proxies must preserve Origin and Sec-Fetch-* and run this guard before
// removing Cookie headers, including when adding a bearer credential.
package originguard

import (
	"net/http"
	"strings"

	"github.com/appthrust/appserver-go/appserver/httpx"
)

// Stable denial reason codes, serialized as the JSON error field by Guard.
const (
	RequestOriginNotAllowed   = "request_origin_not_allowed"
	RequestOriginRequired     = "request_origin_required"
	TrustedOriginsUnavailable = "trusted_origins_unavailable"
)

// Decision is an origin-boundary result, not an authentication result. Reason
// is empty when Allowed is true. The zero value does not allow a request.
type Decision struct {
	Allowed bool
	Reason  string
}

// Check applies the management mutation decision table to an effective method.
// GET/HEAD/OPTIONS are allowed. Other methods require exactly one trusted
// Origin, unless no Origin, Cookie, or Sec-Fetch-* header is present (a
// non-browser client). Cookie and Fetch Metadata flags mean header presence,
// even with an empty value. Bearer credentials never bypass an Origin denial;
// authentication and authorization belong to the next layer.
func Check(method string, originValues []string, fetchMetadataPresent bool, hasCookie bool, trusted TrustedOrigins) Decision {
	if safeMethod(method) {
		return Decision{Allowed: true}
	}
	if len(originValues) == 0 && !fetchMetadataPresent && !hasCookie {
		return Decision{Allowed: true}
	}
	return CheckOrigin(originValues, trusted)
}

// CheckOrigin requires exactly one trusted Origin, without the safe-method or
// non-browser exceptions. Use it for WebSocket handshake origin checks in
// addition to authentication and authorization. No Origin returns
// RequestOriginRequired; malformed, multiple, null, or untrusted values return
// RequestOriginNotAllowed. Callers using a Source must check readiness first.
func CheckOrigin(originValues []string, trusted TrustedOrigins) Decision {
	if len(originValues) == 0 {
		return Decision{Reason: RequestOriginRequired}
	}
	if len(originValues) != 1 || !trusted.contains(originValues[0]) {
		return Decision{Reason: RequestOriginNotAllowed}
	}
	return Decision{Allowed: true}
}

func safeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// Guard applies Check before next, using a single Source snapshot per browser
// mutation. Denials are HTTP 403 with a JSON error reason. While source is nil
// or not ready, all state-changing browser requests instead receive HTTP 503
// TrustedOriginsUnavailable, even if their Origin would otherwise be invalid.
// Safe methods and non-browser requests do not need a snapshot. Guard never
// reads/closes the body, changes headers, authenticates, or implements CORS.
// WebSocket upgrade GETs bypass Guard: use CheckOrigin in the handshake.
func Guard(next http.Handler, source Source) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if safeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		origins, fetchMetadata, cookie := requestMetadata(r.Header)
		if len(origins) == 0 && !fetchMetadata && !cookie {
			next.ServeHTTP(w, r)
			return
		}
		var trusted TrustedOrigins
		var ready bool
		if source != nil {
			trusted, ready = source.Load()
		}
		if !ready || trusted.origins == nil {
			httpx.WriteJSON(w, http.StatusServiceUnavailable, &httpx.Error{
				Code: TrustedOriginsUnavailable, Message: "Trusted request origins are not available",
			})
			return
		}
		decision := Check(r.Method, origins, fetchMetadata, cookie, trusted)
		if !decision.Allowed {
			message := "The request origin is not allowed"
			if decision.Reason == RequestOriginRequired {
				message = "A request origin is required"
			}
			httpx.WriteJSON(w, http.StatusForbidden, &httpx.Error{Code: decision.Reason, Message: message})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestMetadata(headers http.Header) (origins []string, fetchMetadata, cookie bool) {
	// Enumerate keys so header presence (including empty values) and duplicate
	// case variants survive in-process proxies that do not canonicalize keys.
	for name, values := range headers {
		switch {
		case strings.EqualFold(name, "Origin"):
			if origins != nil || len(values) == 0 {
				// An empty header entry or duplicate field spelling is present
				// but invalid, never a missing Origin/non-browser exemption.
				origins = []string{"", ""}
			} else {
				origins = values
			}
		case strings.EqualFold(name, "Cookie"):
			cookie = true
		case len(name) >= len("Sec-Fetch-") && strings.EqualFold(name[:len("Sec-Fetch-")], "Sec-Fetch-"):
			fetchMetadata = true
		}
	}
	return origins, fetchMetadata, cookie
}
