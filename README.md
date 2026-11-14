# AppThrust app server Go SDK

Shared server contracts and helpers for AppThrust apps. This public module is
the frozen contract from ADR-0072 D7, extracted from platform source
`b80b58c71d`, with the AI policy contract extracted from `2c294ee1f5`.
Platform and apps consume the same versioned module; this module never imports
`github.com/appthrust/platform`.

Import packages from:

- `github.com/appthrust/appserver-go/accesskey`
- `github.com/appthrust/appserver-go/apphealth`
- `github.com/appthrust/appserver-go/aigatewaydiscovery`
- `github.com/appthrust/appserver-go/aipolicy`
- `github.com/appthrust/appserver-go/appserver/<package>`

See [COMPATIBILITY.md](COMPATIBILITY.md) and the accepted
[first-party app repositories design](https://github.com/appthrust/platform/blob/main/design/platform/marketplace-apps/first-party-app-repositories.md).

## Management request origins

The next release, v0.7.0, adds `appserver/originguard`, an opt-in exact-Origin
boundary for management APIs. The existing v0.6.0 tag does not contain this
package. It adds no external dependencies and uses the existing `httpx` JSON
error envelope. Build a static trusted-origin set from the entrypoint's
authoritative configured public origin, not request headers or Project domain
suffixes. The Platform API trusts only its Dashboard origin; the Console trusts
only its own origin:

```go
var source originguard.Snapshot // not ready until a validated set is stored
trusted, err := originguard.NewTrustedOrigins([]string{publicOrigin}, originguard.Options{})
if err != nil {
    source.Clear()
    return err
}
source.Store(trusted)
handler := originguard.Guard(next, &source)
```

Validate and `Store` the static configuration before serving requests; invalid
configuration must fail startup. `Snapshot` is an in-memory readiness holder,
not a dynamic trust source: there is no controller, watch, refresh, or external
read. `Clear` marks it unavailable. An explicitly constructed empty set is ready
and trusts no origins. `Load` returns `(TrustedOrigins, bool)` with readiness;
`Origins` returns a sorted copy for a CORS allowlist from the same snapshot.

Origins require HTTPS, with no userinfo, path (even `/`), query, fragment,
percent encoding, wildcard, or trailing dot. Scheme/host case and default ports
are normalized; hosts are ASCII-only. Operators configure internationalized
hostnames in A-label (`xn--`) form, compared byte-for-byte after lower-casing.
Unicode trusted input fails construction; Unicode request origins are denied.
`Options{AllowLoopbackHTTP: true}` permits explicitly listed HTTP origins on
`localhost` or loopback IPs for local development, not arbitrary HTTP hosts.

`Check(method, originValues, fetchMetadataPresent, hasCookie, trusted)` is the
pure decision function. `Guard(next, source)` applies the following boundary:

| Request | Guard result |
| --- | --- |
| GET, HEAD, OPTIONS | Continue; never implement mutations on these methods |
| Other method, exactly one trusted Origin | Continue to authentication/authorization |
| Other Origin, including sibling, port mismatch, `null`, duplicate, or malformed | 403 `request_origin_not_allowed`, even with a bearer |
| No Origin, but Cookie or any Sec-Fetch-* header present | 403 `request_origin_required`, including `same-site` or empty headers |
| No Origin, Cookie, or Sec-Fetch-* | Continue as a non-browser client; authentication is still required |
| State-changing browser request while the snapshot is not ready | 503 `trusted_origins_unavailable` takes precedence |

The middleware never reads the body or changes request headers. Preserve the
original Origin, Cookie, and all Sec-Fetch-* headers through edge proxies until
the entrypoint guard has checked them, including when adding a bearer. After
the guard and actual bearer verification, a BFF's upstream metadata handling is
the consumer's explicit contract. In the Console-to-Platform contract:

- Ordinary HTTP removes Cookie, Origin, Sec-Fetch-* and client-supplied forwarded
  headers, forwarding only the verified user bearer as a non-browser request.
- WebSocket forwarding replaces Origin with the configured, validated Dashboard
  origin and removes Cookie/Sec-Fetch-* only after checking the original Console
  origin and verifying the bearer. Never reflect an arbitrary client Origin.

Metadata stripping or Origin replacement without the guard and actual bearer
verification must never be shipped. An Authorization header's presence alone is
not verification. The SDK does not authenticate, authorize, or implement CORS.
It does not implement method override headers/parameters; if a consumer adds
them, resolve the effective request method before the guard.

### WebSocket upgrades

**`CheckOrigin` is mandatory before every WebSocket upgrade handler or upstream
dial.** `Guard` deliberately allows GET, including upgrade GETs, so wrapping an
upgrade handler with `Guard` alone is insufficient. Check the snapshot's
readiness and pass **all** Origin values, not `Header.Get("Origin")`:

```go
// Inside the consumer's WebSocket entrypoint, before authentication and upgrade.
trusted, ready := source.Load()
if !ready {
    httpx.WriteJSON(w, http.StatusServiceUnavailable, &httpx.Error{
        Code: originguard.TrustedOriginsUnavailable,
        Message: "Trusted request origins are not available",
    })
    return
}
decision := originguard.CheckOrigin(r.Header.Values("Origin"), trusted)
if !decision.Allowed {
    httpx.WriteJSON(w, http.StatusForbidden, &httpx.Error{
        Code: decision.Reason,
        Message: "A trusted request origin is required for WebSocket upgrades",
    })
    return
}
authenticatedUpgrade.ServeHTTP(w, r)
```

`CheckOrigin` has no safe-method or non-browser exception: missing Origin is
403 `request_origin_required`; invalid, `null`, multiple, or untrusted origins
are 403 `request_origin_not_allowed`, even with a valid bearer. Ordinary CLI
POSTs without Origin, Cookie, or Sec-Fetch-* may proceed to authentication;
CLI WebSocket clients must explicitly supply an allowed Origin as well as valid
credentials. The standard-library HTTP/WebSocket handshake test in
`appserver/originguard/websocket_test.go` exercises this consumer composition.

## Development

Go 1.26 or newer is required; CI uses Go 1.27.x.

```sh
go build ./...
go vet ./...
go test ./...
```

The root closure test enforces the reviewed runtime dependency allowlist.
Copied tests retain Testify as a test-only dependency. The Postgres test helper
skips when both `BUILTIN_APPSERVER_TEST_DATABASE_URL` and
`BUILDER_CONSOLE_TEST_DATABASE_URL` are unset; the SDK's own tests do not require
Postgres.

Generated contracts are committed. The copied maintainer generator at
`appserver/contract/gen` still requires platform's `platform-api/go.mod` tooling
and callee-owned OpenAPI sources in the platform repository layout. Its existing
`go:generate` directives do not run from a standalone SDK checkout; generation
is not required to build, test, or consume the SDK.
