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

v0.6 adds `appserver/originguard`, an opt-in exact-Origin boundary for
management APIs. It adds no external dependencies and uses the existing
`httpx` JSON error envelope. Build trusted origins from authoritative installed
Console/Dashboard public URLs, not request headers or Project domain suffixes:

```go
var source originguard.Snapshot // not ready until a validated set is stored
trusted, err := originguard.NewTrustedOrigins(publicOrigins, originguard.Options{})
if err != nil {
    source.Clear()
    return err
}
source.Store(trusted)
handler := originguard.Guard(next, &source)
```

Reload the complete set atomically with `Store`; call `Clear` if its authority
is unavailable or validation fails. An explicitly constructed empty set is
ready and trusts no origins. `Load` returns `(TrustedOrigins, bool)` with
readiness; `Origins` returns a sorted copy for a CORS allowlist from the same
snapshot. Requests never fetch configuration from the control plane.

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

The middleware never reads the body or changes request headers. Install it
before handlers/proxies and before removing Cookies. Upstream proxies must
preserve Origin and Sec-Fetch-* even when injecting a bearer. It does not
authenticate, authorize, or implement CORS. The SDK does not implement method
override headers/parameters; if a consumer adds them, resolve the effective
request method before the guard.

WebSocket upgrade GETs bypass this guard. Handshake authorization must
separately call `CheckOrigin(originValues, trusted)` with a ready snapshot;
this helper requires exactly one trusted Origin even for GET and rejects a
missing Origin with `request_origin_required`.

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
