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

## App permissions (ADR-0082)

App access is opt-in and requires a platform implementing
`POST /api/v1/access/user-token` (see the pending minimum version in
[COMPATIBILITY.md](COMPATIBILITY.md)). Existing authenticators and Project-role
APIs remain unchanged when `Trust.AppAccess` is nil.

```go
trust := identity.FromEnv("EXPENSE")
// The installation name equals the catalog definition name. Supply the app's
// known name explicitly; no installation identity environment is required.
appAccess := identity.AppAccessFromEnv("expense")
appAccess.RequirePermissions = true
trust.AppAccess = &appAccess
auth, err := identity.New(trust)
if err != nil {
    return err
}
handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    user, _ := identity.FromContext(r.Context())
    if !user.Principal.Has("reports:approve") {
        httpx.WriteError(w, httpx.Forbidden(), "expense")
        return
    }
    // Perform the app-owned operation.
}))
```

`AppAccessConfig` can instead be supplied explicitly with `PlatformOrigin`,
`Project`, `Installation`, and optionally `InstallationUID`. `AppAccessFromEnv`
reads `PLATFORM_API_URL` and `PLATFORM_PROJECT_ID`; optional
`PLATFORM_APP_INSTALLATION_NAME` overrides the explicit name and
`PLATFORM_APP_INSTALLATION_UID` enables the UID fence. Those installation
variables are a planned platform addition, not currently injected. Existing
`PLATFORM_OIDC_ISSUER`, `PLATFORM_OIDC_ISSUER_CA_PEM`,
`PLATFORM_ACCESS_ISSUER`, and `<prefix>_OIDC_AUDIENCES` supply trust.
`<prefix>_ACCESS_AUDIENCE` still controls network key assertions only; role-only
apps need no key audience or Space. Enabling app access without both issuers,
Project, or installation name fails at construction.

After verifying the forwarded OIDC bearer, the SDK exchanges it with no request
body and verifies the returned ES256 Assertion's issuer, protected type/key ID,
audience containing the bearer's `azp`, user/session kind, exact subject and
subject issuer, Project, installation, optional UID, expiry, and at-most-five-minute
lifetime. The platform issues 60-second Assertions. Session Assertions are
SDK-internal and rejected as network bearers, even for a matching audience.
Only signed `scope` grants permissions; response role names, response scopes,
and raw groups never grant them.

People retain `Kind: "user"`, their existing subject/profile/groups, and gain
`Scopes` and `Project`. Keys retain `Kind: "key"`. Both use
`Principal.Has("permission")` for exact permission matching.
`Identity.Access` exposes `declared` and `accepted` (nil when exchange is disabled
or the principal is a key). `RequirePermissions` denies people with 403 when
`declared` is true and scope is empty, including pending acceptance. Without
declared roles it passes through. Alternatively apply the same guard per route
with `auth.Middleware(identity.RequireAppAccess(handler))`. Permission-specific
endpoint checks remain necessary, including for keys.

The per-authenticator cache is keyed by `(issuer, subject, azp)` and coalesces
concurrent exchanges. It expires at the earlier of signed `exp - 5s` and response
receipt time plus signed `(exp - iat) - 5s`, so app clock lag cannot extend cache
retention; a non-positive remaining lifetime is not cached. It holds
at most 1024 identities and 1024 in-flight identities by default (`CacheSize`
overrides both). Failed exchanges are never cached, and expired assertions are
never served as fallback. Transport, non-401 HTTP, or verification failures
produce 503 `access_unavailable`; an exchange 401 produces 401
`unauthenticated`, and 429 becomes 503 with `Retry-After`.
`AppAccessConfig.Now` permits an injected clock.

Custom authentication middleware must use `identity.WriteError(w, err)` to
preserve the shared JSON error envelope and retry hints. `platformclient.Roles`,
`ProjectAccess.Role`, and `Principal.Groups` remain available for their existing
uses; do not use them as substitutes for app permissions.

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
