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
`POST /api/v1/access/user-token` (see
[COMPATIBILITY.md](COMPATIBILITY.md)). Existing authenticators and Project-role
APIs remain unchanged when `Trust.AppAccess` is nil.

### Language-neutral contract

1. Add a platform connection to the component. It supplies `PLATFORM_API_URL`,
   `PLATFORM_PROJECT_ID`, `PLATFORM_OIDC_ISSUER`, and `PLATFORM_ACCESS_ISSUER`.
2. Verify the forwarded user token, then
   `POST {PLATFORM_API_URL}/api/v1/access/user-token` with its forwarded
   `Authorization` header and no body. Cache per subject (isolated by issuer
   and client) until shortly before `expiresAt`; Assertions last 60 seconds.
3. Verify the returned Assertion against the Access issuer's JWKS: issuer,
   `aud` matching the forwarded token's `azp`, Project, and application name.
   Require `appthrust.io/application` and `appthrust.io/application_uid`.
4. Authorize on `scopes`, taken from the verified Assertion's signed `scope`,
   never from IdP groups or unsigned response metadata. Exchange or verification
   failure is 503, never a fallback to old grants or raw claims; an invalid
   forwarded user bearer remains 401.

### Go integration

For a Project's own Application, supply its name explicitly:

```go
trust := identity.FromEnv("EXPENSE")
trust.AppAccess = &identity.AppAccessConfig{
    PlatformOrigin:     os.Getenv("PLATFORM_API_URL"),
    Project:            os.Getenv("PLATFORM_PROJECT_ID"),
    Application:        "expense",
    RequirePermissions: true,
}
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

`AppAccessConfig` requires `PlatformOrigin`, `Project`, and exactly one of
`Application` or `Installation`. Configuring both names or neither fails at
construction. With `Application`, the signed application name must match and
its UID must be present; installation claims are not required.

For marketplace apps, `identity.AppAccessFromEnv("expense")` still configures
`Installation` (the catalog definition name), with an optional
`InstallationUID` fence. It reads `PLATFORM_API_URL` and `PLATFORM_PROJECT_ID`;
`PLATFORM_APP_INSTALLATION_NAME` and `PLATFORM_APP_INSTALLATION_UID` optionally
override the installation identity. These installation variables are planned,
not currently injected. Installation configuration accepts both v0.6.0-shaped
Assertions without application claims and newer Assertions with them.
An Assertion carrying only one of the installation name/UID pair is rejected.

`PLATFORM_OIDC_ISSUER`, `PLATFORM_OIDC_ISSUER_CA_PEM`,
`PLATFORM_ACCESS_ISSUER`, and `<prefix>_OIDC_AUDIENCES` supply trust.
Configure the OIDC audiences for the forwarded user token.
`<prefix>_ACCESS_AUDIENCE` still controls network key assertions only; role-only
apps need no key audience or Space. Both issuers are required for app access.

After verifying the forwarded OIDC bearer, the SDK exchanges it with no request
body and verifies the returned ES256 Assertion's issuer, protected type/key ID,
audience containing the bearer's `azp`, user/session kind, exact subject and
subject issuer, Project, configured application or installation (and optional
installation UID), expiry, and at-most-five-minute lifetime. The platform issues
60-second Assertions. Session Assertions are
SDK-internal and rejected as network bearers, even for a matching audience.
Only signed `scope` grants permissions; response role names, response scopes,
and raw groups never grant them.

People retain `Kind: "user"`, their existing subject/profile/groups, and gain
`Scopes` and `Project`. `Principal.Application` and `Principal.ApplicationUID`
expose the signed application identity, when present. `accesskey.SessionClaims`
also exposes `Application`, `ApplicationUID`, `Installation`, and
`InstallationUID`; absent claims remain empty. Keys retain `Kind: "key"`.
Both use `Principal.Has("permission")` for exact permission matching.
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
