# Platform compatibility

Each SDK minor maps to a minimum supported platform version. Contract changes
are released in this repository before platform or app consumers update.

| appserver-go minor | minPlatformVersion |
| --- | --- |
| v0.1 | 0.0.0-dev (platform main 2026-11-06, source b80b58c71d) |
| v0.2 | 0.0.0-dev (platform main 2026-11-06, AI policy source 2c294ee1f5) |
| v0.3 | Platform API with Project access and identity search (ADR-0079 follow-up) |
| v0.6 | 0.0.0-dev (platform main 2026-11-13, ADR-0082 user-token exchange, source 791a7f4d4c) |
| v0.7 | Same as v0.6; request logging requires no platform change |
| v0.8 | Platform API containing appthrust/platform#7087 (source c372f9232b4beba3813289f95d2c69d5f6e704d4), signed principal and group grants |

The v0.1 packages are `accesskey`, `apphealth`, `aigatewaydiscovery`, and
`appserver/<package>`. v0.2 adds `aipolicy`, the dependency-free AI policy
document, model decisions, and invocation record contract shared by the gateway
and platform.

v0.3 uses `GET /api/v1/projects/{id}/access` for effective Project membership.
`ProjectAccess` exposes the Project role, derived console permissions, and
`NotMember`; both membership and denials are cached per subject for 60 seconds.
HTTP 401/403/404 are non-membership; other failures remain errors. Platform roles
alone do not grant app permissions. Clients must upgrade with the Platform API.

Directory imports use `IdentitySearch` and a non-empty query against
`GET /api/v1/identity/search`; permission failures remain typed `HTTPError`s.
`Settings(ctx, bearer)` returns Project settings without ownership metadata.

## v0.6: opt-in app authorization

The minimum platform is main `791a7f4d4c` (appthrust/platform#6676).
Enabling `identity.Trust.AppAccess` requires the C8 exchange response at
`POST /api/v1/access/user-token`, an Access issuer JWKS, and installation-bound
session Assertions. A missing route is an availability error, never an empty
grant. Leaving `AppAccess` nil preserves existing authentication behavior.
`platformclient.Roles`, `ProjectAccess.Role`, raw `Principal.Groups`, existing
key assertion verification, and the OIDC audience requirement remain supported.

Apps supply the installation name explicitly (it equals the catalog definition
name), e.g. `identity.AppAccessFromEnv("expense")`, or set
`AppAccessConfig.Installation`. The current platform already injects
`PLATFORM_API_URL`, `PLATFORM_PROJECT_ID`, `PLATFORM_OIDC_ISSUER`,
`PLATFORM_OIDC_ISSUER_CA_PEM`, and `PLATFORM_ACCESS_ISSUER` through the platform
connection, and `<prefix>_OIDC_AUDIENCES` through the marketplace renderer.
The catalog's access-key audience environment is still independent of the
user's `azp` and is not required for app-role exchange.

**Planned platform addition, not required or included in this change:**
`PLATFORM_APP_INSTALLATION_NAME` and `PLATFORM_APP_INSTALLATION_UID`.
The SDK reads them as optional overrides when present. Enabling AppAccess
without a configured Project and installation name fails closed at construction.
UID verification is mandatory when configured; otherwise Project plus name are
the binding fence. Applications needing protection against same-name
reinstallation must explicitly configure the UID until the platform injects it.

The SDK verifies the signed app scope instead of interpreting groups or roles.
Session Assertions are internal-only: submitting one as a network bearer is
401 regardless of audience. Caches are bounded, single-flight, keyed by issuer,
subject, and client ID, and use the earlier of signed `exp - 5s` and local
response receipt time plus signed `(exp - iat) - 5s`; non-positive lifetimes are
not cached. Issued-at tolerates the existing 30-second assertion clock leeway;
the SDK still requires an unexpired `exp` with no expiry leeway and a lifetime
of at most five minutes. Regardless of static clock offset, cached permissions
outlive issuer expiry by at most max(0, response age since signed `iat` - 5s).
Exchange failures never fall back to stale grants. Apps that enable the
default `RequirePermissions` guard receive 403 for a declared model with no
permission (including an unaccepted model), while undeclared apps pass through.
The SDK deliberately makes this guard opt-in for additive minor-release
compatibility; applications declaring roles should enable it.

## v0.7: opt-in request logs

`appserver/requestlog` adds structured HTTP request logging. The minimum
platform version is unchanged. Without `requestlog.Wrap`, `httpx.WriteError`
keeps its existing response and logging behavior.

## v0.8: signed person keys and group grants

`accesskey.SessionClaims` and `identity.AppAccess` add `Principal string` and
`GroupGrants []accesskey.GroupGrant`. Each grant contains a per-app `Group` key
and its `Permissions`. `Identity.Access.Principal` is the single durable author
key to store; existing OIDC subjects remain available for compatibility.
Caller-owned grant slices cannot mutate cached results or concurrent callers.

Upgrade the Platform API to #7087 or later before updating consumers. Unlike
v0.6/v0.7, a session Assertion missing its signed principal or group grants is
invalid, not an identity fallback or an empty grant. Identity middleware returns
503 `access_unavailable`. Existing key authentication, nil `Trust.AppAccess`,
installation binding, `Principal.Has`, and permission guards are unchanged.
The fields are additive, but this minimum-platform requirement is intentional.
The missing-principal error explicitly names the absent signed claim and
`Platform API must include #7087` in its message.

Go module versions come from Git tags, not a version field in `go.mod`.
After integration and CI, publish a `v0.8.0` tag and update consuming apps'
`go.mod`/`go.sum` to that tag. The repository's `ci.yml` tests pushes and pull
requests; it does not create release tags automatically.
