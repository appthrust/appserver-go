# Platform compatibility

Each SDK minor maps to a minimum supported platform version. Contract changes
are released in this repository before platform or app consumers update.

| appserver-go minor | minPlatformVersion |
| --- | --- |
| v0.1 | 0.0.0-dev (platform main 2026-11-06, source b80b58c71d) |
| v0.2 | 0.0.0-dev (platform main 2026-11-06, AI policy source 2c294ee1f5) |
| v0.3 | Platform API with Project access and identity search (ADR-0079 follow-up) |
| v0.6 | Unchanged from v0.5 (no additional Platform API requirement) |

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

v0.6 adds `appserver/originguard` without changing existing APIs or the minimum
platform version. Consumers opt into the shared exact-Origin decision function,
immutable trusted-origin sets, atomic readiness snapshots, HTTP middleware, and
WebSocket handshake helper. The package adds no external dependencies.

Trusted URLs use ASCII hosts; configure internationalized names in A-label
form. Unicode input fails closed rather than adding IDNA normalization. Scheme
and host case and default ports are normalized; wildcard/suffix matching is
never used. HTTP is available only for explicitly configured loopback origins
with the local-development option.

Denials use the existing `httpx` JSON `error`/`message` envelope: HTTP 403
`request_origin_not_allowed` or `request_origin_required`, and HTTP 503
`trusted_origins_unavailable` for browser mutations without a ready snapshot.
Authentication and CORS remain consumer responsibilities. Safe methods and
non-browser calls continue; WebSocket handshakes require the separate
`CheckOrigin` check. Consumers must preserve browser headers through proxies
and resolve any method override before the guard.
