# Platform compatibility

Each SDK minor maps to a minimum supported platform version. Contract changes
are released in this repository before platform or app consumers update.

| appserver-go minor | minPlatformVersion |
| --- | --- |
| v0.1 | 0.0.0-dev (platform main 2026-11-06, source b80b58c71d) |
| v0.2 | 0.0.0-dev (platform main 2026-11-06, AI policy source 2c294ee1f5) |
| v0.3 | Platform API with Project access and identity search (ADR-0079 follow-up) |

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
