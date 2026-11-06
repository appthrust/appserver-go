# AppThrust app server Go SDK

Shared server contracts and helpers for AppThrust apps. This public module is
the frozen contract from ADR-0072 D7, extracted from platform source
`b80b58c71d`. Platform and apps consume the same versioned module; this module
never imports `github.com/appthrust/platform`.

Import packages from:

- `github.com/appthrust/appserver-go/accesskey`
- `github.com/appthrust/appserver-go/apphealth`
- `github.com/appthrust/appserver-go/aigatewaydiscovery`
- `github.com/appthrust/appserver-go/appserver/<package>`

See [COMPATIBILITY.md](COMPATIBILITY.md) and the accepted
[first-party app repositories design](https://github.com/appthrust/platform/blob/main/design/platform/marketplace-apps/first-party-app-repositories.md).

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
