// Package accesskey implements opaque access keys and short-lived ES256
// assertions without depending on any other platform package. This leaf package
// can be copied into partial-workspace backend images with only go-jose/v4.
//
// Secrets use apk_<prefix>_<random>_<checksum>. The prefix is 3–6 lowercase ASCII
// letters or digits; random is 32 bytes encoded with the 0-9A-Za-z alphabet and
// padded to 43 characters; checksum is IEEE CRC32 over the preceding body,
// encoded with the same alphabet and padded to six characters. CRC32 is only a
// scanner aid, not authentication. Never persist or log Secret.String(): store
// Hash and Hint, and return the secret only at creation.
//
// Verify performs Parse -> Hash -> KeyLookup -> Decide. Decisions honor missing
// keys, deleted spaces, irrevocable revocation, disabling, and expiry in that
// order, then intersect key scopes with live space scopes. An empty intersection
// of originally nonempty scopes is ScopeRetired. UsageExceeded is reserved for
// Phase 3 and is never produced by Decide.
//
// NewClaims caps lifetime at five minutes, uses the decision's effective scopes,
// and binds one audience, project, key name, and subject. Assertion headers carry
// typ=appthrust-access+jwt and a kid. Verifier accepts only ES256, matches the
// configured issuer and requested audience, and allows 30 seconds of expiry
// clock skew. Backends must still enforce the asserted Project and Scopes.
//
// IssuerURL derives the installation issuer from a dashboard origin; JWKSURL
// derives its discovery URL. Signers publish current and retired public keys
// only. MarshalPKCS8 and ParsePKCS8 use PEM PKCS#8 P-256 private keys for Secret
// storage; those bytes must never be logged. HTTP JWKS sources coalesce fetches,
// cache for the supplied TTL, retain stale keys on fetch failure, and throttle
// unknown-kid forced refreshes to one per minute. Reuse a source across requests
// to preserve those cache and refresh bounds.
package accesskey
