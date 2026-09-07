# Auth Hardening Migration Notes

These notes describe the uncommitted generic auth hardening changes. No release
or version change is made here. The existing strict OIDC opt-in remains intact:
generic OAuth userinfo login does not require an ID token unless configured to.

## OAuth Flow API

`oauth2.Options` adds `FlowStore oauth2.FlowStore` and `FlowTTL time.Duration`.
Nonpositive `FlowTTL` defaults to six minutes. This is enforced server-side and
is independent of `FlowCookie.MaxAge`; changing cookie lifetime cannot extend a
flow. Set both explicitly if your login experience needs a different lifetime.

```go
type FlowStore interface {
    Save(context.Context, string, FlowData) error
    Consume(context.Context, string) (FlowData, error)
}

type FlowData struct {
    State, Nonce, Verifier string
    Provider, CallbackURL  string
    ExpiresAt             time.Time
    Source                string
    SourceLimit           int
}
```

- Nil `FlowStore` creates a per-strategy memory store bounded to 4096 live flows.
  Each source can hold at most 10 pending flows by default, so discarding cookies
  or changing TCP source ports cannot let one client occupy all 4096 slots.
  Expired entries are pruned on saves; consumption removes its entry atomically.
  There is no goroutine, janitor, or new `Close` requirement. Hot-replaced OAuth
  strategies are not retained by Auth's closable-strategy lifecycle.
- The cookie is a random 256-bit handle, separate from authorization state.
  Nonce and PKCE verifier remain server-held. Records bind state, provider/client
  configuration, and callback URI. The request callback path must match that URI.
- Callback processing atomically consumes the presented record before state,
  query, provider, callback, or provider-denial validation. Duplicate cookies and
  query parameters are rejected, including repeated identical values. Presented
  valid handles in duplicate cookies are consumed, not left reusable.
- `ErrFlowInvalid` covers unknown, consumed, and expired flows. These return 401
  with the existing `state_invalid` envelope and instructions to restart login.
  Store outages or `ErrFlowStoreFull` return 503 `flow_unavailable` instead of a
  redirect to the provider. No store error text is exposed or logged.
- **Breaking behavior:** the shipped base64-JSON cookie format is rejected.
  In-flight logins must restart after upgrade; there is no dual-format mode.
  Existing completed sessions are not migrated or invalidated by this change.
- Restarting/replacing a strategy with the default store invalidates outstanding
  flows. For multiple replicas or continuity across reloads, inject the same
  shared store/backend in every applicable strategy instance. Sticky routing is
  not a substitute for shared storage when callbacks may reach another replica.

## Initiation Admission

`Options.FlowMaxPendingPerSource` configures the maximum live flows per source;
nonpositive values default to 10. Source quota exhaustion returns 429
`flow_source_full`, with `Cache-Control: no-store`, no new cookie, and no provider
redirect. Complete an outstanding login or wait for expiry before retrying.
The memory store counts source records during its existing bounded scan while
holding the save lock. It adds no IP map, counters requiring cleanup, or goroutine.
Consumption and expiry release quota; failed/cancelled saves do not reserve it.

`FlowData.Source` is a SHA-256 hash of the canonical client address captured by the
server on initiation. Ports and equivalent IP spellings are normalized. By default
all client-IP forwarding headers are ignored and `RemoteAddr` supplies the source.
Explicit `TrustedProxies` uses the existing validated client-IP policy: traverse
X-Forwarded-For from right to left to the first untrusted hop, with single-address
headers considered only when that chain is absent. Malformed forwarding data
falls back to the immediate peer's quota. Invalid trusted-proxy configuration
fails admission. `UnsafeTrustAllForwardedHeaders` never enables trust for admission.
Source keys are pseudonymous, not anonymized; do not log or expose them.

This is admission control, **not callback IP binding**. A mobile browser may change
networks before its callback without losing its flow. Clients behind shared NAT
share a quota; tune the positive limit for your expected concurrency. Reverse
proxies share one quota unless you explicitly configure their trusted addresses
and have them correctly sanitize/append forwarding headers. Do not trust arbitrary
Internet peers or use broad CIDRs to work around NAT limits.

This cap limits outstanding storage, not request rate or upstream workload.
Use edge request-rate/concurrency limits as well, especially for distributed
sources, IPv6 address rotation, shared-NAT abuse, or clients repeatedly consuming
their own flows. Raising the per-source limit increases monopolization risk;
setting it at or above 4096 removes isolation within the default global capacity.

## Distributed Store Contract

Implement `Save` with create-if-absent semantics for live handles and expiration
from `FlowData.ExpiresAt`. Implement `Consume` with atomic get-and-delete semantics
across all replicas, not separate GET and DELETE calls. Return `ErrFlowInvalid`
for missing/consumed/expired records and another error for infrastructure failure.
The strategy independently rejects returned expired records before any exchange.

Injected stores also receive `Source` and `SourceLimit` and **must atomically
enforce the source quota in Save**, across all replicas sharing that store. Treat
nonpositive limits as 10 and return `ErrFlowSourceFull` for a full source. Quota
checking and record insertion must be one transaction, not separate count/write
operations. Count only unexpired records; consume/expiry must release quota and
rejected/cancelled saves must not leak reservations. Bound any source indexes and
expire/delete empty counters. Configure consistent limits and proxy policies on
all replicas. The strategy cannot enforce distributed admission for an injected
store that ignores this contract; existing custom stores must be updated.

Treat all fields as opaque, preserve them exactly, honor cancellation, bound
storage, and protect nonce/verifier confidentiality with appropriate backend
access controls and encryption. `Provider` is an internal binding fingerprint,
not a display name or a store namespace supplied by the application. Namespace
backend keys for the deployment, not the replica. Keep clocks synchronized.

The caller owns injected store resources and closes them after all users stop;
neither strategy replacement nor `Auth.Close` closes an injected shared store.
No Redis/SQL FlowStore adapter is introduced in this change.

## Sessions and Responses

- `issuer.IsTerminal(error)` recognizes wrapped `ErrNotFound`, `ErrRevoked`,
  `ErrAccessExpired`, `ErrRefreshExpired`, and `ErrRefreshInvalid`. Conflicts,
  cancellation, and deadlines take precedence and are nonterminal. Custom issuers
  must wrap these known sentinels for credential failures; arbitrary errors now
  mean infrastructure failure, not logout.
- `Session.Require` clears credentials only for terminal authentication failures
  or an explicitly rejected identity. Existing browser redirects remain; clients
  disabling redirects receive 401. Unknown resolve/refresh errors return 503
  `session_unavailable`, with no clearing cookie or login redirect. Existing
  bounded refresh-conflict recovery is preserved.
- Direct `/me` resolution is a nonmutating snapshot: expired access tokens or
  pending-MFA identities return 401; storage failures return 503. It never
  refreshes, rotates, or clears cookies. Clients needing renewal should use the
  explicit refresh endpoint or a protected route with `Require`. A preceding
  `Require` middleware may still refresh before `/me` runs.
- `issuer.Token.ExpiredAt(now)` expires at equality, not only after expiry. Zero
  expiry retains the existing never-expiring semantics.
- Auth JSON/error helpers, including standalone strategy helpers, now send
  `Cache-Control: no-store`. OAuth initiation/callback responses and session login
  redirects also carry it. Error envelope shapes are unchanged.

## Diagnostics

OAuth logging no longer includes raw upstream error bodies, callback descriptions,
issuer URLs, transport URL errors, claims, or token material. Token/userinfo errors
retain only operation, numeric HTTP status, and an allowlisted OAuth error code;
unknown codes become `unknown`. Discovery and logout returned errors are also
sanitized. The safe upstream-size sentinel remains detectable with `errors.Is`.
Applications and reverse proxies must independently avoid logging callback query
strings, cookies, credentials, or authorization headers in access logs.
