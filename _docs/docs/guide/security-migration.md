# Security Migration Notes

Recent releases make trust boundaries explicit and fail closed where request
metadata can affect identity, rate limits, telemetry, or browser access.

## Forwarded Headers

Forwarding headers are now ignored by default. Configure the CIDRs of proxies
that connect directly to Ada; do not list arbitrary client networks. The proxy
must overwrite incoming forwarding headers rather than append values supplied
by the client.

| Component | Secure configuration | Compatibility option |
|---|---|---|
| [Request log](./middleware/log) | `log.WithTrustedProxies(cidrs...)` | `log.WithUnsafeProxyHeaders()` |
| [Rate limit](./middleware/ratelimit) | `ratelimit.WithTrustedProxies(cidrs...)` or `KeyByRealIPWithTrustedProxies(cidrs...)` | `ratelimit.WithUnsafeProxyHeaders()` |
| [Telemetry](./middleware/telemetry) | `telemetry.WithTrustedProxies(cidrs...)` | `telemetry.WithUnsafeProxyHeaders()` |
| [Header auth](./middleware/auth#header-proxy-strategy) | `header.WithTrustedProxies(cidrs...)`, `WithSharedSecret(...)`, or both | `header.WithUnsafeTrustAll()` |
| [Magic link](./middleware/auth#magic-link-strategy) | `magiclink.WithVerifyBaseURL(origin)` or `WithTrustedProxies(cidrs...)` | `magiclink.WithUnsafeRequestOrigin()` |
| [OAuth2](./middleware/auth#oauth2--oidc-strategy) | `CallbackBaseURL` or `TrustedProxies` | `UnsafeTrustAllForwardedHeaders` |

The compatibility options restore legacy trust-all behavior. They are unsafe
when untrusted clients can connect directly and should be temporary migration
tools, not the default deployment configuration.

## Auth Responses And MFA

- Header auth rejects login when no trust option is configured.
- Magic-link sending fails with `verify_origin_unavailable` when no fixed public
  origin or matching trusted-proxy policy is available.
- `POST /login/refresh` returns the refreshed identity only. The opaque session
  ID remains in its `HttpOnly` cookie and is no longer exposed as `session_id`.
- `WithIssuer` plus `WithSecondFactor` requires `WithPendingIssuer`. The pending
  issuer must implement `issuer.AtomicUpdater`, report atomic updates, and
  expire no later than `MFA.TTL`.
- Auth strategies now enforce their existing request-body caps instead of
  silently truncating oversized input and reporting a parse error. Local, LDAP,
  magic-link and OAuth2 requests are capped at 64 KiB, TOTP at 16 KiB, and
  passkey at 128 KiB; exceeding a cap answers `413 body_too_large`.
- OAuth2 discovery, token, UserInfo and JWKS responses retain their 1 MiB caps,
  but an oversized identity-provider response is now reported as an upstream
  size failure rather than malformed truncated JSON.
- A failed JWKS refresh uses a short retry backoff instead of blocking refresh
  for the full successful-fetch cooldown. A JWT without `kid` is rejected
  immediately when the key set contains multiple usable keys.

## Request And Browser Defaults

- **There is no default request body size limit.**
  [Binding](./binding#request-body-limit) previously capped the total body at
  1 MiB; `bind.DefaultBodyLimit` is now `0` (disabled). Nothing bounds a request
  body until you impose a limit, and what an unbounded request exhausts depends
  on the content type:
  - JSON, XML and URL-encoded bodies are read **entirely into memory**, so an
    unbounded request is an unbounded allocation.
  - Multipart bodies buffer up to `bind.DefaultMultipartFormMaxMemory` (plus the
    10 MiB Go reserves for non-file parts) and then **spool the remainder to
    temporary files on disk**, so an unbounded upload exhausts disk rather than
    memory. Those temporary files are cleaned up, but not before the request
    finishes.

  Add the [body-limit middleware](./middleware/bodylimit) —
  `mux.Use(bodylimit.Middleware(2 << 20))` — or enforce a body size limit at
  your reverse proxy. If routes need different limits, use non-overlapping
  groups or skip those routes in the global limiter and limit them separately.
  A nested limit cannot raise an outer middleware or proxy limit; the smallest
  limit remains effective.
- The old default was removed because it protected the wrong thing: it only
  applied to requests that went through `bind`, never to handlers reading
  `r.Body` directly, and it rejected oversized bodies as a redacted `500`.
  Exceeding a limit now answers `413 Content Too Large` with a message naming
  the limit. Clients and monitoring that keyed on the `500` must be updated.
- `bind.WithBodyLimit(n)` still sets a per-bind limit, and `bind.WithBodyLimit(0)`
  still means "no limit" — it is now simply the default rather than an opt-out.
- The query separator now applies only to slices of scalar values. Scalar and
  JSON-valued fields preserve commas, so `?name=Doe,%20John` binds as
  `"Doe, John"` instead of silently becoming `"Doe"`. Malformed query escapes
  now return a binding error instead of disappearing from `URL.Query()`.
- Removing the 1 MiB cap makes `bind.DefaultMultipartFormMaxMemory` (32 MiB)
  reachable again; it was previously capped away by the total body limit. Note
  that it is a memory/disk threshold, **not** a size limit — it never rejects a
  request. Only the body-limit middleware or your proxy can do that.
- [CORS](./middleware/cors#allowheaders) no longer reflects requested headers
  when `AllowHeaders` is empty. Explicitly allow the required headers.
- Credentialed CORS requires explicit origins. The wildcard-origin combination
  is rejected unless `UnsafeWildcardOriginWithAllowCredentials` is enabled.
- [Wildcard helpers](./routing#wildcard-routes) register descendants only:
  `HandleFuncWildcard("/assets", ...)` does not register the exact `/assets`
  path.
- The default error handler no longer echoes arbitrary error text. A
  `*ada.HTTPError` with a 4xx/5xx status still sends its own message, and an
  error you deliberately answer 4xx with still sends its text; any other error
  resolved to a 5xx now sends the generic status text and logs the real error
  with `slog` at Error level. Set a `Mux.ErrorHandler` to choose a different
  policy. Text wrapped *around* an `HTTPError` is no longer published.
- `ada.NewHTTPError(code, ...)` only sets the response status when `code` is an
  error status. A 2xx/3xx/zero `Code` on a returned error is now promoted to 500
  instead of answering success with an error body.
- Clearing `ada.DefaultErrHandler` no longer yields `200` with an empty body;
  the normalised status is written as a plain-text response.
- `Context.Bind` accepts bind options — use
  `c.Bind(&obj, bind.WithBodyLimit(n))` to cap a single endpoint more tightly
  than its route's body-limit middleware.
- [Route selection](./routing#http-methods) is method-aware, so a path that
  matches a node registered under another method no longer ends the search:
  requests that used to answer `405` now reach the parameterised or wildcard
  route that can serve them. Valid method tokens are normalized to uppercase,
  so `HandleWithMethod("get", ...)` registers `GET` instead of an unreachable
  lowercase route. Invalid RFC 9110 tokens still panic at setup; `""` remains
  the `Handle`/`HandleFunc` catch-all.
- A [`Group`](./routing#route-groups) inherits its parent's `NotFound`,
  `MethodNotAllowed` and `Use` even when they are configured after the group is
  created. Previously the group froze a copy of the parent at creation time and
  claimed its prefix, so a later root `NotFound` or `Use` never applied below
  that prefix. A group that sets its own still wins, for that behavior only.

## Rate Limiting

- Under the default fail-closed policy, downstream responses are buffered until
  the attempt is persisted. A response larger than `ResponseBufferLimit` (1 MiB
  by default) now answers `500 response_too_large` and reaches `OnError`; it is
  no longer misreported as `503 rate_limit_unavailable`. The attempt remains
  counted because the protected handler ran and produced a countable status.
- Fail-closed buffering cannot support SSE, WebSocket upgrades, or other
  streaming responses. Flush attempts now return `ErrStreamingUnsupported` and
  reach `OnError`. Use fail-open policy or scope the limiter to a separate,
  non-streaming authentication request when streaming is required.
- `NewMemoryStore` no longer evicts a live bucket to make room, because doing so
  resets that key's counter. It reclaims expired state; if capacity is full of
  live state, the store returns an error and `ErrorPolicy` decides whether to
  fail closed or open. Capacity bounds active bucket keys, not total memory:
  buckets retain each live attempt timestamp and in-flight reservation. A hard
  threshold bounds those records for a normally governed key; a soft-only
  limiter does not, even when `BackoffMax` is set.
- Configurable limiter construction now panics when both `SoftThreshold` and
  `HardThreshold` are zero. Omit the middleware to disable enforcement.
- `LimitAll`, `LimitByIP`, and related simple helpers now panic during setup for
  a non-positive request limit or window. Omit the middleware to disable it.

## Configuration Validation

- Encoding middleware supports `gzip` only. Empty, duplicate, or unsupported
  configured encodings now panic during construction instead of silently
  passing responses through. Eligible responses are still streamed and gzip is
  applied regardless of body size.
- CORS wildcard/regex matching now accepts legal origins containing a port up
  to its documented bounded input size. `OnOriginTooLong` can observe requests
  rejected for exceeding that bound; ordinary policy denials remain unchanged.
- `securecookie.DefaultMaxLength` is an encoded-value budget, not a 4 KiB
  application-payload budget. The default leaves roughly 2.2 KiB for the tested
  session-shaped value. Use `CookieStore.MaxLength` or `Codec.SetMaxLength` at
  setup time when a different budget is required, while accounting for the
  complete cookie name and attributes in browser limits.

## Path Normalization Is Not Performed

Unlike `net/http.ServeMux`, Ada matches the decoded `r.URL.Path` verbatim: no
`path.Clean`, no canonicalizing redirect. This is intentional and is **not**
going to change — but it moves normalization into your handlers.

- Every `r.PathValue` result is attacker-controlled. Greedy captures (`*`,
  `{name...}`) can contain `..`, `.`, and empty segments, whether sent literally
  (`/static/../../etc/passwd`) or percent-encoded (`/static/..%2f..%2fetc/passwd`)
  — both decode to the same value before matching.
- Clean and confine any captured value before using it as a filesystem path.
  Prefer `os.OpenRoot`/`fs.FS` or the [`handler/folder`](./handler/folder)
  handler over `filepath.Join` on raw input.
- `%2F` in a request decodes to a real separator, so a single-segment `{name}`
  param can never capture a slash: `GET /users/a%2Fb` is matched as
  `/users/a/b` and 404s. Carry such identifiers in a query parameter, the body,
  or a slash-free encoding.

See [Path handling and captured values](./routing#path-handling) for details and
a safe file-serving pattern.
