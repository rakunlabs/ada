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

## Request And Browser Defaults

- [Binding](./binding#request-body-limit) limits the total body to 1 MiB by
  default. Use `bind.WithBodyLimit(0)` only when compatibility with unlimited
  bodies is required.
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
  `c.Bind(&obj, bind.WithBodyLimit(0))` for the compatibility case above.
- [Route selection](./routing#http-methods) is method-aware, so a path that
  matches a node registered under another method no longer ends the search:
  requests that used to answer `405` now reach the parameterised or wildcard
  route that can serve them. Registering a non-canonical method —
  `HandleWithMethod("get", ...)` — now panics at setup instead of silently
  creating an unreachable route; use `"GET"`, or `""` for the
  `Handle`/`HandleFunc` catch-all.
- A [`Group`](./routing#route-groups) inherits its parent's `NotFound`,
  `MethodNotAllowed` and `Use` even when they are configured after the group is
  created. Previously the group froze a copy of the parent at creation time and
  claimed its prefix, so a later root `NotFound` or `Use` never applied below
  that prefix. A group that sets its own still wins, for that behavior only.

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
