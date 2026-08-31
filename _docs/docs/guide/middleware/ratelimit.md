# Rate Limit

The rate-limit module provides a lightweight request limiter and a configurable
sliding-window limiter for sensitive endpoints.

```go
import (
    "net/http"
    "time"

    "github.com/rakunlabs/ada/middleware/ratelimit"
)
```

## General Traffic

Limit all traffic or key it by the immediate client connection:

```go
// Choose one policy.
mux.Use(ratelimit.LimitAll(1_000, time.Minute))
// Or limit independently by immediate peer address.
mux.Use(ratelimit.LimitByIP(100, time.Minute))
```

`LimitByRealIP` also uses the immediate peer by default. It deliberately
ignores `X-Forwarded-For`, `X-Real-IP`, and `True-Client-IP` unless the direct
proxy is trusted:

```go
mux.Use(ratelimit.LimitByRealIP(
    100,
    time.Minute,
    ratelimit.WithTrustedProxies("10.0.0.0/8", "fd00::/8"),
))
```

Configure the CIDRs of the proxies that connect directly to Ada, and make those
proxies overwrite client-supplied forwarding headers. The compatibility option
`ratelimit.WithUnsafeProxyHeaders()` trusts forwarding headers from every peer;
use it only behind a separately enforced network boundary.

## Sensitive Endpoints

The configurable limiter can count selected responses, apply backoff, and
reject repeated attempts. Build the trusted client-IP function once and use it
as part of the limiter key:

```go
store, err := ratelimit.NewMemoryStore(10_000)
if err != nil {
    return err
}

clientIP := ratelimit.KeyByRealIPWithTrustedProxies("10.0.0.0/8")
loginLimit := ratelimit.Middleware(ratelimit.Config{
    Window:        15 * time.Minute,
    SoftThreshold: 3,
    HardThreshold: 30,
    BackoffBase:   time.Second,
    BackoffMax:    15 * time.Second,
    KeyFunc: func(r *http.Request) []string {
        return []string{"ip:" + clientIP(r)}
    },
    ShouldCount: func(_ *http.Request, status int) bool {
        return status == http.StatusUnauthorized
    },
    Store: store,
})

mux.Use(loginLimit)
```

`NewMemoryStore` coordinates all middleware instances sharing that store in one
process. Distributed enforcement requires a backend implementing
`ratelimit.AtomicStore`; set `RequireAtomicStore` for deployments that must fail
at startup rather than silently use process-local coordination.

The memory store's capacity is a hard bound on bucket keys, not a bound on total
memory. It never evicts a bucket whose attempts are still inside the limiter
window or whose reservation is active, because doing so would reset that key's
limit. At capacity it reclaims empty buckets, expired reservations, and attempts
older than the longest window observed among middleware sharing the store. If
all buckets are live, the store returns an error: the default fail-closed policy
responds with `503`, while `ErrorPolicyFailOpen` runs the handler without
persisting that attempt. Increase capacity or use a shared backend when the
number of simultaneously active keys can exceed the bound.

Each bucket retains one timestamp per counted attempt still in `Window` and,
for atomic admission, one reservation plus lease per in-flight request. With a
fixed `HardThreshold`, normal admission keeps the combined live attempts and
reservations for that key at or below the threshold. A soft-only limiter has no
such record bound: `BackoffMax` caps delay but exact sliding-window decisions
still require all live attempt timestamps. Size memory for both active keys and
per-key traffic, shorten `Window`, enable a hard threshold, or use a backend
suited to the expected state volume. At least one of `SoftThreshold` and
`HardThreshold` must be enabled; construction panics when both are zero.

## Buffering And Streaming

The default fail-closed policy buffers the downstream response until the attempt
is persisted, ensuring a store failure cannot leak an uncounted success. The
buffer is limited by `ResponseBufferLimit` (`1 MiB` by default). If it overflows,
the attempt is still persisted and observed through `OnAttempt`, `OnError`
receives a `*ratelimit.ResponseTooLargeError` matching
`ratelimit.ErrResponseTooLarge`, and the client receives `500` with code
`response_too_large`. Downstream headers and partial body data are discarded.

Fail-closed buffering cannot stream. `http.ResponseController.Flush` returns
`ratelimit.ErrStreamingUnsupported`, and `OnError` reports the flush attempt
once after the handler returns. SSE, long polling, chunked progress, and
WebSocket endpoints should use `ErrorPolicyFailOpen` or apply this middleware
only to a separate, non-streaming authentication request.
