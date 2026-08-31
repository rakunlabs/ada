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
