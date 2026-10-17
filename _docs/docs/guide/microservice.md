# Microservice

Most services need the same baseline middleware stack. This page lists a recommended set and the order to register it in.

## Recommended Stack

| Middleware | Purpose |
|---|---|
| [Recover](./middleware/recover) | Recovers from panics anywhere in the chain, so it goes **first** |
| [Server](./middleware/server) | Adds the `Server` response header |
| [CORS](./middleware/cors) | Handles cross-origin requests; usually needed when there is no reverse proxy in front |
| [Request ID](./middleware/request-id) | Assigns a unique ID per request for logging and tracing |
| [Log](./middleware/log) | Logs request and response details |
| [Telemetry](./middleware/telemetry) | Collects OpenTelemetry metrics and traces |

## Usage

```go
import (
    "github.com/rakunlabs/ada"

    mcors "github.com/rakunlabs/ada/middleware/cors"
    mlog "github.com/rakunlabs/ada/middleware/log"
    mrecover "github.com/rakunlabs/ada/middleware/recover"
    mrequestid "github.com/rakunlabs/ada/middleware/requestid"
    mserver "github.com/rakunlabs/ada/middleware/server"
    mtelemetry "github.com/rakunlabs/ada/middleware/telemetry"
)

// /////////////

server := ada.New()
server.Use(
    mrecover.Middleware(),
    mserver.Middleware("my-server/v0.1.0"),
    mcors.Middleware(),
    mrequestid.Middleware(),
    mlog.Middleware(),
    mtelemetry.Middleware(),
)
```

::: tip
Add [Body Limit](./middleware/bodylimit) and [Timeout](./middleware/timeout) as well when the service accepts request bodies or calls slow dependencies.
:::
