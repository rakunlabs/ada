# Microservice

While creating a microservice we need to have basic middlewares should be available to use.

## Usage

- _recover_: Recover from panics anywhere in the chain so should be the first middleware.
- _server_: Add Server HTTP header to responses.
- _cors_: Enable CORS for all requests as default, this usually required if you not have a reverse proxy.
- _requestid_: Generate a unique request ID for each request, useful for logging and tracing.
- _log_: Log the request and response details, useful for debugging and monitoring.
- _telemetry_: OpenTelemetry collect metrics and trace.

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
