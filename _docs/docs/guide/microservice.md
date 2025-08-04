# Microservice

While creating a microservice we need to have basic middlewares should be available to use.

## Usage

- _recover_: Recover from panics anywhere in the chain so should be the first middleware.
- _cors_: Enable CORS for all requests as default, this usually required if you not have a reverse proxy.
- _requestid_: Generate a unique request ID for each request, useful for logging and tracing.
- _log_: Log the request and response details, useful for debugging and monitoring.
- _metrichttp_: OpenTelemetry Collect HTTP metrics like request count, response time, etc.
- _tracehttp_: OpenTelemetry Trace HTTP requests for distributed tracing, useful for monitoring and debugging.

```go
import (
    "github.com/rakunlabs/ada"
    mcors "github.com/rakunlabs/ada/middleware/cors"
    mfolder "github.com/rakunlabs/ada/middleware/folder"
    mlog "github.com/rakunlabs/ada/middleware/log"
    mrecover "github.com/rakunlabs/ada/middleware/recover"
    mrequestid "github.com/rakunlabs/ada/middleware/requestid"
    "github.com/worldline-go/tell/metric/metrichttp"
    "github.com/worldline-go/tell/trace/tracehttp"
)

// /////////////

server := ada.New()
server.Use(
    mrecover.Middleware(),
    mcors.Middleware(),
    mrequestid.Middleware(),
    mlog.Middleware(),
    metrichttp.Middleware(),
    tracehttp.Middleware(),
)
```
