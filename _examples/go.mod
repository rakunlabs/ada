module github.com/rakunlabs/ada/examples

go 1.24

require (
	github.com/rakunlabs/ada v0.0.0-00010101000000-000000000000
	github.com/rakunlabs/ada/middleware/log v0.0.0-00010101000000-000000000000
	github.com/rakunlabs/ada/middleware/mcp v0.0.0-00010101000000-000000000000
	github.com/rakunlabs/ada/middleware/recover v0.0.0-00010101000000-000000000000
	github.com/rakunlabs/ada/middleware/requestid v0.0.0-00010101000000-000000000000
	github.com/rakunlabs/ada/middleware/telemetry v0.0.0-00010101000000-000000000000
	github.com/rakunlabs/into v0.4.1
	github.com/rakunlabs/logi v0.4.1
	github.com/rakunlabs/tell v0.1.0
)

require (
	github.com/cenkalti/backoff/v5 v5.0.2 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.1 // indirect
	github.com/lmittmann/tint v1.1.2 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	github.com/twmb/tlscfg v1.2.1 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.62.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/runtime v0.62.0 // indirect
	go.opentelemetry.io/otel v1.37.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.37.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.37.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.37.0 // indirect
	go.opentelemetry.io/otel/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/sdk v1.37.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/trace v1.37.0 // indirect
	go.opentelemetry.io/proto/otlp v1.7.0 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	google.golang.org/grpc v1.75.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

replace github.com/rakunlabs/ada => ../

replace github.com/rakunlabs/ada/middleware/mcp => ../middleware/mcp

replace github.com/rakunlabs/ada/middleware/recover => ../middleware/recover

replace github.com/rakunlabs/ada/middleware/requestid => ../middleware/requestid

replace github.com/rakunlabs/ada/middleware/log => ../middleware/log

replace github.com/rakunlabs/ada/middleware/cors => ../middleware/cors

replace github.com/rakunlabs/ada/middleware/telemetry => ../middleware/telemetry
