module github.com/rakunlabs/ada/examples

go 1.24

require (
	github.com/rakunlabs/ada v0.0.0-00010101000000-000000000000
	github.com/rakunlabs/ada/middleware/log v0.0.0-00010101000000-000000000000
	github.com/rakunlabs/ada/middleware/mcp v0.0.0-00010101000000-000000000000
	github.com/rakunlabs/ada/middleware/recover v0.0.0-00010101000000-000000000000
	github.com/rakunlabs/ada/middleware/requestid v0.0.0-00010101000000-000000000000
	github.com/rakunlabs/into v0.4.1
	github.com/rakunlabs/logi v0.4.1
)

require (
	github.com/lmittmann/tint v1.1.2 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/oklog/ulid/v2 v2.1.1 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.27.0 // indirect
)

replace github.com/rakunlabs/ada => ../

replace github.com/rakunlabs/ada/middleware/mcp => ../middleware/mcp

replace github.com/rakunlabs/ada/middleware/recover => ../middleware/recover

replace github.com/rakunlabs/ada/middleware/requestid => ../middleware/requestid

replace github.com/rakunlabs/ada/middleware/log => ../middleware/log

replace github.com/rakunlabs/ada/middleware/cors => ../middleware/cors
