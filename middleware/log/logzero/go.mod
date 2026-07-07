module github.com/rakunlabs/ada/middleware/log/logzero

go 1.24

require (
	github.com/rakunlabs/ada/middleware/log v0.0.0-00010101000000-000000000000
	github.com/rs/zerolog v1.34.0
)

replace github.com/rakunlabs/ada/middleware/log => ../

require (
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/lmittmann/tint v1.1.2 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/rakunlabs/logi v0.4.5 // indirect
	golang.org/x/sys v0.35.0 // indirect
)
