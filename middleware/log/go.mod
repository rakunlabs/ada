module github.com/rakunlabs/ada/middleware/log

go 1.24

require (
	github.com/felixge/httpsnoop v1.0.4
	github.com/rakunlabs/ada/utils/proxy v0.5.0
	github.com/rakunlabs/logi v0.4.5
)

replace github.com/rakunlabs/ada/utils/proxy => ../../utils/proxy

require (
	github.com/lmittmann/tint v1.1.2 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/sys v0.35.0 // indirect
)
