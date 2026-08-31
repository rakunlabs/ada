module github.com/rakunlabs/ada/middleware/ratelimit

go 1.24

require (
	github.com/rakunlabs/ada/utils/proxy v0.5.0
	github.com/rakunlabs/cache v0.3.3
	github.com/rakunlabs/tummy v0.1.2
)

replace github.com/rakunlabs/ada/utils/proxy => ../../utils/proxy
