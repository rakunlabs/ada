module github.com/rakunlabs/ada/middleware/auth

go 1.25.0

require (
	github.com/rakunlabs/ada/handler/folder v0.4.10
	github.com/rakunlabs/ada/utils/proxy v0.4.10
)

replace github.com/rakunlabs/ada/handler/folder => ../../handler/folder

replace github.com/rakunlabs/ada/utils/proxy => ../../utils/proxy
