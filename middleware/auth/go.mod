module github.com/rakunlabs/ada/middleware/auth

go 1.25.0

require (
	github.com/rakunlabs/ada/handler/folder v0.5.0
	github.com/rakunlabs/ada/utils/proxy v0.5.0
)

replace github.com/rakunlabs/ada/handler/folder => ../../handler/folder

replace github.com/rakunlabs/ada/utils/proxy => ../../utils/proxy
