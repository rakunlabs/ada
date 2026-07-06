module github.com/rakunlabs/ada/middleware/auth/sessionstore/redis

go 1.24

require (
	github.com/rakunlabs/ada/middleware/auth v0.4.6
	github.com/redis/go-redis/v9 v9.14.0
	github.com/twmb/tlscfg v1.3.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
)

replace github.com/rakunlabs/ada/middleware/auth => ../..

replace github.com/rakunlabs/ada/handler/folder => ../../../../handler/folder
