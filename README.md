<img src="./_docs/docs/public/assets/ada.png" alt="ada" width="240">

[![License](https://img.shields.io/github/license/rakunlabs/ada?color=red&style=flat-square)](https://raw.githubusercontent.com/rakunlabs/ada/main/LICENSE)
[![Coverage](https://img.shields.io/sonar/coverage/rakunlabs_ada?logo=sonarcloud&server=https%3A%2F%2Fsonarcloud.io&style=flat-square)](https://sonarcloud.io/summary/overall?id=rakunlabs_ada)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/rakunlabs/ada/test.yml?branch=main&logo=github&style=flat-square&label=ci)](https://github.com/rakunlabs/ada/actions)
[![Go PKG](https://raw.githubusercontent.com/rakunlabs/.github/main/assets/badges/gopkg.svg)](https://pkg.go.dev/github.com/rakunlabs/ada)
[![Web](https://img.shields.io/badge/web-document-blueviolet?style=flat-square)](https://rakunlabs.github.io/ada/)

Simple, flexible go web framework.

```sh
go get github.com/rakunlabs/ada
```

## Usage

> Check out the [guide](https://rakunlabs.github.io/ada/guide) for more details.

```go
package main

import (
	"net/http"

	"github.com/rakunlabs/ada"
)

func main() {
	server := ada.New()
	server.GET("/hello/{user}", SayHello)

	server.Start(":8080")
}

// /////////////////////

func SayHello(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, " + r.PathValue("user")))
}
```

Context-style handlers may also use `func(c *ada.Context) error`. Handler
contexts are pooled and are valid only until the handler returns; copy the
request data needed by background work instead of retaining `*ada.Context`.
`mux.WrapUnpooled` is available for compatibility when retaining the Context
itself is unavoidable.

## Runtime Route Reload

Add and remove routes on a running server. A request keeps the routing table it
started with, so in-flight work is never disturbed:

```go
server.GET("/beta/feature", betaHandler)   // add at runtime
server.Remove(http.MethodGet, "/beta/feature") // remove at runtime

for _, r := range server.Routes() {
    log.Println(r.Method, r.Pattern)
}
```

Groups share their parent's routing table and resolve `Remove` against their own
prefix:

```go
api := server.Group("/api")
api.GET("/users", listUsers)
api.Remove(http.MethodGet, "/users") // removes /api/users
```

Middlewares (`Use`, `Group`, `NotFound`, …) stay setup-time; use a `Slot` or
`Pipeline` below to change those at runtime.

## Runtime Middleware Reload

Replace, disable, or add middlewares at runtime without restarting:

```go
auth := ada.NewSlot(forwardauth.Middleware(
    forwardauth.WithAddress("http://auth:8080/verify"),
))
server.Use(auth.Middleware())

// Hot-swap at runtime
auth.Replace(forwardauth.Middleware(forwardauth.WithAddress("http://auth-v2:8080")))
auth.Disable()  // bypass
auth.Enable()   // restore

// Or manage multiple middlewares by key
stack := ada.NewPipeline()
stack.Set("cors", cors.Middleware(...))
stack.Set("auth", forwardauth.Middleware(...))
server.Use(stack.Middleware())

stack.Set("ratelimit", ratelimit.Middleware(...))  // add at runtime
stack.Remove("auth")                                // remove at runtime
```

See the [Runtime Reload guide](https://rakunlabs.github.io/ada/guide/middleware/runtime-reload) for full details.
