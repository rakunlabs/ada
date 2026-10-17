# Getting Started

Ada is a simple, flexible Go web framework for building web applications with its own mux and middleware set.

## Installation

```sh
go get github.com/rakunlabs/ada
```

::: info Requirements
Ada requires **Go 1.27** or newer, matching the `go` directive in its `go.mod`.
:::

## Simple Start

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

```sh
curl http://localhost:8080/hello/ada
# Hello, ada
```

## Next Steps

- [Start Server](./guide/start) — graceful shutdown and server options
- [Routing](./guide/routing) — path parameters, wildcards, and groups
- [Middleware](./guide/middleware/) — the bundled middleware set
- [Microservice](./guide/microservice) — a recommended middleware stack
