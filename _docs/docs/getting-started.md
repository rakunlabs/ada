# Getting Started

Ada is a simple, flexible Go web library that allows you to build web applications with our mux and middlewares.

Get `ada` with golang package manager:

```sh
go get github.com/rakunlabs/ada
```

## Simple Start

```go
package main

import (
    "context"
    "io"
    "net/http"

    "github.com/rakunlabs/ada"
)

func main() {
    server := ada.New()
	server.GET("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, World!"))
	})

	server.Start(ctx, ":8080")
}
```
