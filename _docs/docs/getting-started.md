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
