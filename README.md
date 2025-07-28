<img src="./_docs/docs/public/assets/ada.png" alt="ada" width="240">

[![License](https://img.shields.io/github/license/rakunlabs/ada?color=red&style=flat-square)](https://raw.githubusercontent.com/rakunlabs/ada/main/LICENSE)
[![Coverage](https://img.shields.io/sonar/coverage/rakunlabs_ada?logo=sonarcloud&server=https%3A%2F%2Fsonarcloud.io&style=flat-square)](https://sonarcloud.io/summary/overall?id=rakunlabs_ada)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/rakunlabs/ada/test.yml?branch=main&logo=github&style=flat-square&label=ci)](https://github.com/rakunlabs/ada/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/rakunlabs/ada?style=flat-square)](https://goreportcard.com/report/github.com/rakunlabs/ada)
[![Go PKG](https://raw.githubusercontent.com/rakunlabs/.github/main/assets/badges/gopkg.svg)](https://pkg.go.dev/github.com/rakunlabs/ada)

Simple HTTP server.

```sh
go get github.com/rakunlabs/ada
```

## Usage

```go
import (
	"github.com/rakunlabs/ada"
)

func SayHello(w http.ResponseWriter, r *http.Request) {
	v, _ := io.ReadAll(r.Body)

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello, " + string(v)))
}

server, err := ada.New(ctx, func(ctx context.Context, mux *ada.Mux) error {
    mux.POST("/hello", SayHello)

    return nil
})
// ...
return server.Start(ctx, ":8080")
```
