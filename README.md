<img src="./_docs/docs/public/assets/ada.png" alt="ada" width="240">

[![License](https://img.shields.io/github/license/rakunlabs/ada?color=red&style=flat-square)](https://raw.githubusercontent.com/rakunlabs/ada/main/LICENSE)
[![Coverage](https://img.shields.io/sonar/coverage/rakunlabs_ada?logo=sonarcloud&server=https%3A%2F%2Fsonarcloud.io&style=flat-square)](https://sonarcloud.io/summary/overall?id=rakunlabs_ada)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/rakunlabs/ada/test.yml?branch=main&logo=github&style=flat-square&label=ci)](https://github.com/rakunlabs/ada/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/rakunlabs/ada?style=flat-square)](https://goreportcard.com/report/github.com/rakunlabs/ada)
[![Go PKG](https://raw.githubusercontent.com/rakunlabs/.github/main/assets/badges/gopkg.svg)](https://pkg.go.dev/github.com/rakunlabs/ada)
[![Web](https://img.shields.io/badge/web-document-blueviolet?style=flat-square)](https://rakunlabs.github.io/ada/)

Simple, flexible go web library.

```sh
go get github.com/rakunlabs/ada
```

## Usage

> Check out the [examples](https://rakunlabs.github.io/ada/) for more details.

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

// /////////////////////

server := ada.New()
server.POST("/hello", SayHello)

server.Start(ctx, ":8080")
```
