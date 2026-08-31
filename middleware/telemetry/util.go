package telemetry

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
)

// spanNameFormatter returns the semconv based default span name.
func spanNameFormatter(routeName string, r *http.Request) string {
	method := r.Method
	return method + " " + routeName
}

func handleErr(err error) {
	if err != nil {
		otel.Handle(err)
	}
}

func routeAttr(route string) attribute.KeyValue {
	return semconv.HTTPRoute(route)
}

func requiredHTTPPort(https bool, port int) int {
	if https {
		if port > 0 && port != 443 {
			return port
		}
	} else {
		if port > 0 && port != 80 {
			return port
		}
	}

	return -1
}

func schemeReq(req *http.Request) attribute.KeyValue {
	return semconv.URLScheme(serverScheme(req))
}

func serverScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}

	return "http"
}

func metricStatus(code int) (codes.Code, string) {
	if code < 100 || code >= 600 {
		return codes.Error, fmt.Sprintf("Invalid HTTP status code %d", code)
	}
	if code >= 500 {
		return codes.Error, ""
	}
	return codes.Unset, ""
}

func netProtocol(proto string) (name string, version string) {
	name, version, _ = strings.Cut(proto, "/")
	switch name {
	case "HTTP":
		name = "http"
	case "QUIC":
		name = "quic"
	case "SPDY":
		name = "spdy"
	default:
		name = strings.ToLower(name)
	}

	return name, version
}

func httpRoute(pattern string) string {
	if idx := strings.IndexByte(pattern, '/'); idx >= 0 {
		return pattern[idx:]
	}

	return ""
}

func method(method string) (attribute.KeyValue, attribute.KeyValue) {
	if method == "" {
		return semconv.HTTPRequestMethodGet, attribute.KeyValue{}
	}
	if attr, ok := methodLookup[method]; ok {
		return attr, attribute.KeyValue{}
	}

	orig := semconv.HTTPRequestMethodOriginal(method)

	attr, ok := methodLookup[strings.ToUpper(method)]
	if ok {
		return attr, orig
	}

	return semconv.HTTPRequestMethodKey.String(standardizeHTTPMethod(method)), orig
}

func standardizeHTTPMethod(method string) string {
	method = strings.ToUpper(method)
	switch method {
	case http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPatch, http.MethodPost, http.MethodPut, http.MethodTrace:
	default:
		method = "_OTHER"
	}

	return method
}

var methodLookup = map[string]attribute.KeyValue{
	http.MethodConnect: semconv.HTTPRequestMethodConnect,
	http.MethodDelete:  semconv.HTTPRequestMethodDelete,
	http.MethodGet:     semconv.HTTPRequestMethodGet,
	http.MethodHead:    semconv.HTTPRequestMethodHead,
	http.MethodOptions: semconv.HTTPRequestMethodOptions,
	http.MethodPatch:   semconv.HTTPRequestMethodPatch,
	http.MethodPost:    semconv.HTTPRequestMethodPost,
	http.MethodPut:     semconv.HTTPRequestMethodPut,
	http.MethodTrace:   semconv.HTTPRequestMethodTrace,
}

func splitHostPort(hostport string) (host string, port int) {
	port = -1

	if strings.HasPrefix(hostport, "[") {
		addrEnd := strings.LastIndexByte(hostport, ']')
		if addrEnd < 0 {
			// Invalid hostport.
			return
		}
		if i := strings.LastIndexByte(hostport[addrEnd:], ':'); i < 0 {
			host = hostport[1:addrEnd]
			return
		}
	} else {
		if i := strings.LastIndexByte(hostport, ':'); i < 0 {
			host = hostport
			return
		}
	}

	host, pStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return
	}

	p, err := strconv.ParseUint(pStr, 10, 16)
	if err != nil {
		return
	}
	return host, int(p) // nolint: gosec  // Byte size checked 16 above.
}

func extractRoute(r *http.Request) string {
	return r.Pattern
}
