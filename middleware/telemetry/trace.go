package telemetry

import (
	"fmt"
	"net/http"

	"github.com/rakunlabs/ada/utils/proxy"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
)

// RequestTraceAttrs returns HTTP server span attributes using the immediate
// peer as client.address. Forwarding headers are ignored.
func RequestTraceAttrs(req *http.Request) []attribute.KeyValue {
	return requestTraceAttrs(req, proxy.Policy{}, false)
}

// TrustedRequestTraceAttrs returns an attribute helper backed by validated
// trusted proxy CIDRs.
func TrustedRequestTraceAttrs(cidrs ...string) func(*http.Request) []attribute.KeyValue {
	policy, err := proxy.New(cidrs...)
	if err != nil {
		panic(fmt.Errorf("telemetry: trusted proxies: %w", err))
	}

	return func(req *http.Request) []attribute.KeyValue {
		return requestTraceAttrs(req, policy, false)
	}
}

// UnsafeRequestTraceAttrs trusts client IP forwarding headers from every
// peer. Prefer TrustedRequestTraceAttrs.
func UnsafeRequestTraceAttrs(req *http.Request) []attribute.KeyValue {
	return requestTraceAttrs(req, proxy.Policy{}, true)
}

func requestTraceAttrs(req *http.Request, policy proxy.Policy, unsafe bool) []attribute.KeyValue {
	count := 3 // ServerAddress, Method, Scheme

	var host string
	var p int
	host, p = splitHostPort(req.Host)

	hostPort := requiredHTTPPort(req.TLS != nil, p)
	if hostPort > 0 {
		count++
	}

	clientName := req.Header.Get("Server")
	if clientName != "" {
		count++
	}

	method, methodOriginal := method(req.Method)
	if methodOriginal != (attribute.KeyValue{}) {
		count++
	}

	scheme := schemeReq(req)

	_, peerPort := splitHostPort(req.RemoteAddr)
	peer, peerErr := proxy.ClientIP(req)
	if peerErr == nil {
		// The Go HTTP server sets RemoteAddr to "IP:port", this will not be a
		// file-path that would be interpreted with a sock family.
		count++
		if peerPort > 0 {
			count++
		}
	}

	useragent := req.UserAgent()
	if useragent != "" {
		count++
	}

	var clientIP string
	var clientErr error
	if unsafe {
		clientIP, clientErr = proxy.UnsafeClientIP(req)
	} else {
		clientIP, clientErr = policy.ClientIP(req)
	}
	if clientErr != nil {
		clientIP = peer
	}
	if clientIP != "" {
		count++
	}

	if req.URL != nil && req.URL.Path != "" {
		count++
	}

	protoName, protoVersion := netProtocol(req.Proto)
	if protoName != "" && protoName != "http" {
		count++
	}
	if protoVersion != "" {
		count++
	}

	route := httpRoute(req.Pattern)
	if route != "" {
		count++
	}

	attrs := make([]attribute.KeyValue, 0, count)
	attrs = append(attrs,
		semconv.ServerAddress(host),
		method,
		scheme,
	)

	if hostPort > 0 {
		attrs = append(attrs, semconv.ServerPort(hostPort))
	}
	if methodOriginal != (attribute.KeyValue{}) {
		attrs = append(attrs, methodOriginal)
	}

	if peer != "" {
		// The Go HTTP server sets RemoteAddr to "IP:port", this will not be a
		// file-path that would be interpreted with a sock family.
		attrs = append(attrs, semconv.NetworkPeerAddress(peer))
		if peerPort > 0 {
			attrs = append(attrs, semconv.NetworkPeerPort(peerPort))
		}
	}

	if useragent != "" {
		attrs = append(attrs, semconv.UserAgentOriginal(useragent))
	}

	if clientIP != "" {
		attrs = append(attrs, semconv.ClientAddress(clientIP))
	}

	if clientName != "" {
		attrs = append(attrs, attribute.Key("client.name").String(clientName))
	}

	if req.URL != nil && req.URL.Path != "" {
		attrs = append(attrs, semconv.URLPath(req.URL.Path))
	}

	if protoName != "" && protoName != "http" {
		attrs = append(attrs, semconv.NetworkProtocolName(protoName))
	}
	if protoVersion != "" {
		attrs = append(attrs, semconv.NetworkProtocolVersion(protoVersion))
	}

	if route != "" {
		attrs = append(attrs, routeAttr(route))
	}

	return attrs
}

type ResponseTelemetry struct {
	StatusCode int
	ReadBytes  int64
	WriteBytes int64
}

func ResponseTraceAttrs(resp ResponseTelemetry) []attribute.KeyValue {
	var count int

	if resp.ReadBytes > 0 {
		count++
	}
	if resp.WriteBytes > 0 {
		count++
	}
	if resp.StatusCode > 0 {
		count++
	}

	attributes := make([]attribute.KeyValue, 0, count)

	if resp.ReadBytes > 0 {
		attributes = append(attributes,
			semconv.HTTPRequestBodySize(int(resp.ReadBytes)),
		)
	}
	if resp.WriteBytes > 0 {
		attributes = append(attributes,
			semconv.HTTPResponseBodySize(int(resp.WriteBytes)),
		)
	}
	if resp.StatusCode > 0 {
		attributes = append(attributes,
			semconv.HTTPResponseStatusCode(resp.StatusCode),
		)
	}

	return attributes
}
