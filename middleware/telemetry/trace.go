package telemetry

import (
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
)

// RequestTraceAttrs returns HTTP server span attributes using the immediate
// peer as client.address. Forwarding headers are ignored; see WithClientIP to
// resolve them behind a proxy.
func RequestTraceAttrs(req *http.Request) []attribute.KeyValue {
	return requestTraceAttrs(req, nil)
}

// requestTraceAttrs builds the span attributes. resolveClientIP may be nil, in
// which case client.address is the immediate peer.
func requestTraceAttrs(req *http.Request, resolveClientIP func(*http.Request) string) []attribute.KeyValue {
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
	peer := clientIP(req)
	if peer != "" {
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

	clientAddr := peer
	if resolveClientIP != nil {
		if resolved := resolveClientIP(req); resolved != "" {
			clientAddr = resolved
		}
	}
	if clientAddr != "" {
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

	if clientAddr != "" {
		attrs = append(attrs, semconv.ClientAddress(clientAddr))
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
