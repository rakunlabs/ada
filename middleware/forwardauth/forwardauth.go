package forwardauth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	headerXForwardedMethod = "X-Forwarded-Method"
	headerXForwardedProto  = "X-Forwarded-Proto"
	headerXForwardedHost   = "X-Forwarded-Host"
	headerXForwardedURI    = "X-Forwarded-Uri"
	headerXForwardedFor    = "X-Forwarded-For"
)

// hopByHopHeaders are headers that must not be forwarded to the auth service.
// See: https://www.rfc-editor.org/rfc/rfc2616#section-13.5.1
var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailers":            {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// bodyHeaders describe the shape of a request body. The auth request carries
// no body, so forwarding these from the original request would misinform the
// auth service.
var bodyHeaders = map[string]struct{}{
	"Content-Length":    {},
	"Content-Type":      {},
	"Content-Encoding":  {},
	"Transfer-Encoding": {},
}

// ExtractorFunc runs on every 2xx auth response. It may decode the auth-service
// response body, mutate the request, and return an updated request (typically
// carrying new context values). Returning an error fails the request with
// 502 Bad Gateway.
type ExtractorFunc func(r *http.Request, resp *http.Response) (*http.Request, error)

// ForwardAuth defines the config for ForwardAuth middleware.
//
// ForwardAuth delegates authentication to an external service by forwarding
// request headers. The auth service responds with 2xx to allow the request,
// or non-2xx to deny it.
type ForwardAuth struct {
	// Address is the URL of the external authentication service.
	// Required.
	Address string `cfg:"address"`

	// AuthResponseHeaders is the list of headers to copy from the auth service
	// response onto the original request before forwarding to the backend.
	// For example: ["X-Forwarded-User", "X-Auth-Token"].
	//
	// Optional. Default value [].
	AuthResponseHeaders []string `cfg:"auth_response_headers"`

	// AuthResponseHeadersRegex is a regex pattern to match auth response headers
	// to copy onto the original request.
	//
	// Optional. Default value "".
	AuthResponseHeadersRegex string `cfg:"auth_response_headers_regex"`

	// AuthRequestHeaders is an allowlist of headers from the original request
	// to forward to the auth service. If empty, all headers are forwarded
	// (except hop-by-hop and body-shape headers).
	//
	// Optional. Default value [] (forward all).
	AuthRequestHeaders []string `cfg:"auth_request_headers"`

	// DeleteRequestHeaders is a list of headers to delete from the original request
	// before continuing. Applied before copying auth response headers.
	//
	// Optional. Default value [].
	DeleteRequestHeaders []string `cfg:"delete_request_headers"`

	// RequestMethod is the HTTP method to use when calling the auth service.
	//
	// Optional. Default value "GET".
	RequestMethod string `cfg:"request_method"`

	// TrustForwardHeader when true, reuses existing X-Forwarded-* headers
	// from the original request. X-Forwarded-For is extended with the
	// immediate client IP rather than being replaced.
	//
	// Optional. Default value false.
	TrustForwardHeader bool `cfg:"trust_forward_header"`

	// InsecureSkipVerify skips TLS certificate verification when calling
	// the auth service.
	//
	// Optional. Default value false.
	InsecureSkipVerify bool `cfg:"insecure_skip_verify"`

	// Timeout is the maximum duration to wait for the auth service response.
	//
	// Optional. Default value 30s.
	Timeout time.Duration `cfg:"timeout"`

	// RedirectURL is the URL to redirect the client to when the auth service
	// returns a non-2xx response on a GET or HEAD request.
	// Non-GET/HEAD requests always receive the auth response directly.
	//
	// Supported placeholders (all values are URL-encoded):
	//   - {url}  — full original request URL (e.g. "https://login.example.com?rd={url}")
	//   - {uri}  — request URI only, path + query string
	//   - {host} — request host with port if present
	//
	// When TrustForwardHeader is true, X-Forwarded-{Proto,Host,Uri} are used
	// to reconstruct these values if present on the original request.
	//
	// Optional. Default value "" (disabled, auth response is returned as-is).
	RedirectURL string `cfg:"redirect_url"`

	// RedirectCode is the HTTP status code to use for the redirect.
	// Must be a 3xx code.
	//
	// Optional. Default value 302 (Found).
	RedirectCode int `cfg:"redirect_code"`

	// RedirectStatusCodes is the list of auth response status codes that
	// trigger a redirect on GET/HEAD requests. Auth response codes not in this
	// list are proxied to the client as-is regardless of request method.
	//
	// Optional. Default value [401].
	RedirectStatusCodes []int `cfg:"redirect_status_codes"`

	// MaxBodySize caps how much of the auth response body the extractor may
	// read. Pass a power-of-two via shift for readability, e.g. 1 << 20 for
	// 1 MiB or 4 << 10 for 4 KiB. Ignored when no extractor is set.
	//
	// Optional. Default value 1 << 20 (1 MiB).
	MaxBodySize int64 `cfg:"max_body_size"`

	// client is the HTTP client used to call the auth service. When nil a
	// default client is built from Timeout, InsecureSkipVerify, transport,
	// rootCAs and clientCert. Set via WithClient.
	client *http.Client

	// transport is a custom RoundTripper applied to the default client.
	// Ignored when client is set via WithClient. Set via WithTransport.
	transport http.RoundTripper

	// rootCAs is an optional root CA pool used to verify the auth service.
	// Set via WithRootCAs.
	rootCAs *x509.CertPool

	// clientCert is an optional client certificate presented to the auth
	// service during the TLS handshake. Set via WithClientCert.
	clientCert *tls.Certificate

	// onError is called when the auth service call fails (network error,
	// timeout). Set via WithOnError.
	onError func(err error, r *http.Request)

	// extractor is a post-auth hook called on 2xx responses. Set via WithExtractor.
	extractor ExtractorFunc

	// responseHeadersRegex is the compiled form of AuthResponseHeadersRegex.
	responseHeadersRegex *regexp.Regexp
}

// New creates a new ForwardAuth middleware instance from the given options.
// It applies defaults but does not validate; use Validate to fail fast at
// startup.
func New(opts ...Option) *ForwardAuth {
	o := &option{}
	for _, opt := range opts {
		opt(o)
	}

	f := &o.Config
	f.init()

	return f
}

// Middleware is a package-level convenience that returns the middleware
// function directly. It panics if the configuration is invalid so startup
// errors are not deferred to the first request.
func Middleware(opts ...Option) func(http.Handler) http.Handler {
	f := New(opts...)
	if err := f.Validate(); err != nil {
		panic(err)
	}

	return f.Middleware
}

// Validate reports any configuration problems. Call at startup to fail fast.
func (f *ForwardAuth) Validate() error {
	if f.Address == "" {
		return errors.New("forwardauth: Address is required")
	}

	if _, err := url.Parse(f.Address); err != nil {
		return fmt.Errorf("forwardauth: invalid Address: %w", err)
	}

	if f.RedirectCode != 0 && (f.RedirectCode < 300 || f.RedirectCode > 399) {
		return fmt.Errorf("forwardauth: RedirectCode must be a 3xx status, got %d", f.RedirectCode)
	}

	if f.AuthResponseHeadersRegex != "" {
		if _, err := regexp.Compile(f.AuthResponseHeadersRegex); err != nil {
			return fmt.Errorf("forwardauth: invalid AuthResponseHeadersRegex: %w", err)
		}
	}

	return nil
}

func (f *ForwardAuth) init() {
	if f.RequestMethod == "" {
		f.RequestMethod = http.MethodGet
	}

	if f.Timeout == 0 {
		f.Timeout = 30 * time.Second
	}

	if f.RedirectCode == 0 {
		f.RedirectCode = http.StatusFound // 302
	}

	if len(f.RedirectStatusCodes) == 0 && f.RedirectURL != "" {
		f.RedirectStatusCodes = []int{http.StatusUnauthorized}
	}

	if f.MaxBodySize == 0 {
		f.MaxBodySize = 1 << 20 // 1 MiB
	}

	if f.AuthResponseHeadersRegex != "" && f.responseHeadersRegex == nil {
		// Validate catches compile errors; ignore here so init stays non-fatal.
		if re, err := regexp.Compile(f.AuthResponseHeadersRegex); err == nil {
			f.responseHeadersRegex = re
		}
	}

	if f.client != nil {
		return
	}

	transport := f.transport
	if transport == nil {
		t := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}

		if f.InsecureSkipVerify || f.rootCAs != nil || f.clientCert != nil {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: f.InsecureSkipVerify, //nolint:gosec // user explicitly opted in
				RootCAs:            f.rootCAs,
			}

			if f.clientCert != nil {
				tlsConfig.Certificates = []tls.Certificate{*f.clientCert}
			}

			t.TLSClientConfig = tlsConfig
		}

		transport = t
	}

	f.client = &http.Client{
		Timeout:   f.Timeout,
		Transport: transport,
		// Do not follow redirects; return the auth service response as-is.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Middleware returns an http.Handler middleware that delegates authentication
// to the configured external auth service.
func (f *ForwardAuth) Middleware(next http.Handler) http.Handler {
	if f.client == nil {
		f.init()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := f.forward(w, r, next); err != nil {
			if f.onError != nil {
				f.onError(err, r)
			}

			http.Error(w, fmt.Sprintf("forwardauth: %v", err), http.StatusBadGateway)
		}
	})
}

func (f *ForwardAuth) forward(w http.ResponseWriter, r *http.Request, next http.Handler) error {
	authReq, err := http.NewRequestWithContext(r.Context(), f.RequestMethod, f.Address, nil)
	if err != nil {
		return fmt.Errorf("creating auth request: %w", err)
	}

	f.copyRequestHeaders(authReq, r)
	f.setForwardedHeaders(authReq, r)

	authResp, err := f.client.Do(authReq)
	if err != nil {
		return fmt.Errorf("calling auth service: %w", err)
	}
	defer authResp.Body.Close()

	// 2xx: authentication succeeded.
	if authResp.StatusCode >= http.StatusOK && authResp.StatusCode < http.StatusMultipleChoices {
		f.copyAuthResponseHeaders(r, authResp)

		if f.extractor != nil {
			authResp.Body = http.MaxBytesReader(nil, authResp.Body, f.MaxBodySize)

			newReq, err := f.extractor(r, authResp)
			if err != nil {
				return fmt.Errorf("extractor: %w", err)
			}

			r = newReq
		}

		// Drain so the keep-alive connection to the auth service is reusable.
		_, _ = io.Copy(io.Discard, authResp.Body)

		next.ServeHTTP(w, r)

		return nil
	}

	// Non-2xx: authentication failed.
	if f.RedirectURL != "" && isRedirectableMethod(r.Method) && f.isRedirectableStatus(authResp.StatusCode) {
		_, _ = io.Copy(io.Discard, authResp.Body)
		http.Redirect(w, r, f.buildRedirectTarget(r), f.RedirectCode)

		return nil
	}

	f.writeAuthResponse(w, authResp)

	return nil
}

// copyRequestHeaders copies headers from the original request to the auth
// request. With an allowlist, only the named headers are copied. Without one,
// every header is copied except hop-by-hop headers, Connection-listed headers,
// and body-shape headers (the auth request has no body).
func (f *ForwardAuth) copyRequestHeaders(authReq *http.Request, origReq *http.Request) {
	extraHop := connectionHopHeaders(origReq.Header)

	skip := func(name string) bool {
		ck := http.CanonicalHeaderKey(name)
		if _, ok := hopByHopHeaders[ck]; ok {
			return true
		}

		if _, ok := extraHop[ck]; ok {
			return true
		}

		if _, ok := bodyHeaders[ck]; ok {
			return true
		}

		return false
	}

	if len(f.AuthRequestHeaders) > 0 {
		for _, h := range f.AuthRequestHeaders {
			if skip(h) {
				continue
			}

			values := origReq.Header.Values(h)
			if len(values) == 0 {
				continue
			}

			authReq.Header.Del(h)
			for _, v := range values {
				authReq.Header.Add(h, v)
			}
		}

		return
	}

	for name, values := range origReq.Header {
		if skip(name) {
			continue
		}

		for _, v := range values {
			authReq.Header.Add(name, v)
		}
	}
}

// setForwardedHeaders sets the X-Forwarded-* headers on the auth request.
// When TrustForwardHeader is true, incoming X-Forwarded-* values are preserved
// and X-Forwarded-For is extended with the immediate client IP rather than
// overwritten.
func (f *ForwardAuth) setForwardedHeaders(authReq *http.Request, origReq *http.Request) {
	proto := "http"
	if origReq.TLS != nil {
		proto = "https"
	}

	ip := clientIP(origReq)

	if f.TrustForwardHeader {
		if v := origReq.Header.Get(headerXForwardedProto); v != "" {
			proto = v
		}

		if v := origReq.Header.Get(headerXForwardedHost); v != "" {
			authReq.Header.Set(headerXForwardedHost, v)
		} else {
			authReq.Header.Set(headerXForwardedHost, origReq.Host)
		}

		if v := origReq.Header.Get(headerXForwardedURI); v != "" {
			authReq.Header.Set(headerXForwardedURI, v)
		} else {
			authReq.Header.Set(headerXForwardedURI, origReq.RequestURI)
		}

		if v := origReq.Header.Get(headerXForwardedMethod); v != "" {
			authReq.Header.Set(headerXForwardedMethod, v)
		} else {
			authReq.Header.Set(headerXForwardedMethod, origReq.Method)
		}

		existing := origReq.Header.Get(headerXForwardedFor)
		switch {
		case existing != "" && ip != "":
			authReq.Header.Set(headerXForwardedFor, existing+", "+ip)
		case existing != "":
			authReq.Header.Set(headerXForwardedFor, existing)
		case ip != "":
			authReq.Header.Set(headerXForwardedFor, ip)
		}
	} else {
		authReq.Header.Set(headerXForwardedHost, origReq.Host)
		authReq.Header.Set(headerXForwardedURI, origReq.RequestURI)
		authReq.Header.Set(headerXForwardedMethod, origReq.Method)

		if ip != "" {
			authReq.Header.Set(headerXForwardedFor, ip)
		}
	}

	authReq.Header.Set(headerXForwardedProto, proto)
}

// copyAuthResponseHeaders copies configured headers from the auth service
// response onto the original request so they are visible to downstream
// handlers. Multi-value headers are preserved.
func (f *ForwardAuth) copyAuthResponseHeaders(origReq *http.Request, authResp *http.Response) {
	for _, h := range f.DeleteRequestHeaders {
		origReq.Header.Del(h)
	}

	for _, h := range f.AuthResponseHeaders {
		values := authResp.Header.Values(h)
		if len(values) == 0 {
			continue
		}

		origReq.Header.Del(h)
		for _, v := range values {
			origReq.Header.Add(h, v)
		}
	}

	if f.responseHeadersRegex != nil {
		for name, values := range authResp.Header {
			if !f.responseHeadersRegex.MatchString(name) {
				continue
			}

			origReq.Header.Del(name)
			for _, v := range values {
				origReq.Header.Add(name, v)
			}
		}
	}
}

// writeAuthResponse writes the auth service's response (status, headers, body)
// back to the client.
func (f *ForwardAuth) writeAuthResponse(w http.ResponseWriter, authResp *http.Response) {
	for name, values := range authResp.Header {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}

	w.WriteHeader(authResp.StatusCode)
	_, _ = io.Copy(w, authResp.Body)
}

// buildRedirectTarget constructs the redirect URL by replacing placeholders
// with URL-encoded values from the original request. When TrustForwardHeader
// is true, X-Forwarded-{Proto,Host,Uri} are consulted so the URL reflects the
// edge request rather than the hop into this middleware.
func (f *ForwardAuth) buildRedirectTarget(r *http.Request) string {
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}

	host := r.Host
	uri := r.RequestURI

	if f.TrustForwardHeader {
		if v := r.Header.Get(headerXForwardedProto); v != "" {
			proto = v
		}

		if v := r.Header.Get(headerXForwardedHost); v != "" {
			host = v
		}

		if v := r.Header.Get(headerXForwardedURI); v != "" {
			uri = v
		}
	}

	originalURL := proto + "://" + host + uri

	result := f.RedirectURL
	result = strings.ReplaceAll(result, "{url}", url.QueryEscape(originalURL))
	result = strings.ReplaceAll(result, "{uri}", url.QueryEscape(uri))
	result = strings.ReplaceAll(result, "{host}", url.QueryEscape(host))

	return result
}

// isRedirectableMethod reports whether the HTTP method should trigger a
// redirect on auth failure. Only GET and HEAD are redirectable — other methods
// always receive the auth response directly.
func isRedirectableMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func (f *ForwardAuth) isRedirectableStatus(code int) bool {
	return slices.Contains(f.RedirectStatusCodes, code)
}

// clientIP extracts the client IP from the request's RemoteAddr.
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}

	return ip
}

// connectionHopHeaders parses the Connection request header into a set of
// additional hop-by-hop header names per RFC 7230 §6.1.
func connectionHopHeaders(h http.Header) map[string]struct{} {
	values := h.Values("Connection")
	if len(values) == 0 {
		return nil
	}

	set := make(map[string]struct{})

	for _, v := range values {
		for token := range strings.SplitSeq(v, ",") {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}

			set[http.CanonicalHeaderKey(token)] = struct{}{}
		}
	}

	return set
}

// ////////////////////////////////////////////////////////////////////

type option struct {
	Config ForwardAuth
}

// Option is a function that configures ForwardAuth.
type Option func(*option)

// WithConfig sets the ForwardAuth configuration.
func WithConfig(config ForwardAuth) Option {
	return func(o *option) {
		o.Config = config
	}
}

// WithAddress sets the auth service URL.
func WithAddress(address string) Option {
	return func(o *option) {
		o.Config.Address = address
	}
}

// WithAuthResponseHeaders sets the headers to copy from the auth response
// onto the original request.
func WithAuthResponseHeaders(headers ...string) Option {
	return func(o *option) {
		o.Config.AuthResponseHeaders = headers
	}
}

// WithAuthResponseHeadersRegex sets a regex pattern to match auth response
// headers to copy onto the original request.
func WithAuthResponseHeadersRegex(pattern string) Option {
	return func(o *option) {
		o.Config.AuthResponseHeadersRegex = pattern
	}
}

// WithAuthRequestHeaders sets the allowlist of headers to forward from the
// original request to the auth service.
func WithAuthRequestHeaders(headers ...string) Option {
	return func(o *option) {
		o.Config.AuthRequestHeaders = headers
	}
}

// WithDeleteRequestHeaders sets headers to delete from the original request
// before invoking the next handler.
func WithDeleteRequestHeaders(headers ...string) Option {
	return func(o *option) {
		o.Config.DeleteRequestHeaders = headers
	}
}

// WithTrustForwardHeader configures whether to trust existing X-Forwarded-* headers.
func WithTrustForwardHeader(trust bool) Option {
	return func(o *option) {
		o.Config.TrustForwardHeader = trust
	}
}

// WithInsecureSkipVerify configures whether to skip TLS verification.
func WithInsecureSkipVerify(skip bool) Option {
	return func(o *option) {
		o.Config.InsecureSkipVerify = skip
	}
}

// WithTimeout sets the timeout for the auth service request.
func WithTimeout(timeout time.Duration) Option {
	return func(o *option) {
		o.Config.Timeout = timeout
	}
}

// WithRequestMethod sets the HTTP method used to call the auth service.
func WithRequestMethod(method string) Option {
	return func(o *option) {
		o.Config.RequestMethod = method
	}
}

// WithRedirectURL sets the URL to redirect to on auth failure for GET/HEAD
// requests. Supports {url}, {uri}, {host} placeholders.
func WithRedirectURL(redirectURL string) Option {
	return func(o *option) {
		o.Config.RedirectURL = redirectURL
	}
}

// WithRedirectCode sets the HTTP status code used for the redirect.
// Default is 302 (Found). Must be a 3xx code.
func WithRedirectCode(code int) Option {
	return func(o *option) {
		o.Config.RedirectCode = code
	}
}

// WithRedirectStatusCodes sets the auth response status codes that trigger a
// redirect on GET/HEAD requests. Default is [401].
func WithRedirectStatusCodes(codes ...int) Option {
	return func(o *option) {
		o.Config.RedirectStatusCodes = codes
	}
}

// WithClient sets a custom http.Client. When set, Timeout, InsecureSkipVerify,
// WithTransport, WithRootCAs and WithClientCert are ignored for building the
// client — the caller is responsible for configuring them.
func WithClient(c *http.Client) Option {
	return func(o *option) {
		o.Config.client = c
	}
}

// WithTransport sets a custom RoundTripper on the default client. Ignored
// when WithClient is also set.
func WithTransport(t http.RoundTripper) Option {
	return func(o *option) {
		o.Config.transport = t
	}
}

// WithRootCAs sets the root CA pool used to verify the auth service TLS
// certificate. Ignored when WithClient or WithTransport is set.
func WithRootCAs(pool *x509.CertPool) Option {
	return func(o *option) {
		o.Config.rootCAs = pool
	}
}

// WithClientCert sets a client certificate presented to the auth service
// during the TLS handshake. Ignored when WithClient or WithTransport is set.
func WithClientCert(cert tls.Certificate) Option {
	return func(o *option) {
		o.Config.clientCert = &cert
	}
}

// WithOnError sets a callback invoked when the auth service call fails
// (network error, timeout). The response to the client is still a 502 Bad
// Gateway; the callback is purely for observability.
func WithOnError(fn func(err error, r *http.Request)) Option {
	return func(o *option) {
		o.Config.onError = fn
	}
}

// WithExtractor installs a post-auth extractor. When set, fn is called on
// every 2xx auth response after configured headers have been copied onto the
// request. Return an updated request (typically r.WithContext(...)) to pass
// down to the next handler. Returning an error fails the request with 502.
func WithExtractor(fn ExtractorFunc) Option {
	return func(o *option) {
		o.Config.extractor = fn
	}
}

// WithMaxBodySize caps how much of the auth response body the extractor may
// read. Default is 1 MiB (1 << 20). Oversize bodies fail the request with
// 502 Bad Gateway. Ignored when no extractor is set.
//
// Pass a power-of-two via shift for readability, e.g.
//
//	WithMaxBodySize(1 << 20) // 1 MiB
//	WithMaxBodySize(4 << 10) // 4 KiB
func WithMaxBodySize(n int64) Option {
	return func(o *option) {
		o.Config.MaxBodySize = n
	}
}
