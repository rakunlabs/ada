package forwardauth

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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

// hopByHopHeaders are headers that should not be forwarded to the auth service.
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
	// (except hop-by-hop headers).
	//
	// Optional. Default value [] (forward all).
	AuthRequestHeaders []string `cfg:"auth_request_headers"`

	// RequestMethod is the HTTP method to use when calling the auth service.
	//
	// Optional. Default value "GET".
	RequestMethod string `cfg:"request_method"`

	// TrustForwardHeader when true, reuses existing X-Forwarded-* headers
	// from the original request instead of overwriting them.
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
	// returns a non-2xx response on a GET or HEAD request. Supports the {url}
	// placeholder which is replaced with the original request URL (URL-encoded).
	// For example: "https://login.example.com?rd={url}".
	// Non-GET/HEAD requests always receive the auth response directly.
	//
	// Optional. Default value "" (disabled, auth response is returned as-is).
	RedirectURL string `cfg:"redirect_url"`

	// RedirectCode is the HTTP status code to use for the redirect.
	//
	// Optional. Default value 302 (Found).
	RedirectCode int `cfg:"redirect_code"`

	// RedirectStatusCodes is the list of auth response status codes that
	// trigger a redirect on GET/HEAD requests. Auth response codes not in this
	// list are proxied to the client as-is regardless of request method.
	//
	// Optional. Default value [401].
	RedirectStatusCodes []int `cfg:"redirect_status_codes"`

	client *http.Client
}

// New creates a new ForwardAuth middleware instance from the given options.
func New(opts ...Option) *ForwardAuth {
	o := &option{}
	for _, opt := range opts {
		opt(o)
	}

	f := &o.Config
	f.init()

	return f
}

// Middleware is a package-level convenience that returns the middleware function directly.
func Middleware(opts ...Option) func(http.Handler) http.Handler {
	return New(opts...).Middleware
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
		f.RedirectStatusCodes = []int{http.StatusUnauthorized} // 401
	}

	transport := &http.Transport{
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

	if f.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // user explicitly opted in
		}
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
			http.Error(w, fmt.Sprintf("forwardauth: %v", err), http.StatusBadGateway)
		}
	})
}

func (f *ForwardAuth) forward(w http.ResponseWriter, r *http.Request, next http.Handler) error {
	// Build the auth request.
	authReq, err := http.NewRequestWithContext(r.Context(), f.RequestMethod, f.Address, nil)
	if err != nil {
		return fmt.Errorf("creating auth request: %w", err)
	}

	// Copy headers from the original request to the auth request.
	f.copyRequestHeaders(authReq, r)

	// Set X-Forwarded-* headers.
	f.setForwardedHeaders(authReq, r)

	// Execute the auth request.
	authResp, err := f.client.Do(authReq)
	if err != nil {
		return fmt.Errorf("calling auth service: %w", err)
	}
	defer authResp.Body.Close()

	// 2xx: authentication succeeded.
	if authResp.StatusCode >= http.StatusOK && authResp.StatusCode < http.StatusMultipleChoices {
		// Copy configured auth response headers onto the original request.
		f.copyAuthResponseHeaders(r, authResp)

		// Continue to the next handler.
		next.ServeHTTP(w, r)

		return nil
	}

	// Non-2xx: authentication failed.
	// Redirect GET/HEAD requests if RedirectURL is configured and the status code matches.
	if f.RedirectURL != "" && isRedirectableMethod(r.Method) && f.isRedirectableStatus(authResp.StatusCode) {
		target := f.buildRedirectTarget(r)
		http.Redirect(w, r, target, f.RedirectCode)

		return nil
	}

	// Otherwise return the auth service response to the client.
	f.writeAuthResponse(w, authResp)

	return nil
}

// copyRequestHeaders copies headers from the original request to the auth request.
// If AuthRequestHeaders is set, only those headers are copied.
// Hop-by-hop headers are always excluded.
func (f *ForwardAuth) copyRequestHeaders(authReq *http.Request, origReq *http.Request) {
	if len(f.AuthRequestHeaders) > 0 {
		// Allowlist mode: only copy specified headers.
		for _, h := range f.AuthRequestHeaders {
			if v := origReq.Header.Get(h); v != "" {
				authReq.Header.Set(h, v)
			}
		}

		return
	}

	// Forward all headers except hop-by-hop.
	for name, values := range origReq.Header {
		if _, hop := hopByHopHeaders[name]; hop {
			continue
		}

		for _, v := range values {
			authReq.Header.Add(name, v)
		}
	}
}

// setForwardedHeaders sets the X-Forwarded-* headers on the auth request.
func (f *ForwardAuth) setForwardedHeaders(authReq *http.Request, origReq *http.Request) {
	proto := "http"
	if origReq.TLS != nil {
		proto = "https"
	}

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

		if v := origReq.Header.Get(headerXForwardedFor); v != "" {
			authReq.Header.Set(headerXForwardedFor, v)
		} else if clientIP := clientIP(origReq); clientIP != "" {
			authReq.Header.Set(headerXForwardedFor, clientIP)
		}
	} else {
		authReq.Header.Set(headerXForwardedHost, origReq.Host)
		authReq.Header.Set(headerXForwardedURI, origReq.RequestURI)
		authReq.Header.Set(headerXForwardedMethod, origReq.Method)
		if ip := clientIP(origReq); ip != "" {
			authReq.Header.Set(headerXForwardedFor, ip)
		}
	}

	authReq.Header.Set(headerXForwardedProto, proto)
}

// copyAuthResponseHeaders copies configured headers from the auth service
// response onto the original request so they are visible to downstream handlers.
func (f *ForwardAuth) copyAuthResponseHeaders(origReq *http.Request, authResp *http.Response) {
	for _, h := range f.AuthResponseHeaders {
		if v := authResp.Header.Get(h); v != "" {
			origReq.Header.Set(h, v)
		}
	}

	if f.AuthResponseHeadersRegex != "" {
		for name, values := range authResp.Header {
			matched, err := matchHeader(f.AuthResponseHeadersRegex, name)
			if err != nil || !matched {
				continue
			}

			for _, v := range values {
				origReq.Header.Set(name, v)
			}
		}
	}
}

// writeAuthResponse writes the auth service's response (status, headers, body)
// back to the client.
func (f *ForwardAuth) writeAuthResponse(w http.ResponseWriter, authResp *http.Response) {
	// Copy all response headers from auth service.
	for name, values := range authResp.Header {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}

	// Write status code.
	w.WriteHeader(authResp.StatusCode)

	// Copy body.
	_, _ = io.Copy(w, authResp.Body)
}

// buildRedirectTarget constructs the redirect URL by replacing the {url}
// placeholder with the URL-encoded original request URL.
func (f *ForwardAuth) buildRedirectTarget(r *http.Request) string {
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}

	if f.TrustForwardHeader {
		if v := r.Header.Get(headerXForwardedProto); v != "" {
			proto = v
		}
	}

	originalURL := proto + "://" + r.Host + r.RequestURI

	return strings.ReplaceAll(f.RedirectURL, "{url}", url.QueryEscape(originalURL))
}

// isRedirectableMethod reports whether the HTTP method should trigger a redirect
// on auth failure. Only GET and HEAD are redirectable — other methods (POST, PUT,
// DELETE, etc.) always receive the auth response directly.
func isRedirectableMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

// isRedirectableStatus reports whether the auth response status code should
// trigger a redirect.
func (f *ForwardAuth) isRedirectableStatus(code int) bool {
	for _, c := range f.RedirectStatusCodes {
		if c == code {
			return true
		}
	}

	return false
}

// clientIP extracts the client IP from the request's RemoteAddr.
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr might not have a port.
		return strings.TrimSpace(r.RemoteAddr)
	}

	return ip
}

// matchHeader reports whether the header name matches the given regex pattern.
func matchHeader(pattern, name string) (bool, error) {
	// Compile per call for simplicity; a production-grade version could cache.
	// The pattern is typically evaluated only when AuthResponseHeadersRegex is set,
	// and the number of response headers is small.
	return matchString(pattern, name)
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

// WithAuthRequestHeaders sets the allowlist of headers to forward from the
// original request to the auth service.
func WithAuthRequestHeaders(headers ...string) Option {
	return func(o *option) {
		o.Config.AuthRequestHeaders = headers
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

// WithRedirectURL sets the URL to redirect to on auth failure for GET/HEAD requests.
// Supports the {url} placeholder which is replaced with the URL-encoded original
// request URL. For example: "https://login.example.com?rd={url}".
func WithRedirectURL(redirectURL string) Option {
	return func(o *option) {
		o.Config.RedirectURL = redirectURL
	}
}

// WithRedirectCode sets the HTTP status code used for the redirect.
// Default is 302 (Found).
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
