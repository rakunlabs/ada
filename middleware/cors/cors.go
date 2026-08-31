package cors

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	allowOrigins = []string{"*"}
	allowMethods = []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete}
)

const (
	headerVary   = "Vary"
	headerOrigin = "Origin"

	headerAccessControlAllowOrigin      = "Access-Control-Allow-Origin"
	headerAccessControlAllowCredentials = "Access-Control-Allow-Credentials"
	headerAccessControlExposeHeaders    = "Access-Control-Expose-Headers"
	headerAccessControlRequestMethod    = "Access-Control-Request-Method"
	headerAccessControlRequestHeaders   = "Access-Control-Request-Headers"
	headerAccessControlAllowMethods     = "Access-Control-Allow-Methods"
	headerAccessControlAllowHeaders     = "Access-Control-Allow-Headers"
	headerAccessControlMaxAge           = "Access-Control-Max-Age"
)

// Cors defines the config for CORS middleware.
//
//   - Converted from echo's Cors.
type Cors struct {
	// AllowOrigins determines the value of the Access-Control-Allow-Origin
	// response header.  This header defines a list of origins that may access the
	// resource.  The wildcard characters '*' and '?' are supported and are
	// converted to regex fragments '.*' and '.' accordingly.
	//
	// Security: use extreme caution when handling the origin, and carefully
	// validate any logic. Remember that attackers may register hostile domain names.
	// See https://blog.portswigger.net/2016/10/exploiting-cors-misconfigurations-for.html
	//
	// Optional. Default value []string{"*"}.
	//
	// See also: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
	AllowOrigins []string `cfg:"allow_origins"`

	// AllowMethods determines the value of the Access-Control-Allow-Methods
	// response header.  This header specified the list of methods allowed when
	// accessing the resource.  This is used in response to a preflight request.
	// A wildcard allows any requested method. For credentialed requests, the
	// concrete requested method is returned because browsers do not treat '*'
	// as a wildcard when credentials are included.
	//
	// Optional. Default value DefaultCORSConfig.AllowMethods.
	// If `allowMethods` is left empty, this middleware will fill for preflight
	// request `Access-Control-Allow-Methods` header value
	// from `Allow` header that echo.Router set into context.
	//
	// See also: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods
	AllowMethods []string `cfg:"allow_methods"`

	// AllowHeaders determines the value of the Access-Control-Allow-Headers
	// response header.  This header is used in response to a preflight request to
	// indicate which HTTP headers can be used when making the actual request.
	// A wildcard allows any requested header. For credentialed requests, the
	// concrete requested headers are returned because browsers do not treat '*'
	// as a wildcard when credentials are included.
	//
	// Optional. The secure default is an empty list: preflights that request any
	// non-safelisted headers are rejected rather than reflecting those headers.
	//
	// See also: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers
	AllowHeaders []string `cfg:"allow_headers"`

	// AllowCredentials determines the value of the
	// Access-Control-Allow-Credentials response header.  This header indicates
	// whether or not the response to the request can be exposed when the
	// credentials mode (Request.credentials) is true. When used as part of a
	// response to a preflight request, this indicates whether or not the actual
	// request can be made using credentials.  See also
	// [MDN: Access-Control-Allow-Credentials].
	//
	// Optional. Default value false, in which case the header is not set.
	//
	// Security: AllowCredentials cannot be combined with an AllowOrigins entry
	// of "*" unless UnsafeWildcardOriginWithAllowCredentials is explicitly set.
	// See "Exploiting CORS misconfigurations for Bitcoins and bounties",
	// https://blog.portswigger.net/2016/10/exploiting-cors-misconfigurations-for.html
	//
	// See also: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
	AllowCredentials bool `cfg:"allow_credentials"`

	// UnsafeWildcardOriginWithAllowCredentials UNSAFE/INSECURE: allows wildcard '*' origin to be used with AllowCredentials
	// flag. In that case we consider any origin allowed and send it back to the client with `Access-Control-Allow-Origin` header.
	//
	// This is INSECURE and potentially leads to [cross-origin](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
	// attacks. See: https://github.com/labstack/echo/issues/2400 for discussion on the subject.
	//
	// Optional. Default value is false.
	UnsafeWildcardOriginWithAllowCredentials bool `cfg:"unsafe_wildcard_origin_with_allow_credentials"`

	// ExposeHeaders determines the value of Access-Control-Expose-Headers, which
	// defines a list of headers that clients are allowed to access.
	//
	// Optional. Default value []string{}, in which case the header is not set.
	//
	// See also: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Header
	ExposeHeaders []string `cfg:"expose_headers"`

	// MaxAge determines the value of the Access-Control-Max-Age response header.
	// This header indicates how long (in seconds) the results of a preflight
	// request can be cached.
	// The header is set only if MaxAge != 0, negative value sends "0" which instructs browsers not to cache that response.
	//
	// Optional. Default value 0 - meaning header is not sent.
	//
	// See also: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
	MaxAge int `cfg:"max_age"`
}

func Middleware(opts ...Option) func(http.Handler) http.Handler {
	o := &option{}
	for _, opt := range opts {
		opt(o)
	}

	return o.Config.Middleware()
}

// Middleware returns a CORS middleware using an immutable snapshot of m.
func (m *Cors) Middleware() func(http.Handler) http.Handler {
	cfg := *m
	cfg.AllowOrigins = slices.Clone(m.AllowOrigins)
	cfg.AllowMethods = slices.Clone(m.AllowMethods)
	cfg.AllowHeaders = slices.Clone(m.AllowHeaders)
	cfg.ExposeHeaders = slices.Clone(m.ExposeHeaders)

	// Defaults
	if len(cfg.AllowOrigins) == 0 {
		cfg.AllowOrigins = slices.Clone(allowOrigins)
	}
	if len(cfg.AllowMethods) == 0 {
		cfg.AllowMethods = slices.Clone(allowMethods)
	}
	normalizeTokens("allow method", cfg.AllowMethods)
	normalizeTokens("allow header", cfg.AllowHeaders)
	normalizeTokens("expose header", cfg.ExposeHeaders)
	if cfg.AllowCredentials && slices.Contains(cfg.AllowOrigins, "*") &&
		!cfg.UnsafeWildcardOriginWithAllowCredentials {
		panic(fmt.Errorf("cors: wildcard allow origin with credentials requires UnsafeWildcardOriginWithAllowCredentials"))
	}
	wildcardMethod := slices.Contains(cfg.AllowMethods, "*")
	wildcardHeaders := slices.Contains(cfg.AllowHeaders, "*")

	allowOriginPatterns := make([]*regexp.Regexp, 0, len(cfg.AllowOrigins))
	for _, origin := range cfg.AllowOrigins {
		if origin == "" || strings.TrimSpace(origin) != origin {
			panic(fmt.Errorf("cors: invalid allow origin pattern %q", origin))
		}
		if origin == "*" {
			continue // "*" is handled differently and does not need regexp
		}
		pattern := regexp.QuoteMeta(origin)
		pattern = strings.ReplaceAll(pattern, "\\*", ".*")
		pattern = strings.ReplaceAll(pattern, "\\?", ".")
		pattern = "^" + pattern + "$"

		re, err := regexp.Compile(pattern)
		if err != nil {
			panic(fmt.Errorf("cors: invalid allow origin pattern %q: %w", origin, err))
		}
		allowOriginPatterns = append(allowOriginPatterns, re)
	}

	allowMethods := strings.Join(cfg.AllowMethods, ",")
	allowHeaders := strings.Join(cfg.AllowHeaders, ",")
	exposeHeaders := strings.Join(cfg.ExposeHeaders, ",")

	maxAge := "0"
	if cfg.MaxAge > 0 {
		maxAge = strconv.Itoa(cfg.MaxAge)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get(headerOrigin)
			requestedMethod := r.Header.Get(headerAccessControlRequestMethod)
			requestedHeaders := strings.Join(r.Header.Values(headerAccessControlRequestHeaders), ",")
			allowOrigin := ""

			w.Header().Add(headerVary, headerOrigin)

			preflight := r.Method == http.MethodOptions &&
				origin != "" && requestedMethod != ""

			// No Origin provided. This is (probably) not request from actual browser - proceed executing middleware chain
			if origin == "" {
				next.ServeHTTP(w, r)

				return
			}
			if preflight {
				w.Header().Add(headerVary, headerAccessControlRequestMethod)
				w.Header().Add(headerVary, headerAccessControlRequestHeaders)
			}

			// Check allowed origins
			for _, o := range cfg.AllowOrigins {
				if o == "*" && cfg.AllowCredentials && cfg.UnsafeWildcardOriginWithAllowCredentials {
					allowOrigin = origin

					break
				}
				if o == "*" || o == origin {
					allowOrigin = o

					break
				}
				if matchSubdomain(origin, o) {
					allowOrigin = origin

					break
				}
			}

			checkPatterns := false
			if allowOrigin == "" {
				// to avoid regex cost by invalid (long) domains (253 is domain name max limit)
				if len(origin) <= (253+3+5) && strings.Contains(origin, "://") {
					checkPatterns = true
				}
			}
			if checkPatterns {
				for _, re := range allowOriginPatterns {
					if match := re.MatchString(origin); match {
						allowOrigin = origin
						break
					}
				}
			}

			// Origin not allowed
			if allowOrigin == "" {
				if !preflight {
					next.ServeHTTP(w, r)

					return
				}

				w.WriteHeader(http.StatusNoContent)

				return
			}
			if preflight && (!isAllowedMethod(requestedMethod, cfg.AllowMethods) ||
				!areAllowedHeaders(requestedHeaders, cfg.AllowHeaders)) {
				w.WriteHeader(http.StatusNoContent)

				return
			}

			w.Header().Set(headerAccessControlAllowOrigin, allowOrigin)
			if cfg.AllowCredentials {
				w.Header().Set(headerAccessControlAllowCredentials, "true")
			}

			// Simple request
			if !preflight {
				if exposeHeaders != "" {
					w.Header().Set(headerAccessControlExposeHeaders, exposeHeaders)
				}

				next.ServeHTTP(w, r)

				return
			}

			// Preflight request
			responseAllowMethods := allowMethods
			if cfg.AllowCredentials && wildcardMethod {
				responseAllowMethods = requestedMethod
			}
			w.Header().Set(headerAccessControlAllowMethods, responseAllowMethods)

			responseAllowHeaders := allowHeaders
			if cfg.AllowCredentials && wildcardHeaders {
				responseAllowHeaders = requestedHeaders
			}
			if responseAllowHeaders != "" {
				w.Header().Set(headerAccessControlAllowHeaders, responseAllowHeaders)
			}
			if cfg.MaxAge != 0 {
				w.Header().Set(headerAccessControlMaxAge, maxAge)
			}

			w.WriteHeader(http.StatusNoContent)
		})
	}
}

func normalizeTokens(name string, values []string) {
	for i, value := range values {
		value = strings.TrimSpace(value)
		if !isHTTPToken(value) {
			panic(fmt.Errorf("cors: invalid %s %q", name, values[i]))
		}
		values[i] = value
	}
}

func isHTTPToken(value string) bool {
	if value == "" {
		return false
	}

	for i := range len(value) {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}

	return true
}

func isAllowedMethod(requested string, allowed []string) bool {
	requested = strings.TrimSpace(requested)
	if !isHTTPToken(requested) {
		return false
	}
	for _, method := range allowed {
		method = strings.TrimSpace(method)
		if method == "*" || method == requested {
			return true
		}
	}

	return false
}

func areAllowedHeaders(requested string, allowed []string) bool {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return true
	}

	wildcard := false
	allowedHeaders := make(map[string]struct{}, len(allowed))
	for _, header := range allowed {
		header = strings.TrimSpace(header)
		if header == "*" {
			wildcard = true

			continue
		}
		if header != "" {
			allowedHeaders[strings.ToLower(header)] = struct{}{}
		}
	}

	for _, header := range strings.Split(requested, ",") {
		header = strings.TrimSpace(header)
		if !isHTTPToken(header) {
			return false
		}
		if _, ok := allowedHeaders[strings.ToLower(header)]; !wildcard && !ok {
			return false
		}
	}

	return true
}

// ////////////////////////////////////////////////////////////////////

type option struct {
	Config Cors
}

type Option func(*option)

func WithConfig(config Cors) Option {
	return func(o *option) {
		o.Config = config
	}
}
