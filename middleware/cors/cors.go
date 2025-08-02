package cors

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/rakunlabs/ada"
)

// defaultCORSConfig is the default CORS middleware config.
var defaultCORSConfig = Cors{
	AllowOrigins: []string{"*"},
	AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
}

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
	//
	// Optional. Default value []string{}.
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
	// Security: avoid using `AllowCredentials = true` with `AllowOrigins = *`.
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

// CORSWithConfig returns a CORS middleware with config.
// See: [CORS].
func (m *Cors) Middleware() func(http.Handler) http.Handler {
	// Defaults
	if len(m.AllowOrigins) == 0 {
		m.AllowOrigins = defaultCORSConfig.AllowOrigins
	}
	if len(m.AllowMethods) == 0 {
		m.AllowMethods = defaultCORSConfig.AllowMethods
	}

	allowOriginPatterns := make([]*regexp.Regexp, 0, len(m.AllowOrigins))
	for _, origin := range m.AllowOrigins {
		if origin == "*" {
			continue // "*" is handled differently and does not need regexp
		}
		pattern := regexp.QuoteMeta(origin)
		pattern = strings.ReplaceAll(pattern, "\\*", ".*")
		pattern = strings.ReplaceAll(pattern, "\\?", ".")
		pattern = "^" + pattern + "$"

		re, err := regexp.Compile(pattern)
		if err != nil {
			// this is to preserve previous behaviour - invalid patterns were just ignored.
			// If we would turn this to panic, users with invalid patterns
			// would have applications crashing in production due unrecovered panic.
			// TODO: this should be turned to error/panic in `v5`
			continue
		}
		allowOriginPatterns = append(allowOriginPatterns, re)
	}

	allowMethods := strings.Join(m.AllowMethods, ",")
	allowHeaders := strings.Join(m.AllowHeaders, ",")
	exposeHeaders := strings.Join(m.ExposeHeaders, ",")

	maxAge := "0"
	if m.MaxAge > 0 {
		maxAge = strconv.Itoa(m.MaxAge)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get(ada.HeaderOrigin)
			allowOrigin := ""

			w.Header().Add(ada.HeaderVary, ada.HeaderOrigin)

			// Preflight request is an OPTIONS request, using three HTTP request headers: Access-Control-Request-Method,
			// Access-Control-Request-Headers, and the Origin header. See: https://developer.mozilla.org/en-US/docs/Glossary/Preflight_request
			// For simplicity we just consider method type and later `Origin` header.
			preflight := r.Method == http.MethodOptions

			// No Origin provided. This is (probably) not request from actual browser - proceed executing middleware chain
			if origin == "" {
				if !preflight {
					next.ServeHTTP(w, r)

					return
				}

				ada.NoContent(w)

				return
			}

			// Check allowed origins
			for _, o := range m.AllowOrigins {
				if o == "*" && m.AllowCredentials && m.UnsafeWildcardOriginWithAllowCredentials {
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

				ada.NoContent(w)

				return
			}

			w.Header().Set(ada.HeaderAccessControlAllowOrigin, allowOrigin)
			if m.AllowCredentials {
				w.Header().Set(ada.HeaderAccessControlAllowCredentials, "true")
			}

			// Simple request
			if !preflight {
				if exposeHeaders != "" {
					w.Header().Set(ada.HeaderAccessControlExposeHeaders, exposeHeaders)
				}

				next.ServeHTTP(w, r)

				return
			}

			// Preflight request
			w.Header().Add(ada.HeaderVary, ada.HeaderAccessControlRequestMethod)
			w.Header().Add(ada.HeaderVary, ada.HeaderAccessControlRequestHeaders)
			w.Header().Set(ada.HeaderAccessControlAllowMethods, allowMethods)

			if allowHeaders != "" {
				w.Header().Set(ada.HeaderAccessControlAllowHeaders, allowHeaders)
			} else {
				h := r.Header.Get(ada.HeaderAccessControlRequestHeaders)
				if h != "" {
					w.Header().Set(ada.HeaderAccessControlAllowHeaders, h)
				}
			}
			if m.MaxAge != 0 {
				w.Header().Set(ada.HeaderAccessControlMaxAge, maxAge)
			}

			ada.NoContent(w)
		})
	}
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
