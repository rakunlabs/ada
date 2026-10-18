// Package csrf protects unsafe requests against cross-site request forgery.
//
// The origin check uses the Sec-Fetch-Site and Origin headers through
// net/http.CrossOriginProtection and needs no client cooperation. The
// optional token check adds the signed double-submit cookie pattern for
// clients that need an explicit token, such as server-rendered forms.
//
// Typical usage:
//
//	server.Use(csrf.Middleware())
//
//	server.Use(csrf.Middleware(csrf.WithConfig(csrf.Config{
//	    TrustedOrigins: []string{"https://app.example.com"},
//	    BypassPatterns: []string{"POST /webhook/{provider}"},
//	    Token:          csrf.Token{Enabled: true, Secret: secret},
//	})))
package csrf

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

const (
	DefaultCookieName = "csrf_token"
	DefaultHeaderName = "X-CSRF-Token"
	DefaultFormField  = "csrf_token"

	tokenSize = 32
)

var (
	ErrCrossOrigin  = errors.New("cross-origin request rejected")
	ErrTokenMissing = errors.New("csrf token missing")
	ErrTokenInvalid = errors.New("csrf token invalid")
)

type Config struct {
	// TrustedOrigins are cross-origin sources allowed to send unsafe requests,
	// in the form "scheme://host[:port]", e.g. "https://app.example.com".
	// Invalid values panic during middleware construction.
	TrustedOrigins []string `cfg:"trusted_origins"`
	// BypassPatterns are net/http.ServeMux patterns, e.g. "POST /webhook/{id}"
	// or "/api/", whose requests skip every check. Only direct matches bypass;
	// paths ServeMux would redirect (cleaned or with an added slash) do not.
	// Invalid or conflicting patterns panic during middleware construction.
	BypassPatterns []string `cfg:"bypass_patterns"`
	// DisableOriginCheck disables the Sec-Fetch-Site/Origin check. Only the
	// token check then protects the request.
	DisableOriginCheck bool `cfg:"disable_origin_check"`

	Token Token `cfg:"token"`

	// DenyHandler answers rejected requests. Use Cause to read the reason.
	// The default responds with 403 and a JSON error body.
	DenyHandler http.Handler `cfg:"-"`
}

// Token configures the signed double-submit cookie check.
type Token struct {
	Enabled bool `cfg:"enabled"`
	// Secret signs the token with HMAC-SHA256. Without it the token is not
	// signed, so a sibling subdomain able to set cookies could inject a token
	// of its own. Set it in production.
	Secret string `cfg:"secret" log:"-"`
	// CookieName defaults to DefaultCookieName. Consider "__Host-csrf_token"
	// with the default path and no domain to stop subdomain injection.
	CookieName string `cfg:"cookie_name"`
	// HeaderName defaults to DefaultHeaderName.
	HeaderName string `cfg:"header_name"`
	// FormField is read from url-encoded and multipart form posts when the
	// header is empty. Defaults to DefaultFormField.
	FormField string `cfg:"form_field"`

	// CookiePath defaults to "/".
	CookiePath   string `cfg:"cookie_path"`
	CookieDomain string `cfg:"cookie_domain"`
	// CookieMaxAge of zero makes a session cookie. Negative values panic.
	CookieMaxAge time.Duration `cfg:"cookie_max_age"`
	// CookieInsecure drops the Secure attribute, for plain HTTP development.
	CookieInsecure bool `cfg:"cookie_insecure"`
	// CookieSameSite is "lax", "strict" or "none"; default is "lax". "none"
	// cannot be combined with CookieInsecure.
	CookieSameSite string `cfg:"cookie_same_site"`
}

type ctxKey struct{}

type ctxValue struct {
	token string
	cause error
}

// TokenFromRequest returns the CSRF token for the request so handlers can
// embed it in forms or pages. It is empty when the token check is disabled or
// the request bypassed the middleware.
func TokenFromRequest(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKey{}).(*ctxValue); ok {
		return v.token
	}
	return ""
}

// Cause returns why a request was rejected, for use in a DenyHandler. It is
// one of ErrCrossOrigin, ErrTokenMissing or ErrTokenInvalid.
func Cause(r *http.Request) error {
	if v, ok := r.Context().Value(ctxKey{}).(*ctxValue); ok {
		return v.cause
	}
	return nil
}

// Middleware constructs CSRF protection middleware. It panics when Config
// contains an invalid value.
func Middleware(opts ...Option) func(next http.Handler) http.Handler {
	var opt option
	for _, o := range opts {
		o(&opt)
	}

	cfg := opt.Config
	cfg.TrustedOrigins = slices.Clone(cfg.TrustedOrigins)
	cfg.BypassPatterns = slices.Clone(cfg.BypassPatterns)

	cop := http.NewCrossOriginProtection()
	for _, origin := range cfg.TrustedOrigins {
		if err := cop.AddTrustedOrigin(origin); err != nil {
			panic(fmt.Sprintf("csrf: trusted origin %q: %v", origin, err))
		}
	}

	var bypass *http.ServeMux
	if len(cfg.BypassPatterns) > 0 {
		bypass = http.NewServeMux()
		for _, pattern := range cfg.BypassPatterns {
			registerBypass(bypass, pattern)
		}
	}

	tokenCheck := newTokenChecker(cfg.Token)

	deny := cfg.DenyHandler
	if deny == nil {
		deny = http.HandlerFunc(defaultDeny)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if bypass != nil {
				if h, _ := bypass.Handler(r); h == bypassSentinel {
					next.ServeHTTP(w, r)
					return
				}
			}

			value := &ctxValue{}
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, value))

			if !cfg.DisableOriginCheck {
				if err := cop.Check(r); err != nil {
					value.cause = ErrCrossOrigin
					deny.ServeHTTP(w, r)
					return
				}
			}

			if tokenCheck != nil {
				token, err := tokenCheck(w, r)
				if err != nil {
					value.cause = err
					deny.ServeHTTP(w, r)
					return
				}
				value.token = token
			}

			next.ServeHTTP(w, r)
		})
	}
}

type sentinelHandler struct{}

func (*sentinelHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

// bypassSentinel tells bypass matches apart from the mux's NotFound and
// redirect handlers.
var bypassSentinel http.Handler = &sentinelHandler{}

func registerBypass(mux *http.ServeMux, pattern string) {
	defer func() {
		if r := recover(); r != nil {
			panic(fmt.Sprintf("csrf: bypass pattern %q: %v", pattern, r))
		}
	}()
	mux.Handle(pattern, bypassSentinel)
}

func defaultDeny(w http.ResponseWriter, r *http.Request) {
	message := "cross-site request rejected"
	if err := Cause(r); err != nil {
		message = err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"csrf_rejected","message":"` + message + `"}`))
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

func isForm(r *http.Request) bool {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	return strings.HasPrefix(ct, "application/x-www-form-urlencoded") || strings.HasPrefix(ct, "multipart/form-data")
}

// newTokenChecker returns nil when the token check is disabled. The checker
// returns the request's valid token, issuing a new cookie on safe requests
// that lack one.
func newTokenChecker(t Token) func(w http.ResponseWriter, r *http.Request) (string, error) {
	if !t.Enabled {
		return nil
	}

	cookieName := cmp.Or(t.CookieName, DefaultCookieName)
	headerName := cmp.Or(t.HeaderName, DefaultHeaderName)
	formField := cmp.Or(t.FormField, DefaultFormField)
	cookiePath := cmp.Or(t.CookiePath, "/")

	if t.CookieMaxAge < 0 {
		panic("csrf: Token.CookieMaxAge must not be negative")
	}

	var sameSite http.SameSite
	switch strings.ToLower(strings.TrimSpace(t.CookieSameSite)) {
	case "", "lax":
		sameSite = http.SameSiteLaxMode
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "none":
		if t.CookieInsecure {
			panic("csrf: Token.CookieSameSite none requires a secure cookie")
		}
		sameSite = http.SameSiteNoneMode
	default:
		panic(fmt.Sprintf("csrf: unsupported Token.CookieSameSite %q", t.CookieSameSite))
	}

	if strings.HasPrefix(cookieName, "__Host-") && (t.CookieInsecure || t.CookieDomain != "" || cookiePath != "/") {
		panic("csrf: __Host- cookies must be secure, have no domain and use path /")
	}
	if strings.HasPrefix(cookieName, "__Secure-") && t.CookieInsecure {
		panic("csrf: __Secure- cookies must be secure")
	}

	signer := tokenSigner{secret: []byte(t.Secret)}

	issue := func(w http.ResponseWriter) (string, error) {
		token, err := signer.generate()
		if err != nil {
			return "", err
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    token,
			Path:     cookiePath,
			Domain:   t.CookieDomain,
			MaxAge:   int(t.CookieMaxAge / time.Second),
			Secure:   !t.CookieInsecure,
			HttpOnly: false, // JavaScript must read it to send it back in the header.
			SameSite: sameSite,
		})

		return token, nil
	}

	return func(w http.ResponseWriter, r *http.Request) (string, error) {
		var cookieToken string
		if c, err := r.Cookie(cookieName); err == nil && signer.valid(c.Value) {
			cookieToken = c.Value
		}

		if isSafeMethod(r.Method) {
			if cookieToken == "" {
				return issue(w)
			}
			return cookieToken, nil
		}

		if cookieToken == "" {
			return "", ErrTokenMissing
		}

		sent := r.Header.Get(headerName)
		if sent == "" && isForm(r) {
			sent = r.PostFormValue(formField)
		}
		if sent == "" {
			return "", ErrTokenMissing
		}

		if subtle.ConstantTimeCompare([]byte(sent), []byte(cookieToken)) != 1 {
			return "", ErrTokenInvalid
		}

		return cookieToken, nil
	}
}

type tokenSigner struct {
	secret []byte
}

func (s tokenSigner) generate() (string, error) {
	b := make([]byte, tokenSize)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate csrf token: %w", err)
	}

	token := base64.RawURLEncoding.EncodeToString(b)
	if len(s.secret) == 0 {
		return token, nil
	}

	return token + "." + s.sign(token), nil
}

func (s tokenSigner) sign(token string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(token))

	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s tokenSigner) valid(value string) bool {
	token, sig, signed := strings.Cut(value, ".")
	if signed != (len(s.secret) > 0) {
		return false
	}

	if b, err := base64.RawURLEncoding.DecodeString(token); err != nil || len(b) != tokenSize {
		return false
	}

	return !signed || hmac.Equal([]byte(sig), []byte(s.sign(token)))
}

// ////////////////////////////////////////////////////////////////////

type option struct {
	Config Config
}

type Option func(*option)

func WithConfig(cfg Config) Option {
	return func(o *option) {
		o.Config = cfg
	}
}
