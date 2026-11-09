// Package oauthserver is an OAuth 2.1 authorization server for the clients of
// your own application: MCP clients, CLIs, editor extensions.
//
// It implements what the MCP authorization spec asks of a server that issues
// its own tokens:
//
//   - Authorization server metadata (RFC 8414), plus an OpenID-style
//     discovery document for clients that only look there
//   - Dynamic client registration (RFC 7591)
//   - The authorization code grant with mandatory PKCE S256, a consent page
//     and remembered consent
//   - The refresh token grant with rotation
//   - Token revocation (RFC 7009) and the iss response parameter (RFC 9207)
//   - Resource indicators (RFC 8707)
//
// Users sign in through whatever the application already has. With
// middleware/auth that is one call, auth.WithOAuthServer; without it, set
// Config.Authenticate to a middleware that puts an identity in the request
// context.
//
// Tokens are opaque random strings. Only their SHA-256 hashes reach the
// Store, so a copy of the database holds no usable credential. The same
// Server validates them again on protected routes, through Strategy (as an
// auth strategy) or RequireToken (as a plain middleware).
package oauthserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/cookie"
	"github.com/rakunlabs/ada/middleware/auth/proxy"
)

// Mux is the subset of *ada.Mux the server registers routes on. It is the
// same interface as auth.Mux.
type Mux interface {
	HandleWithMethod(method, pattern string, handler http.HandlerFunc, mw ...func(http.Handler) http.Handler)
}

// Defaults.
const (
	DefaultCodeTTL            = 5 * time.Minute
	DefaultAccessTTL          = time.Hour
	DefaultRefreshTTL         = 30 * 24 * time.Hour
	DefaultAccessTokenPrefix  = "oat_"
	DefaultRefreshTokenPrefix = "ort_"
	DefaultStrategyName       = "oauth"

	// maxBody caps registration, token and revocation requests.
	maxBody = 64 << 10
	// maxRedirectURIs caps a registration.
	maxRedirectURIs = 10
)

// Well-known paths.
const (
	WellKnownAuthorizationServer = "/.well-known/oauth-authorization-server"
	WellKnownOpenIDConfiguration = "/.well-known/openid-configuration"
)

// Config configures a Server.
type Config struct {
	// Issuer pins the public issuer URL, e.g. "https://app.example.com".
	// Endpoints are advertised under it: {Issuer}/oauth/token and so on.
	//
	// Leave it empty to derive it from the request origin plus BasePath.
	// Pin it in production: an issuer that follows the Host header is an
	// issuer an attacker can choose. IssuerFunc overrides both.
	Issuer string `cfg:"issuer"`

	// BasePath is the path the application is mounted under in the mux,
	// e.g. "/" or "/dataport". Endpoints are registered at
	// {BasePath}oauth/authorize etc. Defaults to "/". Use the same value as
	// auth.Config.Base.
	BasePath string `cfg:"base_path"`

	// ServiceName is shown on the consent page ("… wants to access
	// ServiceName"). Defaults to the issuer host.
	ServiceName string `cfg:"service_name"`

	// ScopesSupported lists the scopes clients may request. A request for
	// anything else fails with invalid_scope. Empty accepts any scope.
	ScopesSupported []string `cfg:"scopes_supported"`

	// DefaultScopes are granted when a client asks for none.
	DefaultScopes []string `cfg:"default_scopes"`

	// Resources lists the RFC 8707 resource identifiers clients may ask
	// tokens for, e.g. "https://app.example.com/mcp". A request for one of
	// them or a path below it ("…/mcp/shop") is accepted; anything else is
	// invalid_target. Empty accepts any resource on the issuer's origin.
	// A token issued for a resource is accepted only on that resource (see
	// TokenStrategy), which is the audience check the MCP spec requires.
	Resources []string `cfg:"resources"`

	// CodeTTL is the authorization code lifetime. Default 5m.
	CodeTTL time.Duration `cfg:"code_ttl"`
	// AccessTTL is the access token lifetime. Default 1h.
	AccessTTL time.Duration `cfg:"access_ttl"`
	// RefreshTTL is the absolute refresh token lifetime, counted from the
	// first sign-in: rotation does not extend it, so a client in constant
	// use still signs in again at the end. Default 30 days. Negative
	// disables refresh tokens.
	RefreshTTL time.Duration `cfg:"refresh_ttl"`

	// AccessTokenPrefix and RefreshTokenPrefix mark tokens of this server,
	// so the strategy can tell them from API keys and JWTs on the same
	// Authorization header. Defaults "oat_" and "ort_".
	AccessTokenPrefix  string `cfg:"access_token_prefix"`
	RefreshTokenPrefix string `cfg:"refresh_token_prefix"`

	// DisableRegistration turns off dynamic client registration. Clients
	// are then created with Server.RegisterClient.
	DisableRegistration bool `cfg:"disable_registration"`

	// RegistrationsPerHour caps dynamic registrations per client IP, so an
	// anonymous caller cannot fill the clients table. Default 60; negative
	// disables the cap. Re-registrations that reuse an existing client do
	// not count. The client IP honours TrustedProxies.
	RegistrationsPerHour int `cfg:"registrations_per_hour"`

	// RootFallback also answers /authorize, /token and /register at the
	// origin root (and under BasePath), for MCP clients of the 2025-03-26
	// revision that guess these paths when they find no metadata.
	RootFallback bool `cfg:"root_fallback"`

	// DisableOpenIDConfiguration stops publishing
	// /.well-known/openid-configuration. Some clients only look there; the
	// document carries an empty key set because no ID tokens are issued.
	DisableOpenIDConfiguration bool `cfg:"disable_openid_configuration"`

	// ConsentURL sends the browser to the application's own consent page
	// instead of the built-in one, with the authorization request as the
	// query string. The page reads GET {BasePath}oauth/authorize/info and
	// answers with a JSON POST to {BasePath}oauth/authorize. It may be a
	// path ("/#/oauth/authorize") or an absolute URL.
	ConsentURL string `cfg:"consent_url"`

	// CSRFCookie controls the cookie protecting the built-in consent form.
	CSRFCookie cookie.Options `cfg:"csrf_cookie"`

	// TrustedProxies lists CIDRs allowed to set X-Forwarded-Proto and
	// X-Forwarded-Host when the issuer is derived. Only consulted when
	// Issuer and IssuerFunc are empty.
	TrustedProxies []string `cfg:"trusted_proxies"`
	// UnsafeTrustAllForwardedHeaders trusts forwarding headers from any
	// peer when deriving the issuer.
	UnsafeTrustAllForwardedHeaders bool `cfg:"unsafe_trust_all_forwarded_headers"`

	// StrategyName is the name of the token strategy returned by Strategy.
	// Default "oauth".
	StrategyName string `cfg:"strategy_name"`

	// IssuerFunc computes the issuer per request, e.g. from an external URL
	// an administrator can change at runtime. It wins over Issuer.
	IssuerFunc func(r *http.Request) string `cfg:"-" json:"-"`

	// Authenticate guards the authorize endpoints. It must put the signed-in
	// user in the request context with identity.WithContext, or send the
	// browser to sign in and back. auth.WithOAuthServer sets it to
	// Auth.Require; set it yourself when not using middleware/auth.
	Authenticate func(http.Handler) http.Handler `cfg:"-" json:"-"`

	// Hooks customizes authorization and token use.
	Hooks Hooks `cfg:"-" json:"-"`

	// Now replaces time.Now in tests.
	Now func() time.Time `cfg:"-" json:"-"`
}

// Server is an OAuth 2.1 authorization server.
type Server struct {
	cfg     Config
	store   Store
	regRate *rateWindow
	base    string // BasePath without trailing slash; "" for root
	issuer  string // pinned issuer without trailing slash
	policy  proxy.Policy
	now     func() time.Time
}

// New validates cfg and returns a Server backed by store.
func New(cfg Config, store Store) (*Server, error) {
	if store == nil {
		return nil, fmt.Errorf("oauthserver: nil store")
	}

	s := &Server{store: store, now: cfg.Now}
	if s.now == nil {
		s.now = time.Now
	}

	s.base = strings.TrimSuffix("/"+strings.Trim(cfg.BasePath, "/"), "/")

	if cfg.Issuer != "" {
		u, err := url.Parse(cfg.Issuer)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("oauthserver: issuer %q must be an absolute http(s) URL without query or fragment", cfg.Issuer)
		}

		s.issuer = strings.TrimSuffix(cfg.Issuer, "/")
	}

	for _, scope := range append(append([]string(nil), cfg.ScopesSupported...), cfg.DefaultScopes...) {
		if !validScope(scope) {
			return nil, fmt.Errorf("oauthserver: invalid scope %q", scope)
		}
	}

	if len(cfg.ScopesSupported) > 0 {
		for _, scope := range cfg.DefaultScopes {
			if !slices.Contains(cfg.ScopesSupported, scope) {
				return nil, fmt.Errorf("oauthserver: default scope %q is not in scopes_supported", scope)
			}
		}
	}

	policy, err := proxy.New(cfg.TrustedProxies...)
	if err != nil {
		return nil, fmt.Errorf("oauthserver: trusted_proxies: %w", err)
	}
	s.policy = policy

	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = DefaultCodeTTL
	}
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = DefaultAccessTTL
	}
	if cfg.RefreshTTL == 0 {
		cfg.RefreshTTL = DefaultRefreshTTL
	}
	if cfg.AccessTokenPrefix == "" {
		cfg.AccessTokenPrefix = DefaultAccessTokenPrefix
	}
	if cfg.RefreshTokenPrefix == "" {
		cfg.RefreshTokenPrefix = DefaultRefreshTokenPrefix
	}
	if cfg.AccessTokenPrefix == cfg.RefreshTokenPrefix {
		return nil, fmt.Errorf("oauthserver: access and refresh token prefixes must differ")
	}
	if cfg.StrategyName == "" {
		cfg.StrategyName = DefaultStrategyName
	}
	if cfg.RegistrationsPerHour == 0 {
		cfg.RegistrationsPerHour = 60
	}
	if cfg.RegistrationsPerHour > 0 {
		s.regRate = newRateWindow(cfg.RegistrationsPerHour, time.Hour, s.now)
	}

	cfg.CSRFCookie = cfg.CSRFCookie.WithDefaults()
	cfg.CSRFCookie.SameSite = http.SameSiteStrictMode
	cfg.CSRFCookie.DisableHTTPOnly = false

	s.cfg = cfg

	return s, nil
}

// Store returns the store the server was built with.
func (s *Server) Store() Store { return s.store }

// SetAuthenticate sets Config.Authenticate when it was left empty. It is how
// auth.WithOAuthServer plugs in the session middleware; an explicit value
// wins.
func (s *Server) SetAuthenticate(mw func(http.Handler) http.Handler) {
	if s.cfg.Authenticate == nil {
		s.cfg.Authenticate = mw
	}
}

// Paths are the mux paths of the endpoints.
type Paths struct {
	Authorize     string
	AuthorizeInfo string
	Token         string
	Register      string
	Revoke        string
	JWKS          string
}

// Paths returns where the endpoints are registered in the mux.
func (s *Server) Paths() Paths {
	return Paths{
		Authorize:     s.base + "/oauth/authorize",
		AuthorizeInfo: s.base + "/oauth/authorize/info",
		Token:         s.base + "/oauth/token",
		Register:      s.base + "/oauth/register",
		Revoke:        s.base + "/oauth/revoke",
		JWKS:          s.base + "/oauth/jwks",
	}
}

// Mount registers the endpoints and discovery documents on mux.
//
// Mount it on the root mux, not a group: the well-known documents live at the
// origin. Panics when Config.Authenticate is unset, because the authorize
// endpoint would otherwise have no way to know the user.
func (s *Server) Mount(mux Mux) {
	if s.cfg.Authenticate == nil {
		panic("oauthserver: Mount without Config.Authenticate; use auth.WithOAuthServer or set it")
	}

	p := s.Paths()

	// RFC 8414 inserts the issuer's path after the well-known prefix. With a
	// pinned issuer whose path differs from the mux base (a proxy strips a
	// prefix), register that form too: a proxy forwarding the origin root
	// to this process then answers strict clients.
	paths := []string{s.base}
	if u, err := url.Parse(s.issuer); err == nil && strings.TrimSuffix(u.Path, "/") != s.base {
		paths = append(paths, strings.TrimSuffix(u.Path, "/"))
	}

	wellKnown := func(prefix string) []string {
		list := []string{s.base + prefix}
		for _, ip := range paths {
			list = append(list, prefix+ip)
		}

		return uniq(list...)
	}

	for _, path := range wellKnown(WellKnownAuthorizationServer) {
		handle(mux, path, s.handleMetadata, http.MethodGet)
	}

	if !s.cfg.DisableOpenIDConfiguration {
		for _, path := range wellKnown(WellKnownOpenIDConfiguration) {
			handle(mux, path, s.handleOpenIDConfiguration, http.MethodGet)
		}
		handle(mux, p.JWKS, s.handleJWKS, http.MethodGet)
	}

	authorize := s.cfg.Authenticate(http.HandlerFunc(s.handleAuthorize)).ServeHTTP
	info := s.cfg.Authenticate(http.HandlerFunc(s.handleAuthorizeInfo)).ServeHTTP

	mux.HandleWithMethod(http.MethodGet, p.Authorize, authorize)
	mux.HandleWithMethod(http.MethodPost, p.Authorize, authorize)
	mux.HandleWithMethod(http.MethodGet, p.AuthorizeInfo, info)

	handle(mux, p.Token, s.handleToken, http.MethodPost)
	handle(mux, p.Revoke, s.handleRevoke, http.MethodPost)
	if !s.cfg.DisableRegistration {
		handle(mux, p.Register, s.handleRegister, http.MethodPost)
	}

	if s.cfg.RootFallback {
		prefixes := []string{""}
		if s.base != "" {
			prefixes = append(prefixes, s.base)
		}

		for _, prefix := range prefixes {
			mux.HandleWithMethod(http.MethodGet, prefix+"/authorize", s.redirectTo(p.Authorize))
			handle(mux, prefix+"/token", s.handleToken, http.MethodPost)
			if !s.cfg.DisableRegistration {
				handle(mux, prefix+"/register", s.handleRegister, http.MethodPost)
			}
		}
	}
}

// handle registers a CORS-enabled, cookie-free endpoint with its preflight.
func handle(mux Mux, path string, h http.HandlerFunc, method string) {
	wrapped := withCORS(h)
	mux.HandleWithMethod(method, path, wrapped)
	mux.HandleWithMethod(http.MethodOptions, path, wrapped)
}

// redirectTo forwards a fallback path to the real endpoint, keeping the
// query.
func (s *Server) redirectTo(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := s.publicURL(r, path)
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}

		http.Redirect(w, r, target, http.StatusFound)
	}
}

// Issuer returns the issuer identifier for the request, or "" when it cannot
// be derived (a Host header the proxy policy rejects).
func (s *Server) Issuer(r *http.Request) string {
	if s.cfg.IssuerFunc != nil {
		return strings.TrimSuffix(s.cfg.IssuerFunc(r), "/")
	}
	if s.issuer != "" {
		return s.issuer
	}

	var (
		origin proxy.Origin
		err    error
	)
	if s.cfg.UnsafeTrustAllForwardedHeaders {
		origin, err = proxy.UnsafeOrigin(r)
	} else {
		origin, err = s.policy.Origin(r)
	}
	if err != nil {
		return ""
	}

	return origin.String() + s.base
}

// AuthorizationServers returns the issuer as a list, the shape
// resource.Config.AuthorizationServersFunc expects.
func (s *Server) AuthorizationServers(r *http.Request) []string {
	if iss := s.Issuer(r); iss != "" {
		return []string{iss}
	}

	return nil
}

// publicURL maps a mux path to its public URL under the issuer.
func (s *Server) publicURL(r *http.Request, muxPath string) string {
	return s.Issuer(r) + strings.TrimPrefix(muxPath, s.base)
}

// Metadata returns the RFC 8414 document for the request.
func (s *Server) Metadata(r *http.Request) map[string]any {
	p := s.Paths()
	iss := s.Issuer(r)

	grants := []string{GrantCode}
	if s.cfg.RefreshTTL > 0 {
		grants = append(grants, GrantRefresh)
	}

	meta := map[string]any{
		"issuer":                                         iss,
		"authorization_endpoint":                         s.publicURL(r, p.Authorize),
		"token_endpoint":                                 s.publicURL(r, p.Token),
		"revocation_endpoint":                            s.publicURL(r, p.Revoke),
		"response_types_supported":                       []string{ResponseTypeCode},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          grants,
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{AuthMethodNone, AuthMethodBasic, AuthMethodPost},
		"revocation_endpoint_auth_methods_supported":     []string{AuthMethodNone, AuthMethodBasic, AuthMethodPost},
		"authorization_response_iss_parameter_supported": true,
	}

	if !s.cfg.DisableRegistration {
		meta["registration_endpoint"] = s.publicURL(r, p.Register)
	}
	if len(s.cfg.ScopesSupported) > 0 {
		meta["scopes_supported"] = s.cfg.ScopesSupported
	}

	return meta
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if s.Issuer(r) == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "issuer unavailable")

		return
	}

	writeJSON(w, http.StatusOK, s.Metadata(r), true)
}

// handleOpenIDConfiguration serves the metadata in OpenID Connect discovery
// shape. Clients that validate against the OIDC schema need the fields it
// marks required, even though this server issues no ID tokens.
func (s *Server) handleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	if s.Issuer(r) == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "issuer unavailable")

		return
	}

	meta := s.Metadata(r)
	meta["jwks_uri"] = s.publicURL(r, s.Paths().JWKS)
	meta["subject_types_supported"] = []string{"public"}
	meta["id_token_signing_alg_values_supported"] = []string{"RS256"}

	writeJSON(w, http.StatusOK, meta, true)
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []any{}}, true)
}

// withCORS lets browser-based clients (the MCP Inspector, web IDEs) read
// metadata and exchange codes. These endpoints never read cookies, so a
// wildcard origin grants nothing a curl call could not do.
func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Protocol-Version")
		h.Set("Access-Control-Max-Age", "600")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)

			return
		}

		next(w, r)
	}
}

// ////////////////////////////////////////////////////////////////////////////
// helpers

func uniq(list ...string) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		if v == "" {
			v = "/"
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}

	return out
}

func writeJSON(w http.ResponseWriter, status int, v any, cacheable bool) {
	if cacheable {
		w.Header().Set("Cache-Control", "public, max-age=300")
	} else {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("oauthserver: write json", "error", err.Error())
	}
}

// oauthError writes an RFC 6749 §5.2 error response.
func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc}, false)
}

// HashSecret returns the SHA-256 hex digest under which codes, tokens and
// client secrets are stored. Use it to look tokens up in your own store.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))

	return hex.EncodeToString(sum[:])
}

// randomString returns n random bytes, base64url encoded.
func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauthserver: random: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func validScope(scope string) bool {
	if scope == "" {
		return false
	}

	// RFC 6749 §3.3: NQCHAR, i.e. printable ASCII except space, " and \.
	for i := range len(scope) {
		c := scope[i]
		if c <= 0x20 || c >= 0x7f || c == '"' || c == '\\' {
			return false
		}
	}

	return true
}
