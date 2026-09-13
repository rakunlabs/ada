// Package resource publishes OAuth 2.0 Protected Resource Metadata (RFC 9728)
// and builds the Bearer challenge that points clients at it.
//
// This is the discovery half of being a resource server. A client that gets a
// 401 from a protected endpoint reads the resource_metadata parameter of the
// WWW-Authenticate header, fetches the document this package serves, learns
// which authorization server to talk to, and completes an OAuth flow without
// anyone hand-configuring an endpoint. It is what makes `claude mcp add` or
// an editor's "connect" button work against a server it has never seen.
//
// The package does not validate tokens. Publishing metadata and enforcing it
// are separate concerns with separate failure modes; see
// middleware/auth/strategy/bearer for the enforcement side.
package resource

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/rakunlabs/ada/middleware/auth/proxy"
)

// WellKnownPath is the registered well-known URI for protected resource
// metadata (RFC 9728 §3).
const WellKnownPath = "/.well-known/oauth-protected-resource"

// DefaultCacheMaxAge is how long the metadata document may be cached. It is
// configuration a client re-reads only when something breaks, and the values
// in it change on the order of deployments, not requests.
const DefaultCacheMaxAge = 300

// Metadata is the RFC 9728 §2 protected resource metadata document.
//
// Only the fields a resource server can honestly answer are modelled. An
// omitted field means "not asserted", which is a different and more useful
// statement than an empty one.
type Metadata struct {
	// Resource is the resource identifier (RFC 8707). Required.
	Resource string `json:"resource"`
	// AuthorizationServers lists issuer identifiers whose tokens this
	// resource accepts.
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	// JWKSURI is the resource's own key set, for deployments that verify
	// tokens without an authorization server in the loop.
	JWKSURI string `json:"jwks_uri,omitempty"`
	// ScopesSupported advertises the scopes a client may usefully request.
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// BearerMethodsSupported is how the token may be presented. This package
	// only ever claims "header": a token in a query string ends up in access
	// logs and browser history.
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	// ResourceName is a human-readable name shown by clients during consent.
	ResourceName string `json:"resource_name,omitempty"`
	// ResourceDocumentation is a URL for developers.
	ResourceDocumentation string `json:"resource_documentation,omitempty"`
	// TLSClientCertificateBoundAccessTokens signals RFC 8705 support.
	TLSClientCertificateBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens,omitempty"`
}

// Config configures the metadata document.
type Config struct {
	// Resource pins the resource identifier, e.g.
	// "https://mcp.example.com/mcp". Leave it empty to derive the identifier
	// from the request origin plus ResourcePath.
	//
	// Pin it in production. A derived identifier depends on the Host header
	// and the proxy chain in front of the process, which means the value a
	// client is told to request a token for can change with the network.
	Resource string `cfg:"resource"`

	// ResourcePath is the path component of a derived resource identifier,
	// e.g. "/mcp". Ignored when Resource is set. Empty means the origin
	// itself is the resource.
	ResourcePath string `cfg:"resource_path"`

	// AuthorizationServers lists the issuer identifiers clients should use.
	// These are issuer URLs, not metadata URLs: a client appends
	// /.well-known/oauth-authorization-server itself.
	AuthorizationServers []string `cfg:"authorization_servers"`

	// JWKSURI advertises the resource's own key set. An alternative to
	// AuthorizationServers, not a supplement to it in most deployments.
	JWKSURI string `cfg:"jwks_uri"`

	// ScopesSupported advertises requestable scopes.
	ScopesSupported []string `cfg:"scopes_supported"`

	// ResourceName is shown to users during consent.
	ResourceName string `cfg:"resource_name"`

	// ResourceDocumentation is a developer-facing URL.
	ResourceDocumentation string `cfg:"resource_documentation"`

	// TLSClientCertificateBoundAccessTokens advertises RFC 8705 support.
	TLSClientCertificateBoundAccessTokens bool `cfg:"tls_client_certificate_bound_access_tokens"`

	// CacheMaxAge is the Cache-Control max-age in seconds. Zero uses
	// DefaultCacheMaxAge; negative disables caching.
	CacheMaxAge int `cfg:"cache_max_age"`

	// TrustedProxies lists CIDRs allowed to set X-Forwarded-Proto and
	// X-Forwarded-Host when deriving the origin. Only consulted when
	// Resource is empty.
	TrustedProxies []string `cfg:"trusted_proxies"`

	// UnsafeTrustAllForwardedHeaders derives the origin from forwarding
	// headers sent by any peer. Only for deployments that enforce the proxy
	// boundary outside the process.
	UnsafeTrustAllForwardedHeaders bool `cfg:"unsafe_trust_all_forwarded_headers"`
}

// Server serves the metadata document and builds matching challenges.
type Server struct {
	cfg Config

	// resource is the pinned identifier, or "" when derived per request.
	resource string
	// path is the resource's path component, with no trailing slash. It is
	// both the suffix appended to WellKnownPath and the value the handler
	// matches an incoming request against.
	path string

	policy   proxy.Policy
	unsafe   bool
	maxAge   int
	scopes   []string
	authServ []string
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	s := &Server{cfg: cfg, unsafe: cfg.UnsafeTrustAllForwardedHeaders}

	switch {
	case cfg.Resource != "" && cfg.ResourcePath != "":
		return nil, fmt.Errorf("resource: set either resource or resource_path, not both")

	case cfg.Resource != "":
		path, err := resourcePath(cfg.Resource)
		if err != nil {
			return nil, err
		}

		s.resource = strings.TrimSuffix(cfg.Resource, "/")
		s.path = path

	case cfg.ResourcePath != "":
		path, err := validatePath(cfg.ResourcePath)
		if err != nil {
			return nil, err
		}

		s.path = path
	}

	// A document with neither an authorization server nor a key set tells a
	// client "you need a token" and then refuses to say where to get one.
	// That is a 401 loop, not discovery.
	if len(cfg.AuthorizationServers) == 0 && cfg.JWKSURI == "" {
		return nil, fmt.Errorf("resource: authorization_servers or jwks_uri is required")
	}

	for i, issuer := range cfg.AuthorizationServers {
		if err := validateAbsoluteURL(issuer); err != nil {
			return nil, fmt.Errorf("resource: authorization_servers[%d]: %w", i, err)
		}

		s.authServ = append(s.authServ, strings.TrimSuffix(issuer, "/"))
	}

	if cfg.JWKSURI != "" {
		if err := validateAbsoluteURL(cfg.JWKSURI); err != nil {
			return nil, fmt.Errorf("resource: jwks_uri: %w", err)
		}
	}

	for _, scope := range cfg.ScopesSupported {
		if scope == "" || strings.ContainsAny(scope, " \t\r\n\"\\") {
			return nil, fmt.Errorf("resource: scopes_supported contains an invalid scope %q", scope)
		}

		s.scopes = append(s.scopes, scope)
	}

	policy, err := proxy.New(cfg.TrustedProxies...)
	if err != nil {
		return nil, fmt.Errorf("resource: trusted_proxies: %w", err)
	}
	s.policy = policy

	s.maxAge = cfg.CacheMaxAge
	if s.maxAge == 0 {
		s.maxAge = DefaultCacheMaxAge
	}

	return s, nil
}

// Paths returns the URL patterns the metadata handler must be registered on.
//
// Both the bare well-known path and the path-inserted form (RFC 9728 §3.1)
// are returned. Registering both means a client that guesses the wrong one
// gets a 404 from this package rather than whatever the application's
// catch-all happens to be.
func (s *Server) Paths() []string {
	return []string{WellKnownPath, WellKnownPath + "/*"}
}

// ResourceID returns the resource identifier for the request.
func (s *Server) ResourceID(r *http.Request) string {
	if s.resource != "" {
		return s.resource
	}

	origin, err := s.origin(r)
	if err != nil {
		return ""
	}

	return origin + s.path
}

// MetadataURL returns the absolute URL of the metadata document, applying the
// path insertion rule of RFC 9728 §3.1: the resource's path component is
// appended to the well-known path rather than the other way round, so
// https://h/mcp is described at https://h/.well-known/oauth-protected-resource/mcp.
func (s *Server) MetadataURL(r *http.Request) string {
	origin := s.resourceOrigin(r)
	if origin == "" {
		return ""
	}

	return origin + WellKnownPath + s.path
}

// Metadata returns the document for the request.
func (s *Server) Metadata(r *http.Request) Metadata {
	return Metadata{
		Resource:                              s.ResourceID(r),
		AuthorizationServers:                  s.authServ,
		JWKSURI:                               s.cfg.JWKSURI,
		ScopesSupported:                       s.scopes,
		BearerMethodsSupported:                []string{"header"},
		ResourceName:                          s.cfg.ResourceName,
		ResourceDocumentation:                 s.cfg.ResourceDocumentation,
		TLSClientCertificateBoundAccessTokens: s.cfg.TLSClientCertificateBoundAccessTokens,
	}
}

// Handler serves the metadata document.
//
// A request whose path suffix does not match the configured resource gets a
// 404. Answering every suffix with the same document would assert that this
// server guards resources it has never heard of.
func (s *Server) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, WellKnownPath), "/")
		if suffix != s.path {
			http.NotFound(w, r)

			return
		}

		doc := s.Metadata(r)
		if doc.Resource == "" {
			// The origin could not be derived — a Host header the proxy
			// policy rejects. Serving a document with an empty resource
			// would hand the client a broken token request.
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, `{"error":"invalid_request","message":"resource identifier unavailable"}`, http.StatusBadRequest)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		if s.maxAge > 0 {
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", s.maxAge))
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}

		if err := json.NewEncoder(w).Encode(doc); err != nil {
			slog.Debug("resource: write metadata", "error", err.Error())
		}
	}
}

// ChallengeParams are the optional RFC 6750 §3 parameters on a Bearer
// challenge.
type ChallengeParams struct {
	// Error is an RFC 6750 error code: invalid_request, invalid_token or
	// insufficient_scope. Empty for a plain "you need a token" challenge —
	// RFC 6750 §3 forbids an error code when no token was presented.
	Error string
	// Description is a human-readable explanation. Keep it free of anything
	// derived from the token; it is echoed to an unauthenticated caller.
	Description string
	// Scope lists the scopes required for the request, used with
	// insufficient_scope.
	Scope []string
}

// Bearer error codes (RFC 6750 §3.1).
const (
	ErrorInvalidRequest    = "invalid_request"
	ErrorInvalidToken      = "invalid_token"
	ErrorInsufficientScope = "insufficient_scope"
)

// Challenge builds the WWW-Authenticate value for a 401 or 403.
//
// The resource_metadata parameter (RFC 9728 §5.1) is what turns an opaque 401
// into a flow a client can complete on its own.
func (s *Server) Challenge(r *http.Request, p ChallengeParams) string {
	params := make([]string, 0, 4)

	if url := s.MetadataURL(r); url != "" {
		params = append(params, `resource_metadata=`+quoteParam(url))
	}
	if p.Error != "" {
		params = append(params, `error=`+quoteParam(p.Error))
	}
	if p.Description != "" {
		params = append(params, `error_description=`+quoteParam(p.Description))
	}
	if len(p.Scope) > 0 {
		params = append(params, `scope=`+quoteParam(strings.Join(p.Scope, " ")))
	}

	if len(params) == 0 {
		return "Bearer"
	}

	return "Bearer " + strings.Join(params, ", ")
}

// resourceOrigin returns the scheme://host the metadata document lives under.
func (s *Server) resourceOrigin(r *http.Request) string {
	if s.resource != "" {
		// Strip the path back off the pinned identifier: the well-known
		// document sits at the origin, not under the resource path.
		return strings.TrimSuffix(s.resource, s.path)
	}

	origin, err := s.origin(r)
	if err != nil {
		return ""
	}

	return origin
}

func (s *Server) origin(r *http.Request) (string, error) {
	if s.unsafe {
		origin, err := proxy.UnsafeOrigin(r)

		return origin.String(), err
	}

	origin, err := s.policy.Origin(r)

	return origin.String(), err
}

// resourcePath extracts and validates the path component of a resource
// identifier. RFC 8707 §2 requires an absolute URI without a fragment; a
// query is rejected too, because the path-insertion rule has nowhere to put
// one.
func resourcePath(raw string) (string, error) {
	if err := validateAbsoluteURL(raw); err != nil {
		return "", fmt.Errorf("resource: resource: %w", err)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("resource: resource: %w", err)
	}

	return strings.TrimSuffix(u.EscapedPath(), "/"), nil
}

func validatePath(raw string) (string, error) {
	if !strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("resource: resource_path %q must start with /", raw)
	}
	if strings.ContainsAny(raw, "?#") {
		return "", fmt.Errorf("resource: resource_path %q must not contain a query or fragment", raw)
	}

	return strings.TrimSuffix(raw, "/"), nil
}

func validateAbsoluteURL(raw string) error {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return fmt.Errorf("must not be empty or surrounded by whitespace")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return fmt.Errorf("%q must be an absolute http(s) URL", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("%q has no host", raw)
	}
	// RFC 8707 §2: the resource indicator must not include a fragment. A
	// query is allowed by the RFC but rejected here, because it cannot
	// survive the RFC 9728 §3.1 path-insertion round trip.
	if u.Fragment != "" || u.RawQuery != "" {
		return fmt.Errorf("%q must not contain a query or fragment", raw)
	}

	return nil
}

// quoteParam renders a challenge parameter as an RFC 9110 §5.6.4
// quoted-string.
//
// Everything is quoted rather than only what has to be: an unquoted token has
// a narrower grammar than a URL, and a value that slips out of it turns the
// whole header into something the client discards. Control characters are
// dropped outright — one of them in a response header is a header-splitting
// bug, not a formatting one.
func quoteParam(value string) string {
	var b strings.Builder

	b.Grow(len(value) + 2)
	b.WriteByte('"')

	for i := range len(value) {
		c := value[i]
		switch {
		case c < 0x20 || c == 0x7f:
			continue
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}

	b.WriteByte('"')

	return b.String()
}
