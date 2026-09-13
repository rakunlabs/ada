// Package bearer authenticates a request from an OAuth 2.0 access token it
// carries, rather than exchanging credentials for a session.
//
// This is the enforcement half of being a resource server. The token was
// issued by somebody else — Keycloak, turna, Auth0, Entra — and arrives in an
// Authorization header. The strategy verifies its signature against the
// issuer's JWKS, checks that it was issued by the expected issuer, for this
// resource, and has not expired, and turns its claims into an Identity.
//
// Paired with middleware/auth/resource it completes the discovery loop an MCP
// client or a CLI walks on its own:
//
//	POST /mcp                     -> 401, WWW-Authenticate: Bearer resource_metadata="..."
//	GET  /.well-known/oauth-protected-resource -> authorization_servers
//	...client runs an OAuth flow against that server...
//	POST /mcp  Authorization: Bearer <token>   -> 200
//
// Scope enforcement is deliberately not done here. A token that is authentic
// but lacks a scope is an authorization failure (403), not an authentication
// one (401), and middleware/auth/authz already draws that line correctly.
package bearer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/internal/jwt"
	"github.com/rakunlabs/ada/middleware/auth/resource"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

// DefaultClockSkew is the leeway applied to exp and nbf.
const DefaultClockSkew = 60 * time.Second

// maxUpstreamResponseBytes caps discovery and JWKS responses.
const maxUpstreamResponseBytes int64 = 1 << 20

// Errors describing why a presented token was refused. They all wrap
// strategy.ErrInvalidCredentials so Require renders a 401, while remaining
// distinguishable for logging and tests.
var (
	ErrMalformedToken = fmt.Errorf("bearer: malformed token: %w", strategy.ErrInvalidCredentials)
	ErrBadIssuer      = fmt.Errorf("bearer: unexpected issuer: %w", strategy.ErrInvalidCredentials)
	ErrBadAudience    = fmt.Errorf("bearer: token audience does not include this resource: %w", strategy.ErrInvalidCredentials)
	ErrExpired        = fmt.Errorf("bearer: token expired: %w", strategy.ErrInvalidCredentials)
	ErrNotYetValid    = fmt.Errorf("bearer: token not yet valid: %w", strategy.ErrInvalidCredentials)
	ErrNoExpiry       = fmt.Errorf("bearer: token has no exp claim: %w", strategy.ErrInvalidCredentials)
	ErrNoSubject      = fmt.Errorf("bearer: token has no sub claim: %w", strategy.ErrInvalidCredentials)
	ErrWrongType      = fmt.Errorf("bearer: token is not an access token: %w", strategy.ErrInvalidCredentials)
)

// Config is the protocol-level configuration.
type Config struct {
	// Issuer is the expected `iss` claim and, unless JWKSURL is set, the
	// base for metadata discovery. Required.
	//
	// It is compared exactly. An issuer that differs only by a trailing
	// slash is a different issuer as far as RFC 8414 §2 is concerned, and
	// treating them as equal is how a token minted by a neighbouring tenant
	// gets accepted.
	Issuer string `cfg:"issuer"`

	// JWKSURL is the issuer's key set. Discovered from Issuer when empty.
	JWKSURL string `cfg:"jwks_url"`

	// Audience lists the resource identifiers this server answers to. A
	// token is accepted when its `aud` claim contains any of them.
	//
	// Required unless DisableAudienceCheck. This is the check that stops a
	// token minted for a different service on the same authorization server
	// from being replayed here (RFC 8707 §2, and the reason MCP clients send
	// a `resource` parameter at all).
	Audience []string `cfg:"audience"`

	// DisableAudienceCheck accepts tokens regardless of `aud`.
	//
	// Only safe when this resource is the sole audience the issuer ever
	// mints for. Every other deployment that sets it has turned a
	// single-service compromise into a fleet-wide one.
	DisableAudienceCheck bool `cfg:"disable_audience_check"`

	// RequireAccessTokenType rejects a token whose JOSE `typ` header is not
	// `at+jwt` (RFC 9068 §2.1).
	//
	// Off by default because many issuers still mint access tokens with no
	// typ at all. Turn it on when the issuer sets it: it is the cleanest
	// defence against an id_token being replayed as an access token.
	RequireAccessTokenType bool `cfg:"require_access_token_type"`

	// ClockSkew is the leeway applied to exp and nbf. Zero uses
	// DefaultClockSkew; negative disables leeway entirely.
	ClockSkew time.Duration `cfg:"clock_skew"`

	// Claims maps token claims onto Identity fields.
	Claims ClaimMap `cfg:"claims"`
}

// ClaimMap maps token claims onto identity.Identity fields. Each entry
// accepts a dotted path, so Keycloak's realm_access.roles is configuration
// rather than a code change.
type ClaimMap struct {
	// Subject defaults to "sub".
	Subject string `cfg:"subject"`
	// Name is tried in order; defaults to name, preferred_username.
	Name []string `cfg:"name"`
	// Email defaults to "email".
	Email string `cfg:"email"`
	// EmailVerified defaults to "email_verified".
	EmailVerified string `cfg:"email_verified"`
	// Roles are merged in order; defaults to roles, realm_access.roles.
	Roles []string `cfg:"roles"`
}

func (c ClaimMap) subject() string {
	if c.Subject != "" {
		return c.Subject
	}

	return "sub"
}

func (c ClaimMap) names() []string {
	if len(c.Name) > 0 {
		return c.Name
	}

	return []string{"name", "preferred_username"}
}

func (c ClaimMap) email() string {
	if c.Email != "" {
		return c.Email
	}

	return "email"
}

func (c ClaimMap) emailVerified() string {
	if c.EmailVerified != "" {
		return c.EmailVerified
	}

	return "email_verified"
}

func (c ClaimMap) roles() []string {
	if len(c.Roles) > 0 {
		return c.Roles
	}

	return []string{"roles", "realm_access.roles"}
}

// Options are deployment-level knobs that are not part of the protocol.
type Options struct {
	// Name is the registry key. Defaults to "bearer".
	Name string
	// Label is the human-readable name. Defaults to "Bearer token".
	Label string
	// Priority orders the strategy in the login UI listing.
	Priority int

	// HTTPClient fetches discovery and JWKS documents.
	HTTPClient *http.Client
	// InsecureSkipVerify disables TLS verification for those fetches. For
	// development against a self-signed issuer, and nothing else.
	InsecureSkipVerify bool

	// Resource supplies the RFC 9728 metadata URL advertised in the
	// WWW-Authenticate challenge. Without it the strategy still works, but
	// a client that has never been configured has no way to discover where
	// to get a token — which is the whole point of the exercise.
	Resource *resource.Server

	// Verifier replaces local JWT verification. Use it for opaque tokens
	// validated by RFC 7662 introspection, or for a token format this
	// package does not know about.
	Verifier Verifier

	// Now overrides the clock. For tests.
	Now func() time.Time
}

// Verifier turns a presented token into claims, or an error.
//
// Implementations own authenticity only. The strategy still applies the
// issuer, audience and expiry checks to whatever comes back, so a custom
// verifier cannot accidentally widen who is let in.
type Verifier interface {
	VerifyToken(ctx context.Context, token string) (map[string]any, error)
}

// VerifierFunc adapts a function to Verifier.
type VerifierFunc func(ctx context.Context, token string) (map[string]any, error)

// VerifyToken implements Verifier.
func (f VerifierFunc) VerifyToken(ctx context.Context, token string) (map[string]any, error) {
	return f(ctx, token)
}

// Strategy validates inbound access tokens.
type Strategy struct {
	cfg  Config
	opts Options

	name  string
	label string

	client   *http.Client
	keys     *jwt.KeySet
	verifier Verifier

	discovery *discoveryCache
	skew      time.Duration
	now       func() time.Time
}

// New returns a Strategy for cfg.
func New(cfg Config, opts ...Options) (*Strategy, error) {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}

	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, fmt.Errorf("bearer: issuer is required")
	}
	if cfg.Issuer != strings.TrimSpace(cfg.Issuer) {
		return nil, fmt.Errorf("bearer: issuer must not be surrounded by whitespace")
	}
	if len(cfg.Audience) == 0 && !cfg.DisableAudienceCheck {
		return nil, fmt.Errorf("bearer: audience is required (or set disable_audience_check)")
	}
	for _, aud := range cfg.Audience {
		if strings.TrimSpace(aud) == "" {
			return nil, fmt.Errorf("bearer: audience contains an empty entry")
		}
	}

	s := &Strategy{
		cfg:      cfg,
		opts:     o,
		name:     o.Name,
		label:    o.Label,
		verifier: o.Verifier,
		now:      o.Now,
	}

	if s.name == "" {
		s.name = "bearer"
	}
	if s.label == "" {
		s.label = "Bearer token"
	}
	if s.now == nil {
		s.now = time.Now
	}

	s.skew = cfg.ClockSkew
	if s.skew == 0 {
		s.skew = DefaultClockSkew
	}
	if s.skew < 0 {
		s.skew = 0
	}

	s.client = o.HTTPClient
	if s.client == nil {
		s.client = &http.Client{Timeout: 30 * time.Second}
	}
	if o.InsecureSkipVerify {
		s.client = insecureClient(s.client)
	}

	switch {
	case s.verifier != nil:
		// A custom verifier owns key management entirely.
	case cfg.JWKSURL != "":
		s.keys = jwt.NewKeySet(cfg.JWKSURL, s.client, maxUpstreamResponseBytes)
	default:
		s.discovery = newDiscoveryCache(cfg.Issuer, s.client)
	}

	return s, nil
}

// Name implements strategy.Authenticator.
func (s *Strategy) Name() string { return s.name }

// Descriptor implements strategy.Authenticator.
//
// Hidden: there is no widget a login page could render for "present a token
// you already have".
func (s *Strategy) Descriptor() strategy.Descriptor {
	return strategy.Descriptor{
		Name:     s.name,
		Kind:     "bearer",
		Label:    s.label,
		Priority: s.opts.Priority,
		Hidden:   true,
	}
}

// Login validates the Authorization header and returns the identity, so a
// token holder can exchange it for a session cookie at the login endpoint.
//
// Most callers never use this: presenting the token on each request through
// AuthenticateRequest is simpler and keeps the token the single source of
// truth for expiry.
func (s *Strategy) Login(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	id, err := s.AuthenticateRequest(r.Context(), r)

	switch {
	case errors.Is(err, strategy.ErrNoCredentials):
		s.writeError(w, r, http.StatusUnauthorized, resource.ErrorInvalidRequest, "no bearer token provided")

		return nil, strategy.OutcomeFailed, nil

	case errors.Is(err, strategy.ErrInvalidCredentials):
		s.writeError(w, r, http.StatusUnauthorized, resource.ErrorInvalidToken, "the access token is invalid or expired")

		return nil, strategy.OutcomeFailed, nil

	case err != nil:
		return nil, strategy.OutcomeFailed, err
	}

	return id, strategy.OutcomeContinue, nil
}

// Logout implements strategy.Authenticator. Tokens are the issuer's to
// revoke; there is nothing local to clean up.
func (s *Strategy) Logout(_ context.Context, _ *identity.Identity) error { return nil }

// AuthenticateRequest implements strategy.RequestAuthenticator.
func (s *Strategy) AuthenticateRequest(ctx context.Context, r *http.Request) (*identity.Identity, error) {
	token, ok := extractBearer(r)
	if !ok {
		return nil, strategy.ErrNoCredentials
	}
	if token == "" {
		// The scheme was named but no token followed. That is a broken
		// client, not an anonymous request, and falling through to the
		// cookie would hide it behind a login redirect.
		return nil, ErrMalformedToken
	}

	claims, err := s.verify(ctx, token)
	if err != nil {
		if errors.Is(err, strategy.ErrInvalidCredentials) {
			slog.Debug("bearer: token rejected", "strategy", s.name, "error", err.Error())

			return nil, err
		}

		// A JWKS endpoint that is down is our outage, not the caller's bad
		// credential. Reporting it as 401 would send a client into a
		// pointless re-authentication loop.
		return nil, fmt.Errorf("bearer: verify token: %w", err)
	}

	id, err := s.buildIdentity(claims)
	if err != nil {
		return nil, err
	}

	return id, nil
}

// Challenge implements strategy.Challenger.
func (s *Strategy) Challenge() string {
	return "Bearer"
}

// ChallengeRequest implements strategy.RequestChallenger, adding the RFC 9728
// resource_metadata pointer when a resource server is configured.
func (s *Strategy) ChallengeRequest(r *http.Request) string {
	if s.opts.Resource == nil {
		return "Bearer"
	}

	return s.opts.Resource.Challenge(r, resource.ChallengeParams{})
}

// SetProtectedResource implements strategy.ResourceBinder, letting the auth
// middleware hand the strategy the metadata server it publishes.
//
// An explicit Options.Resource wins: a caller that named one meant it.
func (s *Strategy) SetProtectedResource(rs *resource.Server) {
	if s.opts.Resource != nil || rs == nil {
		return
	}

	s.opts.Resource = rs
}

// Interface compliance.
var (
	_ strategy.Authenticator        = (*Strategy)(nil)
	_ strategy.RequestAuthenticator = (*Strategy)(nil)
	_ strategy.RequestChallenger    = (*Strategy)(nil)
	_ strategy.ResourceBinder       = (*Strategy)(nil)
)

// extractBearer pulls the token out of the Authorization header.
//
// Only the header form is read. RFC 6750 also defines a form-encoded body
// parameter and a `access_token` query parameter; the query form lands the
// credential in access logs, referrers and browser history, and RFC 6750 §5.3
// says not to use it.
func extractBearer(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}

	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return "", false
	}
	// Two Authorization headers is not a request anyone makes by accident,
	// and picking one of them is a choice a verifier should not be making.
	if len(values) != 1 {
		return "", true
	}

	scheme, rest, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}

	return strings.TrimSpace(rest), true
}

func (s *Strategy) writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	if s.opts.Resource != nil {
		w.Header().Set("WWW-Authenticate", s.opts.Resource.Challenge(r, resource.ChallengeParams{
			Error:       code,
			Description: message,
		}))
	} else {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_, _ = fmt.Fprintf(w, "{%q:%q,%q:%q}\n", "error", code, "message", message)
}

func insecureClient(base *http.Client) *http.Client {
	clone := *base

	transport, ok := base.Transport.(*http.Transport)
	if !ok || transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		transport = transport.Clone()
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{} //nolint:gosec // explicit opt-in below
	}
	transport.TLSClientConfig.InsecureSkipVerify = true
	clone.Transport = transport

	return &clone
}
