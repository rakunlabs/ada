// Package header implements a strategy.Authenticator that trusts identity
// information from headers set by an upstream reverse proxy (Traefik, nginx,
// etc.). The strategy reads configurable request headers, maps them to
// Identity fields, and returns the resulting Identity to the auth middleware.
//
// This strategy deliberately does NOT implement
// strategy.RequestAuthenticator, so it does not authenticate protected
// routes straight from the incoming headers.
//
// It has no verifier: whoever can set X-Forwarded-User is whoever the
// request claims to be. That is sound only while every path to the
// application passes through the proxy that overwrites those headers.
// Confining the trust to the login endpoint keeps the blast radius of a
// misrouted deployment to one route instead of every route. Deployments
// that genuinely terminate all traffic at the proxy should log in through
// {base}/login/{name} and carry the resulting session, or put an apikey /
// basic strategy — both of which verify something — in front of their
// machine clients.
package header

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
	"github.com/rakunlabs/ada/utils/proxy"
)

// ErrNoUserHeader is returned when the configured user header is missing or
// empty on the incoming request. It surfaces as 401 no_user_header to the
// client.
var ErrNoUserHeader = errors.New("no_user_header")

// HeaderMap defines which request headers map to which Identity fields.
// All values are header names. Zero values fall back to the defaults listed
// below.
type HeaderMap struct {
	User   string // header for Subject, default "X-Forwarded-User"
	Email  string // header for Email, default "X-Forwarded-Email"
	Name   string // header for Name, default "X-Forwarded-Name"
	Roles  string // header for Roles (comma-separated), default "X-Forwarded-Roles"
	Groups string // header for Groups (comma-separated), default "X-Forwarded-Groups"
}

// defaults fills zero-value fields with their default header names.
func (m HeaderMap) defaults() HeaderMap {
	if m.User == "" {
		m.User = "X-Forwarded-User"
	}

	if m.Email == "" {
		m.Email = "X-Forwarded-Email"
	}

	if m.Name == "" {
		m.Name = "X-Forwarded-Name"
	}

	if m.Roles == "" {
		m.Roles = "X-Forwarded-Roles"
	}

	if m.Groups == "" {
		m.Groups = "X-Forwarded-Groups"
	}

	return m
}

// Strategy implements strategy.Authenticator for reverse-proxy header-based
// authentication.
type Strategy struct {
	name      string
	label     string
	priority  int
	hidden    bool
	headerMap HeaderMap

	trustedProxies *proxy.Policy
	secretHeader   string
	secretValue    string
	unsafeTrustAll bool
}

// Option configures a Strategy.
type Option func(*Strategy)

// WithLabel sets the human-readable label shown in the login UI.
func WithLabel(label string) Option {
	return func(s *Strategy) { s.label = label }
}

// WithPriority sets the sort order in /auth/info (lower = earlier).
func WithPriority(p int) Option {
	return func(s *Strategy) { s.priority = p }
}

// WithHidden hides the strategy from /auth/info while keeping it routable.
func WithHidden() Option {
	return func(s *Strategy) { s.hidden = true }
}

// WithHeaderMap overrides the default header-to-field mapping.
func WithHeaderMap(m HeaderMap) Option {
	return func(s *Strategy) { s.headerMap = m.defaults() }
}

// WithTrustedProxies restricts the strategy to requests whose immediate peer
// falls inside one of the given CIDRs (bare IPs are accepted too).
//
// This is the trust boundary the strategy has been missing. The identity
// headers carry no proof of anything; the only thing standing between them and
// an arbitrary impersonation is the claim that nothing but the proxy can
// reach this port. Stating that claim explicitly turns it from an assumption
// into a check.
//
// The peer address is r.RemoteAddr, never X-Forwarded-For — an attacker sets
// that as easily as the header it is supposed to guard.
func WithTrustedProxies(cidrs ...string) Option {
	policy, err := proxy.New(cidrs...)
	if err != nil {
		panic(fmt.Errorf("header: trusted proxies: %w", err))
	}

	return func(s *Strategy) {
		s.trustedProxies = &policy
	}
}

// WithSharedSecret requires the given header to carry the given value.
//
// Use it when the proxy and the application cannot be separated at the network
// layer — a shared cluster, a service mesh without mTLS. Compared in constant
// time. It is a weaker control than WithTrustedProxies and composes with it.
func WithSharedSecret(headerName, value string) Option {
	return func(s *Strategy) {
		if !validHeaderName(headerName) {
			panic(fmt.Errorf("header: shared secret header name %q is invalid", headerName))
		}
		if !validHeaderValue(value) || strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			panic(fmt.Errorf("header: shared secret value must be a non-empty HTTP header value"))
		}

		s.secretHeader = http.CanonicalHeaderKey(headerName)
		s.secretValue = value
	}
}

// WithUnsafeTrustAll permits every caller to supply identity headers. It
// restores the legacy behavior for deployments with a separately enforced
// network boundary, but cannot verify that such a boundary exists.
//
// Prefer WithTrustedProxies, WithSharedSecret, or both.
func WithUnsafeTrustAll() Option {
	return func(s *Strategy) { s.unsafeTrustAll = true }
}

// New returns a header-auth strategy with the given name.
//
// With neither WithTrustedProxies nor WithSharedSecret, the strategy fails
// closed. Deployments whose trust boundary is enforced entirely outside the
// process must opt into the legacy behavior with WithUnsafeTrustAll.
func New(name string, opts ...Option) *Strategy {
	s := &Strategy{
		name:      name,
		label:     name,
		hidden:    true,
		headerMap: HeaderMap{}.defaults(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// trusted reports whether the request may speak for someone else.
func (s *Strategy) trusted(r *http.Request) bool {
	if s.secretValue != "" {
		got := r.Header.Get(s.secretHeader)
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.secretValue)) != 1 {
			return false
		}
	}

	if s.trustedProxies == nil {
		return s.secretValue != "" || s.unsafeTrustAll
	}

	return s.trustedProxies.TrustedPeer(r)
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}

	for i := range len(name) {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}

	return true
}

func validHeaderValue(value string) bool {
	for i := range len(value) {
		c := value[i]
		if c == '\r' || c == '\n' || c == 0x7f || (c < 0x20 && c != '\t') {
			return false
		}
	}

	return true
}

// Name returns the strategy's URL key.
func (s *Strategy) Name() string { return s.name }

// Descriptor returns the UI-facing description of this strategy. Kind is
// "header" and Hidden defaults to true because proxy auth has no login form.
func (s *Strategy) Descriptor() strategy.Descriptor {
	return strategy.Descriptor{
		Name:  s.name,
		Kind:  "header",
		Label: s.label,
		// LoginURL is resolved by the auth middleware from cfg.Base.
		Priority: s.priority,
		Hidden:   s.hidden,
	}
}

// Login reads identity headers from the request. If the user header is
// missing or empty the strategy writes a 401 JSON error and returns
// OutcomeFailed.
func (s *Strategy) Login(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	if !s.trusted(r) {
		// Same response as a missing header. A caller outside the trust
		// boundary learns nothing about why it failed, and in particular not
		// that a shared-secret header exists.
		writeError(w, http.StatusUnauthorized, "no_user_header", "missing required header: "+s.headerMap.User)

		return nil, strategy.OutcomeFailed, nil
	}

	user := strings.TrimSpace(r.Header.Get(s.headerMap.User))
	if user == "" {
		writeError(w, http.StatusUnauthorized, "no_user_header", "missing required header: "+s.headerMap.User)

		return nil, strategy.OutcomeFailed, nil
	}

	id := &identity.Identity{
		Subject:  user,
		Email:    strings.TrimSpace(r.Header.Get(s.headerMap.Email)),
		Name:     strings.TrimSpace(r.Header.Get(s.headerMap.Name)),
		Provider: s.name,
		IssuedAt: time.Now(),
	}

	if raw := strings.TrimSpace(r.Header.Get(s.headerMap.Roles)); raw != "" {
		id.Roles = splitCSV(raw)
	}

	if raw := strings.TrimSpace(r.Header.Get(s.headerMap.Groups)); raw != "" {
		id.Claims = map[string]any{
			"groups": splitCSV(raw),
		}
	}

	return id, strategy.OutcomeContinue, nil
}

// Logout is a no-op for the header strategy; proxy auth is stateless.
func (s *Strategy) Logout(_ context.Context, _ *identity.Identity) error { return nil }

// splitCSV splits a comma-separated string into trimmed, non-empty values.
func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))

	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}

	return out
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}
