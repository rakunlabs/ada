// Package header implements a strategy.Authenticator that trusts identity
// information from headers set by an upstream reverse proxy (Traefik, nginx,
// etc.). The strategy reads configurable request headers, maps them to
// Identity fields, and returns the resulting Identity to the auth middleware.
package header

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
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

// New returns a header-auth strategy with the given name.
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
