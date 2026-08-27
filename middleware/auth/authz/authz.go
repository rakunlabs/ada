// Package authz turns an authenticated identity into an allow/deny decision.
//
// middleware/auth answers "who is this?". It deliberately does not answer "may
// they do this?" — Require() is binary, and Identity.Roles/Scopes travel
// through the session without anything ever reading them. This package is the
// missing half: role and scope guards for a handler, and a rule table for
// deployments that want the policy in configuration rather than in code.
//
// It is not an entitlement service. There is no role hierarchy, no resource
// ownership, no delegation — those belong in the application, which is the
// only thing that knows what a resource is.
package authz

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

// Requirement decides whether an identity may proceed.
//
// A nil identity means the request is unauthenticated; a Requirement that
// wants to allow anonymous access must handle that case itself.
type Requirement interface {
	Allow(id *identity.Identity) bool

	// Describe returns a short human-readable form used in error responses
	// and logs, e.g. `role "admin"`.
	Describe() string
}

// RequirementFunc adapts a function to Requirement.
type RequirementFunc struct {
	Fn   func(*identity.Identity) bool
	Text string
}

// Allow implements Requirement.
func (f RequirementFunc) Allow(id *identity.Identity) bool { return f.Fn(id) }

// Describe implements Requirement.
func (f RequirementFunc) Describe() string { return f.Text }

// Role requires every listed role.
type Role []string

// Allow implements Requirement.
func (r Role) Allow(id *identity.Identity) bool { return id.HasAllRoles(r...) }

// Describe implements Requirement.
func (r Role) Describe() string { return "roles " + quoteList(r) }

// AnyRole requires at least one of the listed roles.
type AnyRole []string

// Allow implements Requirement.
func (r AnyRole) Allow(id *identity.Identity) bool { return id.HasAnyRole(r...) }

// Describe implements Requirement.
func (r AnyRole) Describe() string { return "any of roles " + quoteList(r) }

// Scope requires every listed scope.
type Scope []string

// Allow implements Requirement.
func (s Scope) Allow(id *identity.Identity) bool { return id.HasAllScopes(s...) }

// Describe implements Requirement.
func (s Scope) Describe() string { return "scopes " + quoteList(s) }

// AnyScope requires at least one of the listed scopes.
type AnyScope []string

// Allow implements Requirement.
func (s AnyScope) Allow(id *identity.Identity) bool { return id.HasAnyScope(s...) }

// Describe implements Requirement.
func (s AnyScope) Describe() string { return "any of scopes " + quoteList(s) }

// Any passes when at least one of the wrapped requirements passes.
type Any []Requirement

// Allow implements Requirement.
func (a Any) Allow(id *identity.Identity) bool {
	for _, r := range a {
		if r.Allow(id) {
			return true
		}
	}

	return false
}

// Describe implements Requirement.
func (a Any) Describe() string {
	parts := make([]string, 0, len(a))
	for _, r := range a {
		parts = append(parts, r.Describe())
	}

	return "(" + strings.Join(parts, " or ") + ")"
}

// All passes only when every wrapped requirement passes. An empty All passes.
type All []Requirement

// Allow implements Requirement.
func (a All) Allow(id *identity.Identity) bool {
	for _, r := range a {
		if !r.Allow(id) {
			return false
		}
	}

	return true
}

// Describe implements Requirement.
func (a All) Describe() string {
	parts := make([]string, 0, len(a))
	for _, r := range a {
		parts = append(parts, r.Describe())
	}

	return "(" + strings.Join(parts, " and ") + ")"
}

// Authenticated passes for any non-nil identity.
var Authenticated Requirement = RequirementFunc{
	Fn:   func(id *identity.Identity) bool { return id != nil },
	Text: "an authenticated user",
}

// Public passes for everyone, including anonymous callers.
var Public Requirement = RequirementFunc{
	Fn:   func(*identity.Identity) bool { return true },
	Text: "nothing",
}

// Require returns a middleware enforcing req.
//
// It reads the identity from the request context, so it must run after
// Auth.Require (or anything else that calls identity.WithContext). Placed
// before, it sees no identity and denies everything — noisy, but not
// dangerous, which is the right way round.
func Require(req Requirement, opts ...Option) func(http.Handler) http.Handler {
	cfg := newConfig(opts)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := identity.FromContext(r.Context())

			if req.Allow(id) {
				next.ServeHTTP(w, r)

				return
			}

			cfg.deny(w, r, id, req.Describe())
		})
	}
}

// RequireRole is shorthand for Require(Role{...}).
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return Require(Role(roles))
}

// RequireAnyRole is shorthand for Require(AnyRole{...}).
func RequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return Require(AnyRole(roles))
}

// RequireScope is shorthand for Require(Scope{...}).
func RequireScope(scopes ...string) func(http.Handler) http.Handler {
	return Require(Scope(scopes))
}

// RequireAnyScope is shorthand for Require(AnyScope{...}).
func RequireAnyScope(scopes ...string) func(http.Handler) http.Handler {
	return Require(AnyScope(scopes))
}

// Option configures the middleware produced by Require and Rules.Middleware.
type Option func(*config)

type config struct {
	onDeny http.HandlerFunc
	logger *slog.Logger
}

func newConfig(opts []Option) *config {
	c := &config{}
	for _, o := range opts {
		o(c)
	}

	return c
}

// WithDenyHandler replaces the default 403 JSON response.
func WithDenyHandler(h http.HandlerFunc) Option {
	return func(c *config) { c.onDeny = h }
}

// WithLogger logs each denial at info level. Off by default: a denial is a
// normal outcome, and logging every one turns a permission-heavy API into a
// log firehose.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) { c.logger = l }
}

func (c *config) deny(w http.ResponseWriter, r *http.Request, id *identity.Identity, requirement string) {
	if c.logger != nil {
		subject := "anonymous"
		if id != nil {
			subject = id.Subject
		}

		c.logger.Info("authz: denied",
			"subject", subject,
			"method", r.Method,
			"path", r.URL.Path,
			"requires", requirement,
		)
	}

	if c.onDeny != nil {
		c.onDeny(w, r)

		return
	}

	// 401 when nobody is logged in, 403 when somebody is: RFC 9110 §15.5.4
	// draws the line at "did you authenticate", not "were you allowed".
	// Returning 403 to an anonymous caller tells them to give up when they
	// have not yet tried.
	status := http.StatusForbidden
	code := "forbidden"

	if id == nil {
		status = http.StatusUnauthorized
		code = "unauthorized"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	// The requirement is not echoed: telling an unauthorized caller exactly
	// which role would have worked is free reconnaissance.
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": "insufficient permissions",
	})
}

func quoteList(v []string) string {
	if len(v) == 0 {
		return "(none)"
	}

	parts := make([]string, 0, len(v))
	for _, s := range v {
		parts = append(parts, `"`+s+`"`)
	}

	return strings.Join(parts, ", ")
}
