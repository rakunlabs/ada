// Package basic implements a strategy.Authenticator that validates credentials
// via the HTTP Basic Authentication scheme (RFC 7617). The strategy reads the
// Authorization header, decodes the base64 username:password pair, calls a
// user-supplied Verifier, and returns the resulting Identity to the auth
// middleware. On missing or invalid credentials the strategy responds with a
// WWW-Authenticate header so browsers show the native credential dialog.
package basic

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/rakunlabs/ada/middleware/auth/guard"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

// ErrInvalidCredentials is returned by Verifier when username/password do not
// match. It surfaces as 401 with a WWW-Authenticate challenge to the client.
var ErrInvalidCredentials = errors.New("invalid_credentials")

// Verifier is the user-supplied credential check. Returning ErrInvalidCredentials
// produces a 401 response with a WWW-Authenticate challenge. Returning any
// other error produces a 500.
type Verifier func(ctx context.Context, username, password string) (*identity.Identity, error)

// Strategy implements strategy.Authenticator for HTTP Basic authentication.
type Strategy struct {
	name     string
	label    string
	verify   Verifier
	priority int
	hidden   bool
	realm    string

	limiter guard.Limiter
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

// WithRealm sets the protection space advertised in the WWW-Authenticate
// challenge header. Defaults to "Restricted".
func WithRealm(realm string) Option {
	return func(s *Strategy) { s.realm = realm }
}

// WithLimiter locks an account out after repeated failed attempts.
//
// Basic auth is the strategy that most needs one: the client re-sends the
// credentials on every request, so a guessing loop is a plain HTTP loop with
// no login page, no cookie and no state to manage.
func WithLimiter(l guard.Limiter) Option {
	return func(s *Strategy) { s.limiter = l }
}

// New returns an HTTP Basic Auth strategy with the given name and verifier.
func New(name string, verify Verifier, opts ...Option) *Strategy {
	s := &Strategy{
		name:   name,
		label:  name,
		verify: verify,
		hidden: true,
		realm:  "Restricted",
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Name returns the strategy's URL key.
func (s *Strategy) Name() string { return s.name }

// Descriptor returns the UI-facing description of this strategy.
func (s *Strategy) Descriptor() strategy.Descriptor {
	return strategy.Descriptor{
		Name:  s.name,
		Kind:  "basic",
		Label: s.label,
		// LoginURL is resolved by the auth middleware from cfg.Base.
		Priority: s.priority,
		Hidden:   s.hidden,
	}
}

// Login reads HTTP Basic credentials from the request, calls the Verifier, and
// returns the resulting Identity. If no Authorization header is present or the
// credentials are invalid, it responds with 401 and a WWW-Authenticate header
// to trigger the browser's native login dialog.
func (s *Strategy) Login(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	if s.verify == nil {
		writeError(w, http.StatusInternalServerError, "no_verifier", "no verifier configured")

		return nil, strategy.OutcomeFailed, nil
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		s.writeChallenge(w, http.StatusUnauthorized, "missing_credentials", "HTTP Basic credentials required")

		return nil, strategy.OutcomeFailed, nil
	}

	key := s.guardKey(username)

	if s.limiter != nil {
		if d := s.limiter.Check(key); !d.Allowed {
			guard.WriteLocked(w, d)

			return nil, strategy.OutcomeFailed, nil
		}
	}

	id, err := s.verify(r.Context(), username, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			s.fail(key)
			s.writeChallenge(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")

			return nil, strategy.OutcomeFailed, nil
		}

		// A broken verifier is not a wrong password; counting it would turn an
		// outage into a fleet-wide lockout.
		slog.Error("basic verifier error", "strategy", s.name, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "verify_failed", "verifier error")

		return nil, strategy.OutcomeFailed, nil
	}

	if id == nil {
		s.fail(key)
		s.writeChallenge(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")

		return nil, strategy.OutcomeFailed, nil
	}

	s.succeed(key)

	id.Provider = s.name

	return id, strategy.OutcomeContinue, nil
}

func (s *Strategy) guardKey(username string) string {
	return s.name + ":" + strings.ToLower(username)
}

func (s *Strategy) fail(key string) {
	if s.limiter != nil {
		s.limiter.Fail(key)
	}
}

func (s *Strategy) succeed(key string) {
	if s.limiter != nil {
		s.limiter.Succeed(key)
	}
}

// Logout is a no-op for the basic strategy; sessions are stateless.
func (s *Strategy) Logout(_ context.Context, _ *identity.Identity) error { return nil }

// AuthenticateRequest implements strategy.RequestAuthenticator so Basic
// credentials authorize a protected route directly.
//
// This is what RFC 7617 already describes: the client re-sends the
// Authorization header on every request. Requiring a login round-trip to
// convert it into a cookie first would be a protocol this library invented,
// not one any Basic-auth client implements.
//
// Note the WWW-Authenticate challenge is written by Require, not here —
// AuthenticateRequest must not touch the response — so the realm
// configured via WithRealm is not advertised on this path.
func (s *Strategy) AuthenticateRequest(ctx context.Context, r *http.Request) (*identity.Identity, error) {
	if s.verify == nil {
		return nil, strategy.ErrNoCredentials
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, strategy.ErrNoCredentials
	}

	key := s.guardKey(username)

	if s.limiter != nil {
		if d := s.limiter.Check(key); !d.Allowed {
			// Reported as invalid credentials because AuthenticateRequest
			// cannot write a 429 — it must not touch the response. Require
			// turns this into a 401, which is the right answer for a caller
			// that is, right now, not authorized.
			return nil, strategy.ErrInvalidCredentials
		}
	}

	id, err := s.verify(ctx, username, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			s.fail(key)

			return nil, strategy.ErrInvalidCredentials
		}

		slog.Error("basic verifier error", "strategy", s.name, "error", err.Error())

		return nil, err
	}

	if id == nil {
		s.fail(key)

		return nil, strategy.ErrInvalidCredentials
	}

	s.succeed(key)

	id.Provider = s.name

	return id, nil
}

// Challenge implements strategy.Challenger, carrying the configured realm
// so a browser shows its native credential dialog for the right
// protection space.
func (s *Strategy) Challenge() string {
	return `Basic realm="` + s.realm + `"`
}

// Interface compliance.
var (
	_ strategy.RequestAuthenticator = (*Strategy)(nil)
	_ strategy.Challenger           = (*Strategy)(nil)
)

// writeChallenge writes a JSON error response with the WWW-Authenticate header
// set so the browser shows the native credential dialog.
func (s *Strategy) writeChallenge(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+s.realm+`"`)
	writeError(w, status, code, message)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}
