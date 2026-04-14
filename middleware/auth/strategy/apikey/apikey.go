// Package apikey implements a strategy.Authenticator that validates API keys
// from request headers. The strategy reads a token from the Authorization
// (Bearer) header or a configurable custom header, calls a user-supplied
// Validator, and returns the resulting Identity to the auth middleware.
package apikey

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

// ErrInvalidKey is returned by Validator when the API key is not recognized.
// It surfaces as 401 invalid_key to the client.
var ErrInvalidKey = errors.New("invalid_key")

// Validator is the user-supplied key lookup. Returning ErrInvalidKey produces
// a 401 response. Returning any other error produces a 500.
type Validator func(ctx context.Context, key string) (*identity.Identity, error)

// Strategy implements strategy.Authenticator for API-key-based authentication.
type Strategy struct {
	name        string
	label       string
	validate    Validator
	priority    int
	hidden      bool
	headerName  string
	bearerPrefix bool
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

// WithHeaderName overrides the header that is checked for the API key.
// The default behavior checks Authorization first, then X-API-Key. Setting a
// custom header name causes the strategy to read only that header.
func WithHeaderName(name string) Option {
	return func(s *Strategy) { s.headerName = name }
}

// WithBearerPrefix controls whether the strategy strips the "Bearer " prefix
// from the header value before passing the token to the Validator. Enabled by
// default. Pass false to read the raw header value as-is.
func WithBearerPrefix(strip bool) Option {
	return func(s *Strategy) { s.bearerPrefix = strip }
}

// New returns an API-key strategy with the given name and validator.
func New(name string, validate Validator, opts ...Option) *Strategy {
	s := &Strategy{
		name:         name,
		label:        name,
		validate:     validate,
		hidden:       true,
		bearerPrefix: true,
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
		Name:     s.name,
		Kind:     "apikey",
		Label:    s.label,
		LoginURL: "/auth/login/" + s.name,
		Priority: s.priority,
		Hidden:   s.hidden,
	}
}

// Login reads the API key from the request header, calls the Validator, and
// returns the resulting Identity.
func (s *Strategy) Login(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	if s.validate == nil {
		writeError(w, http.StatusInternalServerError, "no_validator", "no validator configured")

		return nil, strategy.OutcomeFailed, nil
	}

	key := s.extractKey(r)
	if key == "" {
		writeError(w, http.StatusUnauthorized, "missing_key", "API key not provided")

		return nil, strategy.OutcomeFailed, nil
	}

	id, err := s.validate(r.Context(), key)
	if err != nil {
		if errors.Is(err, ErrInvalidKey) {
			writeError(w, http.StatusUnauthorized, "invalid_key", "invalid API key")

			return nil, strategy.OutcomeFailed, nil
		}

		slog.Error("apikey validator error", "strategy", s.name, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "validate_failed", "validator error")

		return nil, strategy.OutcomeFailed, nil
	}

	if id == nil {
		writeError(w, http.StatusUnauthorized, "invalid_key", "invalid API key")

		return nil, strategy.OutcomeFailed, nil
	}

	id.Provider = s.name

	return id, strategy.OutcomeContinue, nil
}

// Logout is a no-op for the API key strategy; keys are stateless.
func (s *Strategy) Logout(_ context.Context, _ *identity.Identity) error { return nil }

// extractKey reads the API key from the configured header(s).
func (s *Strategy) extractKey(r *http.Request) string {
	// Custom header takes precedence when explicitly set.
	if s.headerName != "" {
		return s.stripPrefix(r.Header.Get(s.headerName))
	}

	// Default: try Authorization first, then X-API-Key.
	if v := r.Header.Get("Authorization"); v != "" {
		return s.stripPrefix(v)
	}

	return r.Header.Get("X-API-Key")
}

// stripPrefix removes the "Bearer " prefix when bearerPrefix is enabled.
func (s *Strategy) stripPrefix(v string) string {
	if !s.bearerPrefix {
		return v
	}

	if after, ok := strings.CutPrefix(v, "Bearer "); ok {
		return after
	}

	return v
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}
