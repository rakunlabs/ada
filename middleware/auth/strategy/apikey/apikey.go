// Package apikey implements a strategy.Authenticator that validates API keys
// from request headers. The strategy reads a token from one of a configured
// list of headers, calls a user-supplied Validator, and returns the resulting
// Identity to the auth middleware.
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

// DefaultHeaders is the header lookup order used when the caller does not
// configure its own. Authorization is checked first (Bearer-prefix-stripped
// when enabled), then X-API-Key as a fallback.
var DefaultHeaders = []string{"Authorization", "X-API-Key"}

// Strategy implements strategy.Authenticator for API-key-based authentication.
type Strategy struct {
	name         string
	label        string
	validate     Validator
	priority     int
	hidden       bool
	headers      []string
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

// WithHeaders sets the exact list of headers the strategy reads, in priority
// order. The first non-empty header wins. Calling this REPLACES the default
// Authorization / X-API-Key fallback — callers that want strict single-header
// behavior should use this. An empty list restores the default.
//
// Example: WithHeaders("Authorization") to accept only `Authorization: Bearer <key>`,
// rejecting X-API-Key.
func WithHeaders(headers ...string) Option {
	return func(s *Strategy) {
		if len(headers) == 0 {
			s.headers = nil // restore default on next use
			return
		}
		s.headers = append([]string(nil), headers...)
	}
}

// WithAdditionalHeader appends a header to the lookup list, preserving the
// defaults. Useful when you want "Authorization, X-API-Key, AND my custom
// header" without having to restate the defaults.
func WithAdditionalHeader(name string) Option {
	return func(s *Strategy) {
		if name == "" {
			return
		}
		if len(s.headers) == 0 {
			// Clone defaults so WithHeaders callers aren't surprised by
			// shared-slice mutation.
			s.headers = append([]string(nil), DefaultHeaders...)
		}
		s.headers = append(s.headers, name)
	}
}

// WithHeaderName overrides the header that is checked for the API key.
// Equivalent to WithHeaders(name) — kept for backward compatibility. Setting
// a single header disables the default Authorization / X-API-Key fallback.
//
// Deprecated: prefer WithHeaders (single or multiple headers) for clarity.
func WithHeaderName(name string) Option {
	return WithHeaders(name)
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
		Name:  s.name,
		Kind:  "apikey",
		Label: s.label,
		// LoginURL is resolved by the auth middleware from cfg.Base.
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

// effectiveHeaders returns the header lookup order, applying the default
// when nothing was configured.
func (s *Strategy) effectiveHeaders() []string {
	if len(s.headers) == 0 {
		return DefaultHeaders
	}
	return s.headers
}

// extractKey reads the API key from the configured headers in order. The
// first non-empty header wins; its value is returned with the Bearer prefix
// stripped when bearerPrefix is enabled.
func (s *Strategy) extractKey(r *http.Request) string {
	for _, h := range s.effectiveHeaders() {
		if v := r.Header.Get(h); v != "" {
			return s.stripPrefix(v)
		}
	}
	return ""
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
