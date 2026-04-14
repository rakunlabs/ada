// Package local implements a strategy.Authenticator backed by a user-supplied
// credential verifier. The strategy parses {username, password} from the
// request body (JSON or form-encoded), calls Verifier, and returns the
// resulting Identity to the auth middleware.
package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

// ErrInvalidCredentials is returned by Verifier when username/password do not
// match. It surfaces as 401 invalid_credentials to the client.
var ErrInvalidCredentials = errors.New("invalid_credentials")

// Verifier is the user-supplied credential check. Returning ErrInvalidCredentials
// produces a 401 response. Returning any other error produces a 500.
type Verifier func(ctx context.Context, username, password string) (*identity.Identity, error)

// Strategy implements strategy.Authenticator for app-managed credentials.
type Strategy struct {
	name     string
	label    string
	verify   Verifier
	priority int
	hidden   bool
	fields   []strategy.Field

	// usernameField/passwordField are the JSON/form keys the strategy reads.
	usernameField string
	passwordField string
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

// WithFields overrides the default username/password fields. Use this when
// the verifier expects different credential keys (e.g. email + token).
// The first field is treated as the username key, the second as the password
// key for parsing.
func WithFields(fields ...strategy.Field) Option {
	return func(s *Strategy) {
		s.fields = fields
		if len(fields) >= 1 {
			s.usernameField = fields[0].Name
		}
		if len(fields) >= 2 {
			s.passwordField = fields[1].Name
		}
	}
}

// New returns a local-credential strategy with the given name and verifier.
func New(name string, verify Verifier, opts ...Option) *Strategy {
	s := &Strategy{
		name:          name,
		label:         name,
		verify:        verify,
		usernameField: "username",
		passwordField: "password",
		fields: []strategy.Field{
			{Name: "username", Label: "Username", Type: "text", Required: true},
			{Name: "password", Label: "Password", Type: "password", Required: true},
		},
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
		Kind:     "password",
		Label:    s.label,
		LoginURL: "/auth/login/" + s.name,
		Fields:   s.fields,
		Priority: s.priority,
		Hidden:   s.hidden,
	}
}

// Login parses credentials from the request body, calls the verifier, and
// returns the resulting Identity.
func (s *Strategy) Login(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")

		return nil, strategy.OutcomeFailed, nil
	}

	if s.verify == nil {
		writeError(w, http.StatusInternalServerError, "no_verifier", "no verifier configured")

		return nil, strategy.OutcomeFailed, nil
	}

	username, password, err := s.readCredentials(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())

		return nil, strategy.OutcomeFailed, nil
	}

	id, err := s.verify(r.Context(), username, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")

			return nil, strategy.OutcomeFailed, nil
		}

		slog.Error("local verifier error", "strategy", s.name, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "verify_failed", "verifier error")

		return nil, strategy.OutcomeFailed, nil
	}

	if id == nil {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")

		return nil, strategy.OutcomeFailed, nil
	}

	id.Provider = s.name

	return id, strategy.OutcomeContinue, nil
}

// Logout is a no-op for the local strategy; the issuer revokes the session.
func (s *Strategy) Logout(_ context.Context, _ *identity.Identity) error { return nil }

func (s *Strategy) readCredentials(r *http.Request) (string, string, error) {
	contentType := r.Header.Get("Content-Type")

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		return "", "", fmt.Errorf("read body: %w", err)
	}

	switch {
	case strings.HasPrefix(contentType, "application/json"):
		var m map[string]string
		if err := json.Unmarshal(body, &m); err != nil {
			return "", "", fmt.Errorf("decode json: %w", err)
		}

		return m[s.usernameField], m[s.passwordField], nil

	case strings.HasPrefix(contentType, "application/x-www-form-urlencoded"):
		// r.Body is already drained — parse the buffered body directly.
		values, err := parseForm(string(body))
		if err != nil {
			return "", "", fmt.Errorf("parse form: %w", err)
		}

		return values[s.usernameField], values[s.passwordField], nil
	}

	return "", "", fmt.Errorf("unsupported content type %q", contentType)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}
