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
	"log/slog"
	"net/http"
	"strings"

	"github.com/rakunlabs/ada/middleware/auth/guard"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/internal/bodylimit"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

// maxBodyBytes caps login and registration request bodies at 64 KiB.
const maxBodyBytes = 1 << 16

// ErrInvalidCredentials is returned by Verifier when username/password do not
// match. It surfaces as 401 invalid_credentials to the client.
var ErrInvalidCredentials = errors.New("invalid_credentials")

// ErrUserExists is returned by Registrar when the requested username is
// already taken. It surfaces as 409 user_exists to the client.
var ErrUserExists = errors.New("user_exists")

// ErrInvalidInput is returned by Registrar when input fails validation (weak
// password, malformed email, etc.). It surfaces as 400 invalid_input with the
// error's message as the user-facing detail.
var ErrInvalidInput = errors.New("invalid_input")

// ErrPasswordMismatch is returned when password and password_confirm do not
// match during signup. It surfaces as 400 password_mismatch. The check runs
// before the Registrar is invoked — Registrar never sees the mismatched
// request.
var ErrPasswordMismatch = errors.New("password_mismatch")

// confirmFieldName is the reserved register-field name used for the
// client-side confirmation check. When present in the request body, it is
// compared against the password field and stripped before the request reaches
// the Registrar.
const confirmFieldName = "password_confirm"

// Verifier is the user-supplied credential check. Returning ErrInvalidCredentials
// produces a 401 response. Returning any other error produces a 500.
type Verifier func(ctx context.Context, username, password string) (*identity.Identity, error)

// Registrar creates a new account. It receives the parsed fields from the
// signup request; Extras holds any register-only fields declared via
// WithRegisterFields. Returning ErrUserExists produces 409; ErrInvalidInput
// produces 400 (wrap with fmt.Errorf to attach a user-visible message); any
// other error produces 500. The returned Identity is used when AutoLogin is
// enabled.
type Registrar func(ctx context.Context, req RegisterRequest) (*identity.Identity, error)

// RegisterRequest is the payload passed to Registrar.
type RegisterRequest struct {
	Username string
	Password string
	// Extras carries any register-only fields declared via WithRegisterFields
	// beyond username and password. Keys are the Field.Name values.
	Extras map[string]string
}

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

	// register is set by WithRegistrar. Presence enables signup.
	register       Registrar
	registerFields []strategy.Field
	autoLogin      bool

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

// WithFields overrides the default username/password fields. Use this when
// the verifier expects different credential keys (e.g. email + token).
// The first field is treated as the username key, the second as the password
// key for parsing.
func WithFields(fields ...strategy.Field) Option {
	return func(s *Strategy) {
		s.fields = append([]strategy.Field(nil), fields...)
		if len(s.fields) >= 1 {
			s.usernameField = s.fields[0].Name
		}
		if len(s.fields) >= 2 {
			s.passwordField = s.fields[1].Name
		}
	}
}

// WithLimiter locks an account out after repeated failed logins.
//
// Nothing here counts failures without it: the Verifier is called once per
// request, forever. guard.New(guard.Config{}) gives five attempts and an
// escalating lockout.
func WithLimiter(l guard.Limiter) Option {
	return func(s *Strategy) { s.limiter = l }
}

// WithRegistrar enables signup for this strategy. The presence of a Registrar
// causes the descriptor's Register block to be populated so the login UI shows
// a signup option. The middleware routes POST .../login/register/{name} to
// this strategy's Register method.
func WithRegistrar(fn Registrar) Option {
	return func(s *Strategy) { s.register = fn }
}

// WithRegisterFields overrides the default signup form fields. Defaults to
// username, password, and password_confirm (the latter enforces a
// confirmation match server-side).
// Fields named the same as the login username/password fields are parsed as
// credentials; anything else is collected into RegisterRequest.Extras.
// The "password_confirm" field, if present in the request, is compared to
// the password field and a mismatch yields 400 password_mismatch; the value
// is never forwarded to the Registrar.
func WithRegisterFields(fields ...strategy.Field) Option {
	return func(s *Strategy) { s.registerFields = append([]strategy.Field(nil), fields...) }
}

// WithAutoLogin, when true, issues a session immediately after a successful
// signup and redirects the user into the app. Default false: the UI flips to
// the login form with an "account created" notice.
func WithAutoLogin(enabled bool) Option {
	return func(s *Strategy) { s.autoLogin = enabled }
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
	d := strategy.Descriptor{
		Name:  s.name,
		Kind:  "password",
		Label: s.label,
		// LoginURL is resolved by the auth middleware from cfg.Base; leave
		// it empty here so there is a single source of truth.
		Fields:   append([]strategy.Field(nil), s.fields...),
		Priority: s.priority,
		Hidden:   s.hidden,
	}

	if s.register != nil {
		d.Register = &strategy.RegisterInfo{
			// URL is resolved by the auth middleware from cfg.Base.
			Fields: append([]strategy.Field(nil), s.effectiveRegisterFields()...),
		}
	}

	return d
}

// effectiveRegisterFields returns the configured register fields, or a sane
// default (username, password, password_confirm) when none were supplied.
func (s *Strategy) effectiveRegisterFields() []strategy.Field {
	if len(s.registerFields) > 0 {
		return s.registerFields
	}

	return []strategy.Field{
		{Name: s.usernameField, Label: "Username", Type: "text", Required: true},
		{Name: s.passwordField, Label: "Password", Type: "password", Required: true},
		{Name: confirmFieldName, Label: "Confirm password", Type: "password", Required: true},
	}
}

// registerFieldNameSet returns the set of register field names (effective,
// including defaults). Used to decide whether a given payload key is a known
// register field or should be treated as an extra.
func (s *Strategy) registerFieldNameSet() map[string]struct{} {
	fields := s.effectiveRegisterFields()
	set := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		set[f.Name] = struct{}{}
	}
	return set
}

// requiresConfirm reports whether the current register fields include the
// reserved password_confirm field. Callers who override WithRegisterFields
// can drop this field to disable the match check (useful for machine
// clients); callers relying on the default form get the check.
func (s *Strategy) requiresConfirm() bool {
	for _, f := range s.effectiveRegisterFields() {
		if f.Name == confirmFieldName {
			return true
		}
	}
	return false
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

	username, password, err := s.readCredentials(w, r)
	if err != nil {
		writeBadRequest(w, err)

		return nil, strategy.OutcomeFailed, nil
	}

	key := s.guardKey(r, username)

	if s.limiter != nil {
		if d := s.limiter.Check(key); !d.Allowed {
			guard.WriteLocked(w, d)

			return nil, strategy.OutcomeFailed, nil
		}
	}

	id, err := s.verify(r.Context(), username, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			s.recordFailure(key)
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")

			return nil, strategy.OutcomeFailed, nil
		}

		// A verifier that blew up is not a wrong password. Counting it would
		// let a database outage lock out the whole user base.
		slog.Error("local verifier error", "strategy", s.name, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "verify_failed", "verifier error")

		return nil, strategy.OutcomeFailed, nil
	}

	if id == nil {
		s.recordFailure(key)
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")

		return nil, strategy.OutcomeFailed, nil
	}

	if s.limiter != nil {
		s.limiter.Succeed(key)
	}

	id.Provider = s.name

	return id, strategy.OutcomeContinue, nil
}

func (s *Strategy) recordFailure(key string) {
	if s.limiter != nil {
		s.limiter.Fail(key)
	}
}

// guardKey identifies the attempt for rate-limiting purposes.
//
// Keyed on the username, not the client address. An attacker spraying one
// password across many accounts from one IP is the case an IP key catches; an
// attacker grinding one account from a botnet is the case it misses, and that
// is the one that actually takes over accounts. Deployments that want both can
// wrap the Limiter.
func (s *Strategy) guardKey(_ *http.Request, username string) string {
	return s.name + ":" + strings.ToLower(username)
}

// Logout is a no-op for the local strategy; the issuer revokes the session.
func (s *Strategy) Logout(_ context.Context, _ *identity.Identity) error { return nil }

// Register handles self-service signup. It parses the request body, calls the
// configured Registrar, and either returns the new Identity for auto-login or
// writes a "created, please sign in" response directly. If WithRegistrar was
// not called, Register returns OutcomeFailed with 404.
func (s *Strategy) Register(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")

		return nil, strategy.OutcomeFailed, nil
	}

	if s.register == nil {
		writeError(w, http.StatusNotFound, "signup_disabled", "signup is not enabled for this strategy")

		return nil, strategy.OutcomeFailed, nil
	}

	req, err := s.readRegister(w, r)
	if err != nil {
		switch {
		case errors.Is(err, ErrPasswordMismatch):
			writeError(w, http.StatusBadRequest, "password_mismatch", "passwords do not match")
		default:
			writeBadRequest(w, err)
		}

		return nil, strategy.OutcomeFailed, nil
	}

	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "username and password are required")

		return nil, strategy.OutcomeFailed, nil
	}

	id, err := s.register(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, ErrUserExists):
			writeError(w, http.StatusConflict, "user_exists", "username already taken")
		case errors.Is(err, ErrInvalidInput):
			writeError(w, http.StatusBadRequest, "invalid_input", err.Error())
		default:
			slog.Error("local registrar error", "strategy", s.name, "error", err.Error())
			writeError(w, http.StatusInternalServerError, "register_failed", "registrar error")
		}

		return nil, strategy.OutcomeFailed, nil
	}

	if s.autoLogin {
		if id == nil {
			writeError(w, http.StatusInternalServerError, "no_identity", "registrar returned no identity for auto-login")

			return nil, strategy.OutcomeFailed, nil
		}

		id.Provider = s.name

		return id, strategy.OutcomeContinue, nil
	}

	// Auto-login disabled: tell the UI to flip to the login form.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"strategy":   s.name,
		"registered": true,
		"auto_login": false,
	})

	return nil, strategy.OutcomePending, nil
}

// readRegister parses the signup body and enforces the password_confirm
// match when the strategy's register fields declare that field.
//
// Returns a populated RegisterRequest with username, password, and any
// additional register-only fields collected into Extras. The
// "password_confirm" field is never forwarded to the Registrar; when declared
// in the register fields, a missing or mismatched value yields
// ErrPasswordMismatch.
func (s *Strategy) readRegister(w http.ResponseWriter, r *http.Request) (RegisterRequest, error) {
	contentType := r.Header.Get("Content-Type")

	body, err := bodylimit.Read(w, r, maxBodyBytes)
	if err != nil {
		return RegisterRequest{}, fmt.Errorf("read body: %w", err)
	}

	var raw map[string]string

	switch {
	case strings.HasPrefix(contentType, "application/json"):
		if err := json.Unmarshal(body, &raw); err != nil {
			return RegisterRequest{}, fmt.Errorf("decode json: %w", err)
		}
	case strings.HasPrefix(contentType, "application/x-www-form-urlencoded"):
		raw, err = parseForm(string(body))
		if err != nil {
			return RegisterRequest{}, fmt.Errorf("parse form: %w", err)
		}
	default:
		return RegisterRequest{}, fmt.Errorf("unsupported content type %q", contentType)
	}

	// Enforce password confirmation when the register form declares it.
	// This is a defense-in-depth check: the UI should also validate, but
	// relying on the UI alone would let a typo through to the Registrar
	// and leave the user with an account they can't log into. Unknown
	// password means the user can't use their new account at all, so
	// silently accepting a mismatch is strictly worse than rejecting it.
	if s.requiresConfirm() {
		pw := raw[s.passwordField]
		confirm, hasConfirm := raw[confirmFieldName]
		if !hasConfirm || pw != confirm {
			return RegisterRequest{}, ErrPasswordMismatch
		}
	}

	req := RegisterRequest{
		Username: raw[s.usernameField],
		Password: raw[s.passwordField],
	}

	// Extras carries any register-only fields declared via WithRegisterFields
	// beyond username/password/password_confirm. Unknown keys (not declared
	// as register fields) are dropped rather than blindly forwarded, to
	// avoid smuggling arbitrary data into the Registrar.
	known := s.registerFieldNameSet()
	extras := make(map[string]string)
	for k, v := range raw {
		if k == s.usernameField || k == s.passwordField || k == confirmFieldName {
			continue
		}
		if _, declared := known[k]; !declared {
			continue
		}
		extras[k] = v
	}
	if len(extras) > 0 {
		req.Extras = extras
	}

	return req, nil
}

func (s *Strategy) readCredentials(w http.ResponseWriter, r *http.Request) (string, string, error) {
	contentType := r.Header.Get("Content-Type")

	body, err := bodylimit.Read(w, r, maxBodyBytes)
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

func writeBadRequest(w http.ResponseWriter, err error) {
	if status, message, tooLarge := bodylimit.Reject(err); tooLarge {
		writeError(w, status, bodylimit.Code, message)

		return
	}

	writeError(w, http.StatusBadRequest, "bad_request", err.Error())
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}
