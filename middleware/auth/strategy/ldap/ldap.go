// Package ldap implements a strategy.Authenticator that authenticates users
// against an LDAP directory (Active Directory, OpenLDAP, etc.). The actual
// LDAP wire protocol is abstracted behind the Connector/Conn interfaces so
// callers can plug in any LDAP library (e.g. go-ldap) without this package
// importing one.
package ldap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

// ---------------------------------------------------------------------------
// LDAP abstraction — users supply an implementation backed by any LDAP library.
// ---------------------------------------------------------------------------

// Connector creates new LDAP connections. Implementations should handle TLS
// negotiation, timeouts, and connection pooling as they see fit.
type Connector interface {
	Connect(ctx context.Context) (Conn, error)
}

// Conn is a single LDAP connection. Implementations wrap their library's
// connection type and translate results into Entry values.
type Conn interface {
	Bind(dn, password string) error
	Search(baseDN, filter string, attributes []string) ([]Entry, error)
	Close() error
}

// Entry is a single LDAP search result.
type Entry struct {
	DN         string
	Attributes map[string][]string
}

// ---------------------------------------------------------------------------
// Configuration types
// ---------------------------------------------------------------------------

// Config holds the LDAP connection and search parameters.
type Config struct {
	// Address is the LDAP server URL (e.g. "ldap://ad.example.com:389").
	Address string
	// BaseDN is the search base (e.g. "dc=example,dc=com").
	BaseDN string
	// BindDN is the service-account DN used for the initial bind + search.
	BindDN string
	// BindPassword is the service-account password.
	BindPassword string
	// UserFilter is an LDAP search filter with a single %s placeholder for the
	// username. Defaults to "(uid=%s)".
	UserFilter string
}

// AttributeMap maps LDAP attribute names to Identity fields. Each value is
// the LDAP attribute to read (e.g. Subject: "uid", Email: "mail").
type AttributeMap struct {
	// Subject maps to Identity.Subject (required).
	Subject string
	// Email maps to Identity.Email.
	Email string
	// Name maps to Identity.Name.
	Name string
	// Roles maps to Identity.Roles (multi-valued attribute).
	Roles string
}

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// ErrInvalidCredentials is returned when the user-bind fails. It surfaces as
// a 401 invalid_credentials response to the client.
var ErrInvalidCredentials = errors.New("invalid_credentials")

// ---------------------------------------------------------------------------
// Strategy
// ---------------------------------------------------------------------------

// Strategy implements strategy.Authenticator for LDAP-based authentication.
type Strategy struct {
	name      string
	label     string
	connector Connector
	config    Config
	attrMap   AttributeMap
	priority  int
	hidden    bool
	fields    []strategy.Field

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
// the login form should present different credential keys. The first field is
// treated as the username key, the second as the password key for parsing.
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

// New returns an LDAP strategy with the given name, connector, config, and
// attribute map. The connector is used for all LDAP operations; callers
// provide an implementation backed by their preferred LDAP library.
func New(name string, connector Connector, cfg Config, attrs AttributeMap, opts ...Option) *Strategy {
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(uid=%s)"
	}

	s := &Strategy{
		name:          name,
		label:         name,
		connector:     connector,
		config:        cfg,
		attrMap:       attrs,
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

// Login parses credentials from the request body and authenticates the user
// against the configured LDAP directory.
//
// Flow:
//  1. Parse {username, password} from JSON or form body.
//  2. Connect to LDAP and bind with the service account.
//  3. Search for the user entry using UserFilter.
//  4. Re-bind as the found user DN with the supplied password.
//  5. Map LDAP attributes to an Identity and return it.
func (s *Strategy) Login(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")

		return nil, strategy.OutcomeFailed, nil
	}

	if s.connector == nil {
		writeError(w, http.StatusInternalServerError, "no_connector", "no LDAP connector configured")

		return nil, strategy.OutcomeFailed, nil
	}

	username, password, err := s.readCredentials(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())

		return nil, strategy.OutcomeFailed, nil
	}

	if username == "" || password == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "username and password are required")

		return nil, strategy.OutcomeFailed, nil
	}

	id, err := s.authenticate(r.Context(), username, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")

			return nil, strategy.OutcomeFailed, nil
		}

		slog.Error("ldap authentication error", "strategy", s.name, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "ldap_error", "authentication failed")

		return nil, strategy.OutcomeFailed, nil
	}

	id.Provider = s.name

	return id, strategy.OutcomeContinue, nil
}

// Logout is a no-op for the LDAP strategy; the issuer revokes the session.
func (s *Strategy) Logout(_ context.Context, _ *identity.Identity) error { return nil }

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// authenticate performs the full LDAP bind-search-bind flow.
func (s *Strategy) authenticate(ctx context.Context, username, password string) (*identity.Identity, error) {
	conn, err := s.connector.Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()

	// Step 1: Bind with the service account.
	if err := conn.Bind(s.config.BindDN, s.config.BindPassword); err != nil {
		return nil, fmt.Errorf("service bind: %w", err)
	}

	// Step 2: Search for the user entry.
	filter := fmt.Sprintf(s.config.UserFilter, escapeLDAPFilter(username))
	attrs := s.requestedAttributes()

	entries, err := conn.Search(s.config.BaseDN, filter, attrs)
	if err != nil {
		return nil, fmt.Errorf("user search: %w", err)
	}

	if len(entries) == 0 {
		return nil, ErrInvalidCredentials
	}

	if len(entries) > 1 {
		return nil, fmt.Errorf("user search returned %d entries, expected 1", len(entries))
	}

	entry := entries[0]

	// Step 3: Bind as the user to verify the password.
	if err := conn.Bind(entry.DN, password); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Step 4: Build the Identity from LDAP attributes.
	id := s.buildIdentity(entry)

	return id, nil
}

// requestedAttributes returns the LDAP attribute names to request during the
// user search, derived from the configured AttributeMap.
func (s *Strategy) requestedAttributes() []string {
	var attrs []string

	for _, a := range []string{s.attrMap.Subject, s.attrMap.Email, s.attrMap.Name, s.attrMap.Roles} {
		if a != "" {
			attrs = append(attrs, a)
		}
	}

	return attrs
}

// buildIdentity maps LDAP entry attributes to an Identity using the
// configured AttributeMap.
func (s *Strategy) buildIdentity(entry Entry) *identity.Identity {
	id := &identity.Identity{
		IssuedAt: time.Now(),
	}

	if attr := s.attrMap.Subject; attr != "" {
		id.Subject = firstValue(entry, attr)
	}

	// Fall back to the DN if no Subject attribute was mapped or found.
	if id.Subject == "" {
		id.Subject = entry.DN
	}

	if attr := s.attrMap.Email; attr != "" {
		id.Email = firstValue(entry, attr)
	}

	if attr := s.attrMap.Name; attr != "" {
		id.Name = firstValue(entry, attr)
	}

	if attr := s.attrMap.Roles; attr != "" {
		if vals, ok := entry.Attributes[attr]; ok {
			id.Roles = vals
		}
	}

	return id
}

// firstValue returns the first value of the named attribute, or "" if absent.
func firstValue(entry Entry, attr string) string {
	if vals, ok := entry.Attributes[attr]; ok && len(vals) > 0 {
		return vals[0]
	}

	return ""
}

// readCredentials extracts the username and password from a JSON or
// form-encoded request body.
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
		values, err := parseForm(string(body))
		if err != nil {
			return "", "", fmt.Errorf("parse form: %w", err)
		}

		return values[s.usernameField], values[s.passwordField], nil
	}

	return "", "", fmt.Errorf("unsupported content type %q", contentType)
}

// parseForm parses an x-www-form-urlencoded body into a flat string map.
func parseForm(body string) (map[string]string, error) {
	values, err := url.ParseQuery(body)
	if err != nil {
		return nil, err
	}

	out := make(map[string]string, len(values))
	for k, v := range values {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}

	return out, nil
}

// escapeLDAPFilter escapes special characters in a string so it can be safely
// interpolated into an LDAP search filter (RFC 4515, section 3).
func escapeLDAPFilter(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := range len(s) {
		c := s[i]
		switch c {
		case '\\', '(', ')', '*', '\x00':
			fmt.Fprintf(&b, "\\%02x", c)
		default:
			b.WriteByte(c)
		}
	}

	return b.String()
}

// writeError writes a JSON error response to w.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}
