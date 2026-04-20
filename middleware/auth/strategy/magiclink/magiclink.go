// Package magiclink implements a strategy.Authenticator for passwordless
// email-based login. The flow has two steps:
//
//  1. POST {email} -> strategy generates a random token, stores it, and calls
//     the user-supplied Sender to deliver the magic link. Returns 200 with a
//     "check your email" message.
//  2. GET ?token=<value> -> strategy looks up the token, validates it (exists +
//     not expired), calls the user-supplied Resolver to get the Identity, and
//     returns it to the auth middleware for session minting.
package magiclink

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

// Sender delivers the magic link/code to the user. The token is the random
// value; the strategy builds the full verify URL and passes it too.
type Sender func(ctx context.Context, email, token, verifyURL string) error

// Resolver looks up or creates a user by email and returns their Identity.
type Resolver func(ctx context.Context, email string) (*identity.Identity, error)

// TokenStore persists pending magic-link tokens.
type TokenStore interface {
	Store(ctx context.Context, token, email string, ttl time.Duration) error
	Lookup(ctx context.Context, token string) (email string, err error)
	Delete(ctx context.Context, token string) error
}

// Strategy implements strategy.Authenticator for magic-link passwordless login.
type Strategy struct {
	name     string
	label    string
	priority int
	hidden   bool

	sender   Sender
	resolver Resolver
	store    TokenStore

	tokenTTL    time.Duration
	tokenLength int

	verifyBaseURL string
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

// WithTokenStore overrides the default in-memory token store.
func WithTokenStore(store TokenStore) Option {
	return func(s *Strategy) { s.store = store }
}

// WithTokenTTL sets how long a magic link token is valid. Default is 15 minutes.
func WithTokenTTL(ttl time.Duration) Option {
	return func(s *Strategy) { s.tokenTTL = ttl }
}

// WithTokenLength sets the number of random bytes for the token. Default is 32.
func WithTokenLength(n int) Option {
	return func(s *Strategy) { s.tokenLength = n }
}

// WithVerifyBaseURL sets the base URL for building the verify link. When empty,
// the strategy derives the origin from the request's X-Forwarded-* headers or
// Host.
func WithVerifyBaseURL(u string) Option {
	return func(s *Strategy) { s.verifyBaseURL = u }
}

// New returns a magic-link strategy with the given name, sender, and resolver.
func New(name string, sender Sender, resolver Resolver, opts ...Option) *Strategy {
	s := &Strategy{
		name:        name,
		label:       name,
		sender:      sender,
		resolver:    resolver,
		tokenTTL:    15 * time.Minute,
		tokenLength: 32,
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.store == nil {
		s.store = NewMemoryStore()
	}

	return s
}

// Name returns the strategy's URL key.
func (s *Strategy) Name() string { return s.name }

// Descriptor returns the UI-facing description of this strategy.
func (s *Strategy) Descriptor() strategy.Descriptor {
	return strategy.Descriptor{
		Name:  s.name,
		Kind:  "custom",
		Label: s.label,
		// LoginURL is resolved by the auth middleware from cfg.Base.
		Fields: []strategy.Field{
			{Name: "email", Label: "Email", Type: "email", Required: true},
		},
		Priority: s.priority,
		Hidden:   s.hidden,
	}
}

// Login dispatches based on request shape:
//   - POST with body {email} -> Step 1: send magic link.
//   - GET with ?token=<value> -> Step 2: verify token and return Identity.
func (s *Strategy) Login(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	switch r.Method {
	case http.MethodPost:
		return s.handleSendLink(w, r)
	case http.MethodGet:
		if r.URL.Query().Get("token") != "" {
			return s.handleVerifyToken(w, r)
		}

		writeError(w, http.StatusBadRequest, "missing_token", "token query parameter required")

		return nil, strategy.OutcomeFailed, nil
	}

	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST or GET required")

	return nil, strategy.OutcomeFailed, nil
}

// Logout is a no-op for the magic-link strategy; the issuer revokes the session.
func (s *Strategy) Logout(_ context.Context, _ *identity.Identity) error { return nil }

// handleSendLink reads the email from the request body, generates a token,
// stores it, builds the verify URL, calls the Sender, and writes a 200 JSON
// response.
func (s *Strategy) handleSendLink(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	email, err := s.readEmail(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())

		return nil, strategy.OutcomeFailed, nil
	}

	if email == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "email is required")

		return nil, strategy.OutcomeFailed, nil
	}

	token, err := generateToken(s.tokenLength)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_generate", "failed to generate token")

		return nil, strategy.OutcomeFailed, nil
	}

	if err := s.store.Store(r.Context(), token, email, s.tokenTTL); err != nil {
		slog.Error("magiclink store error", "strategy", s.name, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "store_failed", "failed to store token")

		return nil, strategy.OutcomeFailed, nil
	}

	verifyURL := s.buildVerifyURL(r, token)

	if err := s.sender(r.Context(), email, token, verifyURL); err != nil {
		// Best-effort cleanup of stored token on send failure.
		_ = s.store.Delete(r.Context(), token)

		slog.Error("magiclink sender error", "strategy", s.name, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "send_failed", "failed to send magic link")

		return nil, strategy.OutcomeFailed, nil
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "check your email",
	})

	return nil, strategy.OutcomeFailed, nil
}

// handleVerifyToken looks up the token, validates it, resolves the identity,
// and returns it for session minting.
func (s *Strategy) handleVerifyToken(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	token := r.URL.Query().Get("token")

	email, err := s.store.Lookup(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "token is invalid or expired")

		return nil, strategy.OutcomeFailed, nil
	}

	// Delete the token so it cannot be reused.
	_ = s.store.Delete(r.Context(), token)

	id, err := s.resolver(r.Context(), email)
	if err != nil {
		slog.Error("magiclink resolver error", "strategy", s.name, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "resolve_failed", "failed to resolve user")

		return nil, strategy.OutcomeFailed, nil
	}

	if id == nil {
		writeError(w, http.StatusUnauthorized, "unknown_user", "no user found for this email")

		return nil, strategy.OutcomeFailed, nil
	}

	id.Provider = s.name

	return id, strategy.OutcomeContinue, nil
}

// readEmail extracts the email from JSON or form-encoded request body.
func (s *Strategy) readEmail(r *http.Request) (string, error) {
	contentType := r.Header.Get("Content-Type")

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	switch {
	case strings.HasPrefix(contentType, "application/json"):
		var m map[string]string
		if err := json.Unmarshal(body, &m); err != nil {
			return "", fmt.Errorf("decode json: %w", err)
		}

		return m["email"], nil

	case strings.HasPrefix(contentType, "application/x-www-form-urlencoded"):
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return "", fmt.Errorf("parse form: %w", err)
		}

		return values.Get("email"), nil
	}

	return "", fmt.Errorf("unsupported content type %q", contentType)
}

// buildVerifyURL constructs the full verify URL for the magic link.
func (s *Strategy) buildVerifyURL(r *http.Request, token string) string {
	scheme, host := s.verifyOrigin(r)

	u := &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     path.Join("/auth/login", s.name),
		RawQuery: url.Values{"token": {token}}.Encode(),
	}

	return u.String()
}

// verifyOrigin determines the scheme and host for building the verify URL.
func (s *Strategy) verifyOrigin(r *http.Request) (string, string) {
	if s.verifyBaseURL != "" {
		if u, err := url.Parse(s.verifyBaseURL); err == nil {
			return u.Scheme, u.Host
		}
	}

	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			return proto, host
		}
	}

	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
		scheme = "http"
	}

	return scheme, r.Host
}

// generateToken produces a cryptographically random hex-encoded token.
func generateToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

// --- In-memory TokenStore ---------------------------------------------------

type memoryEntry struct {
	email     string
	expiresAt time.Time
}

// MemoryStore is a default in-memory TokenStore backed by sync.Map with
// TTL-based expiry.
type MemoryStore struct {
	entries sync.Map // map[token string]memoryEntry
}

// NewMemoryStore returns an in-memory TokenStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

// Store saves a token -> email mapping with a TTL.
func (m *MemoryStore) Store(_ context.Context, token, email string, ttl time.Duration) error {
	m.entries.Store(token, memoryEntry{
		email:     email,
		expiresAt: time.Now().Add(ttl),
	})

	return nil
}

// Lookup retrieves the email for a token. Returns an error if the token does
// not exist or has expired.
func (m *MemoryStore) Lookup(_ context.Context, token string) (string, error) {
	v, ok := m.entries.Load(token)
	if !ok {
		return "", fmt.Errorf("token not found")
	}

	entry := v.(memoryEntry)
	if time.Now().After(entry.expiresAt) {
		m.entries.Delete(token)

		return "", fmt.Errorf("token expired")
	}

	return entry.email, nil
}

// Delete removes a token from the store.
func (m *MemoryStore) Delete(_ context.Context, token string) error {
	m.entries.Delete(token)

	return nil
}

// --- Helpers ----------------------------------------------------------------

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(v)
}
