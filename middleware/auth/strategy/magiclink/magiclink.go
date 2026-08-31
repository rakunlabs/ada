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
	"crypto/sha256"
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

	"github.com/rakunlabs/ada/middleware/auth/guard"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
	"github.com/rakunlabs/ada/utils/proxy"
)

// Sender delivers the magic link/code to the user. The token is the random
// value; the strategy builds the full verify URL and passes it too.
type Sender func(ctx context.Context, email, token, verifyURL string) error

// Resolver looks up or creates a user by email and returns their Identity.
type Resolver func(ctx context.Context, email string) (*identity.Identity, error)

// TokenStore persists pending magic-link tokens.
//
// The value handed to Store is the SHA-256 of the token that went out by
// email, never the token itself. A store is a database row or a Redis key;
// treating a login credential the way a password is treated means a leaked
// dump is not a stack of usable logins.
//
// Consume MUST atomically retrieve and remove a token so concurrent requests
// cannot both authenticate with the same link.
type TokenStore interface {
	Store(ctx context.Context, token, email string, ttl time.Duration) error
	Consume(ctx context.Context, token string) (email string, err error)
	Delete(ctx context.Context, token string) error
}

// Strategy implements strategy.Authenticator for magic-link passwordless login.
type Strategy struct {
	name     string
	label    string
	priority int
	hidden   bool

	sender     Sender
	resolver   Resolver
	store      TokenStore
	ownedStore bool
	closeOnce  sync.Once

	tokenTTL    time.Duration
	tokenLength int

	verifyBaseURL       *proxy.Origin
	trustedProxies      *proxy.Policy
	unsafeRequestOrigin bool

	// verifyBasePath is the mounted path prefix the magic link points at. Set
	// by SetCallbackBasePath at Mount time, or pinned via WithVerifyPath.
	verifyBasePath string
	verifyPathSet  bool

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

// WithVerifyBaseURL sets the public origin for verify links. It must be an
// absolute http(s) URL containing only a scheme and host. Invalid values panic
// during construction, like invalid trusted-proxy CIDRs.
//
// Configure this in normal deployments. Without it, links can only be built
// from requests arriving through WithTrustedProxies, or through the explicitly
// unsafe compatibility option WithUnsafeRequestOrigin.
func WithVerifyBaseURL(raw string) Option {
	return func(s *Strategy) {
		origin, err := proxy.ParseOrigin(raw)
		if err != nil {
			panic(fmt.Errorf("magiclink: verify base URL: %w", err))
		}

		s.verifyBaseURL = &origin
	}
}

// WithTrustedProxies permits verify-link origins to be derived from requests
// whose immediate peer falls within one of the given CIDRs. Bare IPs are also
// accepted. X-Forwarded-Proto and X-Forwarded-Host are consulted only for such
// peers; X-Forwarded-For is never trusted.
//
// The proxy must overwrite the forwarded and Host headers rather than append
// caller-supplied values. Prefer WithVerifyBaseURL when the public origin is
// fixed.
func WithTrustedProxies(cidrs ...string) Option {
	policy, err := proxy.New(cidrs...)
	if err != nil {
		panic(fmt.Errorf("magiclink: trusted proxies: %w", err))
	}

	return func(s *Strategy) {
		s.trustedProxies = &policy
	}
}

// WithUnsafeRequestOrigin restores the legacy behavior of deriving externally
// generated links from Host and X-Forwarded-* headers for every caller.
//
// This is unsafe whenever an untrusted client can reach the send endpoint,
// because that client can choose where another user's login link points. Use a
// configured base URL or WithTrustedProxies instead.
func WithUnsafeRequestOrigin() Option {
	return func(s *Strategy) { s.unsafeRequestOrigin = true }
}

// WithVerifyPath pins the path prefix the magic link points at, e.g.
// "/auth/login/callback". The strategy appends "/<name>".
//
// Leave it unset in the normal case: the auth middleware pushes its own
// resolved callback base at Mount time, which is the only value guaranteed to
// match the routes that actually exist.
func WithVerifyPath(p string) Option {
	return func(s *Strategy) {
		s.verifyBasePath = p
		s.verifyPathSet = true
	}
}

// WithLimiter throttles link requests per email address.
//
// Without one, the send endpoint is an open relay pointed at anybody's inbox
// and a free user-enumeration oracle. guard.New(guard.Config{}) is a
// reasonable default.
func WithLimiter(l guard.Limiter) Option {
	return func(s *Strategy) { s.limiter = l }
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
		s.ownedStore = true
	}

	return s
}

// Name returns the strategy's URL key.
func (s *Strategy) Name() string { return s.name }

// SetCallbackBasePath implements strategy.CallbackBinder.
//
// A magic link is a callback: the user leaves the site, and the mail client
// brings them back with a one-time credential in the URL. The auth middleware
// pushes the base it actually mounted, which is what the previously hardcoded
// "/auth/login" was standing in for — and getting wrong, since the real route
// has never been at that path.
func (s *Strategy) SetCallbackBasePath(p string) {
	if s.verifyPathSet {
		return
	}

	s.verifyBasePath = p
}

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

// Close releases resources created by the strategy. Injected token stores are
// caller-owned and are not closed.
func (s *Strategy) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.ownedStore {
			err = s.store.(*MemoryStore).Close()
		}
	})

	return err
}

// handleSendLink reads the email from the request body, generates a token,
// stores it, builds the verify URL, calls the Sender, and writes a 200 JSON
// response.
func (s *Strategy) handleSendLink(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	email, err := s.readEmail(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())

		return nil, strategy.OutcomeFailed, nil
	}

	if !validEmail(email) {
		writeError(w, http.StatusBadRequest, "bad_request", "a valid email is required")

		return nil, strategy.OutcomeFailed, nil
	}

	key := strings.ToLower(email)

	if s.limiter != nil {
		if d := s.limiter.Check(key); !d.Allowed {
			guard.WriteLocked(w, d)

			return nil, strategy.OutcomePending, nil
		}
	}

	token, err := generateToken(s.tokenLength)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_generate", "failed to generate token")

		return nil, strategy.OutcomeFailed, nil
	}

	verifyURL, err := s.buildVerifyURL(r, token)
	if err != nil {
		slog.Error("magiclink verify origin unavailable", "strategy", s.name, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "verify_origin_unavailable", "verify URL origin is not configured")

		return nil, strategy.OutcomeFailed, nil
	}

	if err := s.store.Store(r.Context(), hashToken(token), email, s.tokenTTL); err != nil {
		slog.Error("magiclink store error", "strategy", s.name, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "store_failed", "failed to store token")

		return nil, strategy.OutcomeFailed, nil
	}

	if err := s.sender(r.Context(), email, token, verifyURL); err != nil {
		// Best-effort cleanup of stored token on send failure.
		_ = s.store.Delete(r.Context(), hashToken(token))

		slog.Error("magiclink sender error", "strategy", s.name, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "send_failed", "failed to send magic link")

		return nil, strategy.OutcomeFailed, nil
	}

	// Every send counts against the address, successful or not: the abuse
	// here is volume, not failure.
	if s.limiter != nil {
		s.limiter.Fail(key)
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "check your email",
	})

	// Pending, not Failed. The response is written and the flow is mid-air
	// waiting for the user to click; reporting failure was misleading to
	// anything reading the outcome.
	return nil, strategy.OutcomePending, nil
}

// handleVerifyToken looks up the token, validates it, resolves the identity,
// and returns it for session minting.
func (s *Strategy) handleVerifyToken(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	hashed := hashToken(r.URL.Query().Get("token"))

	email, err := s.store.Consume(r.Context(), hashed)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "token is invalid or expired")

		return nil, strategy.OutcomeFailed, nil
	}

	if s.limiter != nil {
		s.limiter.Succeed(strings.ToLower(email))
	}

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
func (s *Strategy) buildVerifyURL(r *http.Request, token string) (string, error) {
	origin, err := s.verifyOrigin(r)
	if err != nil {
		return "", err
	}

	base := s.verifyBasePath
	if base == "" {
		// Nothing pushed a base and none was configured. Fall back to the
		// path this request arrived on, minus the strategy segment, which is
		// by construction a route that exists.
		base = path.Dir(r.URL.Path)
	}

	u := &url.URL{
		Scheme:   origin.Scheme,
		Host:     origin.Host,
		Path:     path.Join(base, s.name),
		RawQuery: url.Values{"token": {token}}.Encode(),
	}

	return u.String(), nil
}

// hashToken is what actually lands in the TokenStore.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))

	return hex.EncodeToString(sum[:])
}

// validEmail is a deliberately loose sanity check: exactly one "@", something
// on either side, a dot in the domain, no spaces. Anything stricter rejects
// addresses that are legal, and anything looser lets an obvious typo consume
// a send.
func validEmail(v string) bool {
	if v == "" || len(v) > 254 || strings.ContainsAny(v, " \t\r\n") {
		return false
	}

	at := strings.IndexByte(v, '@')
	if at <= 0 || at != strings.LastIndexByte(v, '@') || at == len(v)-1 {
		return false
	}

	domain := v[at+1:]

	return strings.Contains(domain, ".") && !strings.HasPrefix(domain, ".") && !strings.HasSuffix(domain, ".")
}

// verifyOrigin determines the scheme and host for building the verify URL.
func (s *Strategy) verifyOrigin(r *http.Request) (proxy.Origin, error) {
	if s.verifyBaseURL != nil {
		origin := *s.verifyBaseURL

		return origin, nil
	}

	if s.trustedProxies != nil && s.trustedProxies.TrustedPeer(r) {
		return s.trustedProxies.Origin(r)
	}
	if s.unsafeRequestOrigin {
		return proxy.UnsafeOrigin(r)
	}

	return proxy.Origin{}, fmt.Errorf("set WithVerifyBaseURL or a trusted-proxy policy")
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
// TTL-based expiry and a background sweeper.
//
// It is single-process: with more than one replica, a link minted on one and
// clicked on another will not resolve. Supply a shared TokenStore for those
// deployments.
type MemoryStore struct {
	entries sync.Map // map[hashedToken string]memoryEntry

	stop   chan struct{}
	done   chan struct{}
	closed sync.Once
}

// NewMemoryStore returns an in-memory TokenStore and starts its sweeper.
//
// Expiry used to happen only on lookup, so a token nobody clicked — the common
// case for an abuse run — stayed resident for the life of the process.
func NewMemoryStore() *MemoryStore {
	m := &MemoryStore{stop: make(chan struct{}), done: make(chan struct{})}

	go m.janitor()

	return m
}

// Close stops the sweeper and waits for it to exit.
func (m *MemoryStore) Close() error {
	m.closed.Do(func() { close(m.stop) })
	<-m.done

	return nil
}

func (m *MemoryStore) janitor() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	defer close(m.done)

	for {
		select {
		case <-m.stop:
			return
		case now := <-t.C:
			m.entries.Range(func(k, v any) bool {
				if e, ok := v.(memoryEntry); ok && now.After(e.expiresAt) {
					m.entries.Delete(k)
				}

				return true
			})
		}
	}
}

// Store saves a token -> email mapping with a TTL.
func (m *MemoryStore) Store(_ context.Context, token, email string, ttl time.Duration) error {
	m.entries.Store(token, memoryEntry{
		email:     email,
		expiresAt: time.Now().Add(ttl),
	})

	return nil
}

// Consume atomically retrieves and removes a token. Returns an error if the
// token does not exist or has expired.
func (m *MemoryStore) Consume(_ context.Context, token string) (string, error) {
	v, ok := m.entries.LoadAndDelete(token)
	if !ok {
		return "", fmt.Errorf("token not found")
	}

	entry, ok := v.(memoryEntry)
	if !ok {
		return "", fmt.Errorf("token not found")
	}

	if time.Now().After(entry.expiresAt) {
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
