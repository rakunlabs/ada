package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/cookie"
	"github.com/rakunlabs/ada/middleware/auth/proxy"
)

// FlowData is server-held authorization material. Never send it to a browser.
type FlowData struct {
	State, Nonce, Verifier string
	Provider, CallbackURL  string
	ExpiresAt              time.Time
	// Source is a server-derived hash used only for initiation admission, not
	// callback authentication. SourceLimit is the maximum live flows per source.
	Source      string
	SourceLimit int
}

// FlowStore holds short-lived flows under random browser-cookie handles.
// Save must reject existing live handles and record ExpiresAt. Expired records
// must never be usable; storage may prune them lazily or use a backend TTL.
// Save must atomically enforce SourceLimit across live records with the same
// Source (nonpositive limits mean 10), returning ErrFlowSourceFull at capacity.
// Rejection/cancellation must not reserve quota; expiry and Consume release it.
// Consume must atomically remove and return a record, at most once across all
// replicas, including expired records (which may instead return ErrFlowInvalid).
// Unknown/consumed handles return ErrFlowInvalid. Other errors mean unavailable.
// Implementations must bound storage and honor context cancellation. Callers own
// injected stores and their cleanup; the strategy never closes a shared store.
type FlowStore interface {
	Save(context.Context, string, FlowData) error
	Consume(context.Context, string) (FlowData, error)
}

var (
	// ErrFlowInvalid identifies an unknown, expired, or consumed flow.
	ErrFlowInvalid = errors.New("oauth2: authorization flow expired, invalid or already used; restart login")
	// ErrFlowStoreFull indicates capacity exhaustion, not invalid credentials.
	ErrFlowStoreFull = errors.New("oauth2: authorization flow store full")
	// ErrFlowSourceFull indicates the source's pending-flow admission quota.
	ErrFlowSourceFull = errors.New("oauth2: too many pending authorization flows")
)

// memoryFlowStore needs no janitor/Close, including when strategies are replaced.
type memoryFlowStore struct {
	mu    sync.Mutex
	flows map[string]FlowData
}

func (m *memoryFlowStore) Save(ctx context.Context, key string, f FlowData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	pending := 0
	for k, v := range m.flows {
		if !now.Before(v.ExpiresAt) {
			delete(m.flows, k)
		} else if v.Source == f.Source {
			pending++
		}
	}
	if !now.Before(f.ExpiresAt) {
		return ErrFlowInvalid
	}
	if _, exists := m.flows[key]; exists {
		return ErrFlowInvalid
	}
	limit := f.SourceLimit
	if limit <= 0 {
		limit = 10
	}
	if pending >= limit {
		return ErrFlowSourceFull
	}
	if len(m.flows) >= 4096 {
		return ErrFlowStoreFull
	}
	m.flows[key] = f
	return nil
}

func (m *memoryFlowStore) Consume(ctx context.Context, key string) (FlowData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return FlowData{}, err
	}
	f, ok := m.flows[key]
	delete(m.flows, key)
	if !ok || !time.Now().Before(f.ExpiresAt) {
		return FlowData{}, ErrFlowInvalid
	}
	return f, nil
}

func (s *Strategy) flowProvider() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%q", []string{
		s.name, s.cfg.ClientID, s.cfg.IssuerURL, s.cfg.AuthURL, s.cfg.TokenURL,
		s.cfg.UserInfoURL, s.cfg.JWKSURL, s.cfg.Audience,
		fmt.Sprint(s.cfg.RequireIDToken, s.cfg.SkipIDTokenVerify, s.cfg.DisableNonce, s.cfg.DisablePKCE),
	}))))
}

// flowCookieName is the single cookie carrying an opaque handle for this strategy.
func (s *Strategy) flowCookieName() string {
	return "auth_flow_" + s.name
}

// Count raw names too: net/http silently drops malformed cookie values, which
// must not hide an ambiguous second flow cookie from validation.
func (s *Strategy) flowCookieCount(r *http.Request) int {
	count := 0
	for _, header := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(header, ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if strings.TrimSpace(name) == s.flowCookieName() {
				count++
			}
		}
	}
	return count
}

func (s *Strategy) setFlowCookie(w http.ResponseWriter, r *http.Request, f FlowData) error {
	policy, err := proxy.New(s.opts.TrustedProxies...)
	if err != nil {
		return err
	}
	source, err := policy.ClientIP(r)
	if err != nil {
		// Malformed forwarding data shares the peer's quota, never a new bucket.
		source = proxy.RealIP(r)
	}
	f.Source = fmt.Sprintf("%x", sha256.Sum256([]byte(source)))
	f.SourceLimit = s.opts.FlowMaxPendingPerSource
	v, err := randomURLSafe(32)
	if err != nil {
		return err
	}
	f.Provider = s.flowProvider()
	f.ExpiresAt = time.Now().Add(s.opts.FlowTTL)
	if err := s.flows.Save(r.Context(), v, f); err != nil {
		return err
	}
	s.flowCookie.Set(w, r, s.flowCookieName(), v)

	return nil
}

// takeFlowCookie reads the flow state and clears the cookie in the same breath.
// One authorization response, one use.
func (s *Strategy) takeFlowCookie(w http.ResponseWriter, r *http.Request) (FlowData, error) {
	s.flowCookie.Clear(w, r, s.flowCookieName())
	var flow FlowData
	var consumeErr error
	count := s.flowCookieCount(r)
	for _, c := range r.Cookies() {
		if c.Name != s.flowCookieName() {
			continue
		}
		// Reject the shipped base64 JSON format, with no insecure fallback.
		if len(c.Value) != 43 {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(c.Value)
		if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != c.Value {
			continue
		}
		f, err := s.flows.Consume(r.Context(), c.Value)
		if err != nil {
			consumeErr = err
			continue
		}
		flow = f
	}
	if consumeErr != nil && !errors.Is(consumeErr, ErrFlowInvalid) {
		return FlowData{}, consumeErr
	}
	if count != 1 || flow.State == "" || !time.Now().Before(flow.ExpiresAt) {
		return FlowData{}, ErrFlowInvalid
	}
	callback, err := s.callbackURL(r)
	if err != nil || flow.Provider != s.flowProvider() || flow.CallbackURL != callback {
		return FlowData{}, ErrFlowInvalid
	}
	u, err := url.Parse(callback)
	if err != nil || r.URL.Path != u.Path {
		return FlowData{}, ErrFlowInvalid
	}
	return flow, nil
}

// checkState compares the callback's state against the cookie in constant
// time. Both are attacker-visible; a comparison that returns early on the
// first differing byte is a slow oracle for forging one.
func checkState(want, got string) error {
	if want == "" || got == "" {
		return errors.New("oauth2: missing state")
	}

	if subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return errors.New("oauth2: state mismatch")
	}

	return nil
}

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth2: read random: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// defaultFlowCookie is the policy for the short-lived authorization cookie.
// Six minutes is long enough for a human to finish a login at the IdP and
// short enough that an abandoned attempt does not linger.
func defaultFlowCookie(opts cookie.Options) cookie.Options {
	if opts.MaxAge == 0 {
		opts.MaxAge = 360
	}

	// The flow cookie must survive the cross-site redirect back from the IdP,
	// so Strict is not an option here.
	if opts.SameSite == 0 {
		opts.SameSite = http.SameSiteLaxMode
	}

	// Nothing in the browser needs to read this cookie.
	opts.DisableHTTPOnly = false

	return opts.WithDefaults()
}
