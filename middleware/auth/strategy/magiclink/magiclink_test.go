package magiclink_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/guard"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
	"github.com/rakunlabs/ada/middleware/auth/strategy/magiclink"
)

type capture struct {
	mu    sync.Mutex
	email string
	token string
	url   string
	calls int
}

func (c *capture) send(_ context.Context, email, token, verifyURL string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.email, c.token, c.url = email, token, verifyURL
	c.calls++

	return nil
}

func resolver(_ context.Context, email string) (*identity.Identity, error) {
	return &identity.Identity{Subject: email, Email: email}, nil
}

func newStrategy(t *testing.T, opts ...magiclink.Option) (*magiclink.Strategy, *capture, *magiclink.MemoryStore) {
	t.Helper()

	store := magiclink.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })

	c := &capture{}

	all := append([]magiclink.Option{
		magiclink.WithTokenStore(store),
		magiclink.WithVerifyBaseURL("https://app.example"),
	}, opts...)
	s := magiclink.New("mail", c.send, resolver, all...)

	return s, c, store
}

func sendLink(t *testing.T, s *magiclink.Strategy, email string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://app.example/auth/login/pass/mail",
		strings.NewReader(url.Values{"email": {email}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, _, err := s.Login(rec, r)
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	return rec
}

// The bug this replaces: the verify URL was hardcoded to "/auth/login/<name>",
// a route that has never existed. Every link 404'd.
func TestVerifyURLUsesMountedCallbackBase(t *testing.T) {
	s, c, _ := newStrategy(t)
	s.SetCallbackBasePath("/api/v1/login/callback")

	sendLink(t, s, "alice@example.com")

	u, err := url.Parse(c.url)
	if err != nil {
		t.Fatalf("parse verify url: %v", err)
	}

	if u.Path != "/api/v1/login/callback/mail" {
		t.Fatalf("verify path = %q", u.Path)
	}

	if u.Query().Get("token") == "" {
		t.Error("verify url carries no token")
	}
}

func TestWithVerifyPathWinsOverBinder(t *testing.T) {
	s, c, _ := newStrategy(t, magiclink.WithVerifyPath("/custom/verify"))
	s.SetCallbackBasePath("/api/v1/login/callback")

	sendLink(t, s, "alice@example.com")

	u, _ := url.Parse(c.url)
	if u.Path != "/custom/verify/mail" {
		t.Fatalf("verify path = %q", u.Path)
	}
}

func TestVerifyBaseURLOrigin(t *testing.T) {
	s, c, _ := newStrategy(t, magiclink.WithVerifyBaseURL("https://public.example"))
	s.SetCallbackBasePath("/auth/login/callback")

	sendLink(t, s, "alice@example.com")

	if !strings.HasPrefix(c.url, "https://public.example/") {
		t.Fatalf("verify url = %q", c.url)
	}
}

func TestRequestOriginIsNotTrustedByDefault(t *testing.T) {
	store := magiclink.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })

	c := &capture{}
	s := magiclink.New("mail", c.send, resolver, magiclink.WithTokenStore(store))
	s.SetCallbackBasePath("/auth/login/callback")

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://attacker.example/auth/login/pass/mail",
		strings.NewReader(`{"email":"alice@example.com"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "attacker.example")

	_, outcome, _ := s.Login(rec, r)
	if outcome != strategy.OutcomeFailed || rec.Code != http.StatusInternalServerError {
		t.Fatalf("outcome = %v, code = %d, body = %s", outcome, rec.Code, rec.Body)
	}
	if c.calls != 0 {
		t.Fatal("sender must not receive a caller-controlled verification URL")
	}
}

func TestTrustedProxyMaySupplyOrigin(t *testing.T) {
	store := magiclink.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })

	c := &capture{}
	s := magiclink.New("mail", c.send, resolver,
		magiclink.WithTokenStore(store),
		magiclink.WithTrustedProxies("10.0.0.0/8"),
	)
	s.SetCallbackBasePath("/auth/login/callback")

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "http://internal/auth/login/pass/mail",
		strings.NewReader(`{"email":"alice@example.com"}`))
	r.RemoteAddr = "10.1.2.3:1234"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "public.example")

	if _, outcome, _ := s.Login(rec, r); outcome != strategy.OutcomePending {
		t.Fatalf("trusted request failed: %d %s", rec.Code, rec.Body)
	}
	if !strings.HasPrefix(c.url, "https://public.example/") {
		t.Fatalf("verify URL = %q", c.url)
	}
}

func TestUntrustedPeerCannotSupplyForwardedOrigin(t *testing.T) {
	store := magiclink.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })

	c := &capture{}
	s := magiclink.New("mail", c.send, resolver,
		magiclink.WithTokenStore(store),
		magiclink.WithTrustedProxies("10.0.0.0/8"),
	)
	s.SetCallbackBasePath("/auth/login/callback")

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "http://internal/auth/login/pass/mail",
		strings.NewReader(`{"email":"alice@example.com"}`))
	r.RemoteAddr = "203.0.113.9:1234"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "attacker.example")

	if _, outcome, _ := s.Login(rec, r); outcome != strategy.OutcomeFailed {
		t.Fatal("untrusted forwarded origin was accepted")
	}
	if c.calls != 0 {
		t.Fatal("sender called for an untrusted origin")
	}
}

func TestTrustedProxyOriginIsValidated(t *testing.T) {
	store := magiclink.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })

	for name, headers := range map[string]map[string]string{
		"malformed proto": {"X-Forwarded-Proto": "javascript", "X-Forwarded-Host": "public.example"},
		"proto chain":     {"X-Forwarded-Proto": "https, http", "X-Forwarded-Host": "public.example"},
		"host chain":      {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "public.example, attacker.example"},
	} {
		t.Run(name, func(t *testing.T) {
			c := &capture{}
			s := magiclink.New("mail", c.send, resolver,
				magiclink.WithTokenStore(store),
				magiclink.WithTrustedProxies("10.0.0.0/8"),
			)
			s.SetCallbackBasePath("/auth/login/callback")

			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "http://internal/auth/login/pass/mail",
				strings.NewReader(`{"email":"alice@example.com"}`))
			r.RemoteAddr = "10.1.2.3:1234"
			r.Header.Set("Content-Type", "application/json")
			for key, value := range headers {
				r.Header.Set(key, value)
			}

			if _, outcome, _ := s.Login(rec, r); outcome != strategy.OutcomeFailed {
				t.Fatal("malformed forwarded origin was accepted")
			}
			if c.calls != 0 {
				t.Fatal("sender called with malformed forwarded origin")
			}
		})
	}
}

func TestTrustedIPv6ProxyMaySupplyIPv6Origin(t *testing.T) {
	store := magiclink.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })

	c := &capture{}
	s := magiclink.New("mail", c.send, resolver,
		magiclink.WithTokenStore(store),
		magiclink.WithTrustedProxies("2001:db8::/32"),
	)
	s.SetCallbackBasePath("/auth/login/callback")

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "http://internal/auth/login/pass/mail",
		strings.NewReader(`{"email":"alice@example.com"}`))
	r.RemoteAddr = "[2001:db8::1]:1234"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "[2001:0db8::8]:8443")

	if _, outcome, _ := s.Login(rec, r); outcome != strategy.OutcomePending {
		t.Fatalf("trusted IPv6 request failed: %d %s", rec.Code, rec.Body)
	}
	if !strings.HasPrefix(c.url, "https://[2001:db8::8]:8443/") {
		t.Fatalf("verify URL = %q", c.url)
	}
}

func TestUnsafeRequestOriginRequiresExplicitOptIn(t *testing.T) {
	store := magiclink.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })
	c := &capture{}
	s := magiclink.New("mail", c.send, resolver,
		magiclink.WithTokenStore(store),
		magiclink.WithUnsafeRequestOrigin(),
	)
	s.SetCallbackBasePath("/auth/login/callback")

	sendLink(t, s, "alice@example.com")
	if !strings.HasPrefix(c.url, "https://app.example/") {
		t.Fatalf("legacy request origin = %q", c.url)
	}
}

func TestVerifyBaseURLIsValidatedAtConstruction(t *testing.T) {
	for _, raw := range []string{"", "public.example", "ftp://public.example", "https://user@public.example", "https://public.example/path", "https://public.example?x=1"} {
		t.Run(raw, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("WithVerifyBaseURL(%q) did not panic", raw)
				}
			}()

			_ = magiclink.New("mail", (&capture{}).send, resolver, magiclink.WithVerifyBaseURL(raw))
		})
	}
}

// A store dump must not be a stack of usable logins.
func TestTokenIsStoredHashed(t *testing.T) {
	s, c, store := newStrategy(t)
	s.SetCallbackBasePath("/auth/login/callback")

	sendLink(t, s, "alice@example.com")

	if _, err := store.Consume(context.Background(), c.token); err == nil {
		t.Fatal("the raw token must not be a key in the store")
	}
}

func TestRoundTrip(t *testing.T) {
	s, c, _ := newStrategy(t)
	s.SetCallbackBasePath("/auth/login/callback")

	sendLink(t, s, "alice@example.com")

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, c.url, nil)

	id, outcome, err := s.Login(rec, r)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if outcome != strategy.OutcomeContinue {
		t.Fatalf("outcome = %v (%s)", outcome, rec.Body)
	}

	if id.Email != "alice@example.com" || id.Provider != "mail" {
		t.Fatalf("identity = %+v", id)
	}
}

func TestTokenIsSingleUse(t *testing.T) {
	s, c, _ := newStrategy(t)
	s.SetCallbackBasePath("/auth/login/callback")

	sendLink(t, s, "alice@example.com")

	first := httptest.NewRequest(http.MethodGet, c.url, nil)
	if _, outcome, _ := s.Login(httptest.NewRecorder(), first); outcome != strategy.OutcomeContinue {
		t.Fatal("first use should succeed")
	}

	second := httptest.NewRequest(http.MethodGet, c.url, nil)
	if _, outcome, _ := s.Login(httptest.NewRecorder(), second); outcome != strategy.OutcomeFailed {
		t.Fatal("a magic link must not work twice")
	}
}

func TestTokenConcurrentConsumptionIsAtomic(t *testing.T) {
	s, c, _ := newStrategy(t)
	s.SetCallbackBasePath("/auth/login/callback")
	sendLink(t, s, "alice@example.com")

	const requests = 32
	start := make(chan struct{})
	outcomes := make(chan strategy.Outcome, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r := httptest.NewRequest(http.MethodGet, c.url, nil)
			_, outcome, _ := s.Login(httptest.NewRecorder(), r)
			outcomes <- outcome
		}()
	}

	close(start)
	wg.Wait()
	close(outcomes)

	succeeded := 0
	for outcome := range outcomes {
		if outcome == strategy.OutcomeContinue {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful concurrent uses = %d, want 1", succeeded)
	}
}

type trackingStore struct {
	*magiclink.MemoryStore
	closes int
}

func (s *trackingStore) Close() error {
	s.closes++
	return s.MemoryStore.Close()
}

func TestStrategyCloseOwnsOnlyDefaultStore(t *testing.T) {
	custom := &trackingStore{MemoryStore: magiclink.NewMemoryStore()}
	t.Cleanup(func() { _ = custom.MemoryStore.Close() })

	s := magiclink.New("mail", (&capture{}).send, resolver, magiclink.WithTokenStore(custom))
	if err := s.Close(); err != nil {
		t.Fatalf("close custom strategy: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second close custom strategy: %v", err)
	}
	if custom.closes != 0 {
		t.Fatalf("custom store closed %d times, want 0", custom.closes)
	}

	owned := magiclink.New("owned", (&capture{}).send, resolver)
	if err := owned.Close(); err != nil {
		t.Fatalf("close default strategy: %v", err)
	}
	if err := owned.Close(); err != nil {
		t.Fatalf("second close default strategy: %v", err)
	}
}

func TestTokenExpires(t *testing.T) {
	s, c, _ := newStrategy(t, magiclink.WithTokenTTL(10*time.Millisecond))
	s.SetCallbackBasePath("/auth/login/callback")

	sendLink(t, s, "alice@example.com")

	time.Sleep(30 * time.Millisecond)

	r := httptest.NewRequest(http.MethodGet, c.url, nil)
	if _, outcome, _ := s.Login(httptest.NewRecorder(), r); outcome != strategy.OutcomeFailed {
		t.Fatal("an expired link must be rejected")
	}
}

func TestSendOutcomeIsPending(t *testing.T) {
	s, _, _ := newStrategy(t)
	s.SetCallbackBasePath("/auth/login/callback")

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://app.example/auth/login/pass/mail",
		strings.NewReader(`{"email":"alice@example.com"}`))
	r.Header.Set("Content-Type", "application/json")

	_, outcome, _ := s.Login(rec, r)

	// The response is written and the flow is mid-air, which is Pending.
	// Reporting Failed on the success path was simply wrong.
	if outcome != strategy.OutcomePending {
		t.Fatalf("outcome = %v, want Pending", outcome)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
}

func TestRejectsMalformedEmail(t *testing.T) {
	s, c, _ := newStrategy(t)
	s.SetCallbackBasePath("/auth/login/callback")

	for _, bad := range []string{"", "nope", "a@b", "a@@b.com", "a b@c.com", "@example.com", "a@.com"} {
		rec := sendLink(t, s, bad)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q accepted with code %d", bad, rec.Code)
		}
	}

	if c.calls != 0 {
		t.Errorf("sender was invoked %d times for malformed input", c.calls)
	}
}

// Without a limiter, the send endpoint is an open relay pointed at anybody's
// inbox.
func TestLimiterThrottlesPerEmail(t *testing.T) {
	g := guard.New(guard.Config{MaxFailures: 3, Window: time.Minute, Lockout: time.Minute})
	t.Cleanup(func() { _ = g.Close() })

	s, c, _ := newStrategy(t, magiclink.WithLimiter(g))
	s.SetCallbackBasePath("/auth/login/callback")

	for range 3 {
		sendLink(t, s, "alice@example.com")
	}

	rec := sendLink(t, s, "alice@example.com")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("code = %d, want 429", rec.Code)
	}

	if c.calls != 3 {
		t.Errorf("sender called %d times, want 3", c.calls)
	}

	// A different address is unaffected.
	if got := sendLink(t, s, "bob@example.com"); got.Code != http.StatusOK {
		t.Errorf("unrelated address throttled: %d", got.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	s, _, _ := newStrategy(t)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/auth/login/pass/mail", nil)

	if _, outcome, _ := s.Login(rec, r); outcome != strategy.OutcomeFailed {
		t.Fatal("expected failure")
	}

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("code = %d", rec.Code)
	}
}

func TestGetWithoutTokenIsBadRequest(t *testing.T) {
	s, _, _ := newStrategy(t)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/login/callback/mail", nil)

	s.Login(rec, r) //nolint:errcheck // outcome checked below

	if rec.Code != http.StatusBadRequest {
		t.Errorf("code = %d", rec.Code)
	}
}

func TestImplementsCallbackBinder(t *testing.T) {
	s, _, _ := newStrategy(t)

	if _, ok := any(s).(strategy.CallbackBinder); !ok {
		t.Fatal("magiclink must implement CallbackBinder so Mount can wire the real route")
	}
}
