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

	all := append([]magiclink.Option{magiclink.WithTokenStore(store)}, opts...)
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

// A store dump must not be a stack of usable logins.
func TestTokenIsStoredHashed(t *testing.T) {
	s, c, store := newStrategy(t)
	s.SetCallbackBasePath("/auth/login/callback")

	sendLink(t, s, "alice@example.com")

	if _, err := store.Lookup(context.Background(), c.token); err == nil {
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
