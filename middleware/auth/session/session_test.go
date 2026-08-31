package session_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/cookie"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/issuer"
	"github.com/rakunlabs/ada/middleware/auth/issuer/backend"
	"github.com/rakunlabs/ada/middleware/auth/session"
)

func newSession(t *testing.T, mutate func(*session.Session)) (*session.Session, issuer.Issuer) {
	t.Helper()

	iss := issuer.NewDefault(backend.NewMemory(), issuer.Config{
		AccessTTL:  time.Minute,
		RefreshTTL: time.Hour,
	})

	s := &session.Session{Issuer: iss, LoginPath: "/login"}
	if mutate != nil {
		mutate(s)
	}

	if err := s.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}

	return s, iss
}

func TestInitCookieDefaults(t *testing.T) {
	s, _ := newSession(t, nil)

	if s.CookieName != "auth_session" {
		t.Errorf("cookie name = %q", s.CookieName)
	}

	rec := httptest.NewRecorder()
	s.IssueCookie(rec, httptest.NewRequest(http.MethodGet, "/", nil), "sid")

	got := rec.Result().Cookies()
	if len(got) != 1 {
		t.Fatalf("expected one cookie, got %d", len(got))
	}

	// The whole point of the change: a default deployment must not ship a
	// script-readable session cookie.
	if !got[0].HttpOnly {
		t.Error("session cookie must be HttpOnly by default")
	}

	if got[0].SameSite != http.SameSiteLaxMode {
		t.Errorf("same site = %v", got[0].SameSite)
	}
}

func TestInitRejectsUnusableCookieCombination(t *testing.T) {
	iss := issuer.NewDefault(backend.NewMemory(), issuer.Config{})

	s := &session.Session{
		Issuer: iss,
		Cookie: cookie.Options{SameSite: http.SameSiteNoneMode, Secure: cookie.SecureNever},
	}

	if err := s.Init(); err == nil {
		t.Error("expected Init to reject SameSite=None without Secure")
	}
}

func TestInitRequiresIssuer(t *testing.T) {
	s := &session.Session{}
	if err := s.Init(); err == nil {
		t.Error("expected error for nil issuer")
	}
}

func TestRequireHappyPath(t *testing.T) {
	s, iss := newSession(t, nil)

	pair, err := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	var seen *identity.Identity

	h := s.Require()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = identity.FromContext(r.Context())
	}))

	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: pair.SessionID})

	h.ServeHTTP(httptest.NewRecorder(), r)

	if seen == nil || seen.Subject != "alice" {
		t.Fatalf("identity not propagated: %+v", seen)
	}
}

func TestRequireRedirectsWithRedirectPath(t *testing.T) {
	s, _ := newSession(t, nil)

	rec := httptest.NewRecorder()
	h := s.Require()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler should not run")
	}))

	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/private?x=1", nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code = %d", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "redirect_path=%2Fprivate%3Fx%3D1") {
		t.Errorf("location = %q", loc)
	}
}

func TestRequireRejectFn(t *testing.T) {
	s, iss := newSession(t, func(s *session.Session) {
		s.RejectFn = func(id *identity.Identity) bool { return id.Subject == "pending" }
	})

	pair, _ := iss.Issue(context.Background(), &identity.Identity{Subject: "pending"})

	rec := httptest.NewRecorder()
	h := s.Require()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a rejected session must not reach the handler")
	}))

	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: pair.SessionID})

	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want redirect", rec.Code)
	}
}

func TestRequireDisableRedirectGives401(t *testing.T) {
	s, _ := newSession(t, func(s *session.Session) {
		s.ChallengeFn = func() string { return "Bearer" }
	})

	rec := httptest.NewRecorder()
	h := s.Require()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r = r.WithContext(session.SetDisableRedirect(r.Context(), true))

	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}

	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("challenge = %q", got)
	}
}

func TestRefreshOnExpiredAccess(t *testing.T) {
	iss := issuer.NewDefault(backend.NewMemory(), issuer.Config{
		AccessTTL:  time.Millisecond,
		RefreshTTL: time.Hour,
	})

	s := &session.Session{Issuer: iss, LoginPath: "/login"}
	if err := s.Init(); err != nil {
		t.Fatalf("init: %v", err)
	}

	pair, _ := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})

	time.Sleep(5 * time.Millisecond)

	var seen *identity.Identity

	h := s.Require()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = identity.FromContext(r.Context())
	}))

	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: pair.SessionID})

	h.ServeHTTP(httptest.NewRecorder(), r)

	if seen == nil || seen.Subject != "alice" {
		t.Fatalf("expired access token should have been refreshed, got %+v", seen)
	}
}

type replicaConflictIssuer struct {
	*issuer.Default
	winner *issuer.Default
	once   sync.Once
	calls  atomic.Int32
}

func (i *replicaConflictIssuer) Refresh(ctx context.Context, sessionID, refreshToken string) (*issuer.Pair, error) {
	i.calls.Add(1)
	conflicted := false
	var winnerErr error
	i.once.Do(func() {
		conflicted = true
		_, winnerErr = i.winner.Refresh(ctx, sessionID, refreshToken)
	})
	if winnerErr != nil {
		return nil, winnerErr
	}
	if conflicted {
		return nil, issuer.ErrTransactionConflict
	}

	return i.Default.Refresh(ctx, sessionID, refreshToken)
}

type alwaysConflictRefreshIssuer struct {
	issuer.Issuer
	calls atomic.Int32
}

func (i *alwaysConflictRefreshIssuer) Refresh(context.Context, string, string) (*issuer.Pair, error) {
	i.calls.Add(1)

	return nil, issuer.ErrTransactionConflict
}

func expireStoredAccess(t *testing.T, memory *backend.Memory, sessionID string) {
	t.Helper()

	_, err := memory.TransactPair(context.Background(), sessionID, 0, func(pair *issuer.Pair) (*issuer.Pair, bool, error) {
		pair.Access.ExpiresAt = time.Now().Add(-time.Minute)
		pair.Identity.ExpiresAt = pair.Access.ExpiresAt

		return pair, true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRefreshRecoversFromReplicaConflictUsingStoredWinner(t *testing.T) {
	memory := backend.NewMemory()
	first := issuer.NewDefault(memory, issuer.Config{AccessTTL: time.Minute, RefreshTTL: time.Hour})
	second := issuer.NewDefault(memory, issuer.Config{AccessTTL: time.Minute, RefreshTTL: time.Hour})
	pair, err := first.Issue(context.Background(), &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	expireStoredAccess(t, memory, pair.SessionID)
	iss := &replicaConflictIssuer{Default: first, winner: second}
	s := &session.Session{Issuer: iss, LoginPath: "/login"}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}

	called := false
	h := s.Require()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: pair.SessionID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if !called || rec.Code != http.StatusOK {
		t.Fatalf("request was not recovered: called=%t code=%d body=%s", called, rec.Code, rec.Body)
	}
	if got := iss.calls.Load(); got != 1 {
		t.Fatalf("Refresh calls = %d, want one conflicted call followed by winner resolve", got)
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("valid cookie was modified after recovery: %v", got)
	}
	if _, err := first.Refresh(context.Background(), pair.SessionID, pair.Refresh.Value); !errors.Is(err, issuer.ErrRefreshInvalid) {
		t.Fatalf("low-level refresh accepted the stale token: %v", err)
	}
}

func TestRefreshConflictExhaustionPreservesCookie(t *testing.T) {
	memory := backend.NewMemory()
	base := issuer.NewDefault(memory, issuer.Config{AccessTTL: time.Minute, RefreshTTL: time.Hour})
	pair, err := base.Issue(context.Background(), &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	expireStoredAccess(t, memory, pair.SessionID)
	iss := &alwaysConflictRefreshIssuer{Issuer: base}
	s := &session.Session{Issuer: iss, LoginPath: "/login"}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}

	h := s.Require()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler ran despite refresh failure")
	}))
	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: pair.SessionID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503 (%s)", rec.Code, rec.Body)
	}
	if got := iss.calls.Load(); got != 3 {
		t.Fatalf("Refresh calls = %d, want bounded 3 attempts", got)
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("transient conflict cleared the cookie: %v", got)
	}
}

func TestCookieNameForHost(t *testing.T) {
	s, _ := newSession(t, func(s *session.Session) {
		s.CookieNameHosts = []session.HostCookieName{
			{Host: "exact.example", CookieName: "exact"},
			{Regex: `^.*\.wild\.example$`, CookieName: "wild"},
		}
	})

	cases := map[string]string{
		"exact.example":  "exact",
		"a.wild.example": "wild",
		"other.example":  "auth_session",
	}

	for host, want := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = host

		if got := s.CookieNameFor(r); got != want {
			t.Errorf("%s -> %q, want %q", host, got, want)
		}
	}
}

func TestSafeRedirectPath(t *testing.T) {
	safe := []string{
		"/dashboard",
		"/a/b?c=d",
		"/x#frag",
		"/",
	}

	for _, v := range safe {
		if got := session.SafeRedirectPath(v); got != v {
			t.Errorf("%q should be accepted, got %q", v, got)
		}
	}

	// Every one of these is an open redirect if it survives.
	unsafe := []string{
		"",
		"https://evil.example/",
		"//evil.example/",
		"/\\evil.example",
		"\\\\evil.example",
		"http:/evil.example",
		"javascript:alert(1)",
		"dashboard",
		"/ok\nLocation: https://evil.example",
	}

	for _, v := range unsafe {
		if got := session.SafeRedirectPath(v); got != "" {
			t.Errorf("%q should be rejected, got %q", v, got)
		}
	}
}
