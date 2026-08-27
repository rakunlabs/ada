package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy/local"
)

// secondFactor is a stand-in for a TOTP verifier: the code is always "123456".
type secondFactor struct {
	required bool
	err      error
	calls    int
}

func (s *secondFactor) Required(context.Context, *identity.Identity) (bool, error) {
	return s.required, s.err
}

func (s *secondFactor) Verify(_ context.Context, r *http.Request, _ *identity.Identity) error {
	s.calls++

	var body struct {
		Code string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return err
	}

	if body.Code != "123456" {
		return http.ErrNoCookie // any error rejects
	}

	return nil
}

func newMFAAuth(t *testing.T, sf auth.SecondFactor) (*auth.Auth, *fakeMux) {
	t.Helper()

	a := auth.New(auth.Config{Base: "/auth", UI: auth.UIConfig{ExternalFolder: true}}).
		Strategy(local.New("local", func(_ context.Context, u, p string) (*identity.Identity, error) {
			if u == "alice" && p == "pw" {
				return &identity.Identity{Subject: "alice"}, nil
			}

			return nil, local.ErrInvalidCredentials
		}))

	if sf != nil {
		a = a.WithSecondFactor(sf)
	}

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	return a, mux
}

func login(t *testing.T, mux *fakeMux) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login/pass/local",
		strings.NewReader(`{"username":"alice","password":"pw"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")

	mux.mu.ServeHTTP(rec, r)

	return rec
}

func postMFA(t *testing.T, mux *fakeMux, cookie *http.Cookie, body string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login/mfa", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	if cookie != nil {
		r.AddCookie(cookie)
	}

	mux.mu.ServeHTTP(rec, r)

	return rec
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}

	return nil
}

func TestNoSecondFactorIssuesSessionDirectly(t *testing.T) {
	_, mux := newMFAAuth(t, nil)

	rec := login(t, mux)

	if cookieNamed(rec, "auth_session") == nil {
		t.Fatalf("expected a session cookie, got %v", rec.Result().Cookies())
	}
}

func TestSecondFactorNotRequiredIssuesSessionDirectly(t *testing.T) {
	_, mux := newMFAAuth(t, &secondFactor{required: false})

	rec := login(t, mux)

	if cookieNamed(rec, "auth_session") == nil {
		t.Fatal("expected a session cookie")
	}

	if cookieNamed(rec, "auth_mfa") != nil {
		t.Fatal("no pending cookie should be set when MFA is not required")
	}
}

func TestSecondFactorParksTheLogin(t *testing.T) {
	_, mux := newMFAAuth(t, &secondFactor{required: true})

	rec := login(t, mux)

	// The first factor must not, on its own, produce a session.
	if cookieNamed(rec, "auth_session") != nil {
		t.Fatal("a session was issued before the second factor")
	}

	pending := cookieNamed(rec, "auth_mfa")
	if pending == nil {
		t.Fatalf("expected a pending cookie, got %v", rec.Result().Cookies())
	}

	if !pending.HttpOnly {
		t.Error("pending cookie must be HttpOnly")
	}

	if pending.Path != "/auth/login/mfa" {
		t.Errorf("pending cookie path = %q; it should not travel with every request", pending.Path)
	}

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)

	if body["mfa_required"] != true {
		t.Errorf("response = %s", rec.Body)
	}
}

func TestSecondFactorCompletesLogin(t *testing.T) {
	sf := &secondFactor{required: true}
	_, mux := newMFAAuth(t, sf)

	pending := cookieNamed(login(t, mux), "auth_mfa")

	rec := postMFA(t, mux, pending, `{"code":"123456"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d (%s)", rec.Code, rec.Body)
	}

	if cookieNamed(rec, "auth_session") == nil {
		t.Fatal("expected a session cookie after the second factor")
	}

	if sf.calls != 1 {
		t.Errorf("verifier called %d times", sf.calls)
	}
}

func TestSecondFactorRejectsWrongCode(t *testing.T) {
	_, mux := newMFAAuth(t, &secondFactor{required: true})

	pending := cookieNamed(login(t, mux), "auth_mfa")

	rec := postMFA(t, mux, pending, `{"code":"000000"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d", rec.Code)
	}

	if cookieNamed(rec, "auth_session") != nil {
		t.Fatal("a wrong code must not produce a session")
	}
}

func TestSecondFactorAttemptsAreCapped(t *testing.T) {
	a, mux := newMFAAuth(t, &secondFactor{required: true})
	_ = a

	pending := cookieNamed(login(t, mux), "auth_mfa")

	// Default MaxAttempts is 5.
	for i := range 5 {
		rec := postMFA(t, mux, pending, `{"code":"000000"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: code = %d", i+1, rec.Code)
		}
	}

	rec := postMFA(t, mux, pending, `{"code":"123456"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("code = %d, want 429 after exhausting attempts (%s)", rec.Code, rec.Body)
	}

	// The pending login is destroyed, so even the right code no longer works.
	again := postMFA(t, mux, pending, `{"code":"123456"}`)
	if again.Code == http.StatusOK {
		t.Fatal("a burned pending login must not be usable")
	}
}

func TestMFAWithoutPendingCookie(t *testing.T) {
	_, mux := newMFAAuth(t, &secondFactor{required: true})

	rec := postMFA(t, mux, nil, `{"code":"123456"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d", rec.Code)
	}
}

// A pending session ID must not be usable as a real one.
func TestPendingSessionIsNotASession(t *testing.T) {
	a, mux := newMFAAuth(t, &secondFactor{required: true})

	pending := cookieNamed(login(t, mux), "auth_mfa")

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: pending.Value})

	a.Require()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a half-authenticated identity must not pass Require")
	})).ServeHTTP(rec, r)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("code = %d, want a redirect to login", rec.Code)
	}
}

func TestMFARouteAbsentWhenNotConfigured(t *testing.T) {
	_, mux := newMFAAuth(t, nil)

	rec := postMFA(t, mux, nil, `{"code":"1"}`)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404 when no second factor is registered", rec.Code)
	}
}

// A failing Required must fail the login, not silently downgrade it.
func TestSecondFactorCheckFailsClosed(t *testing.T) {
	_, mux := newMFAAuth(t, &secondFactor{required: true, err: context.DeadlineExceeded})

	rec := login(t, mux)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500", rec.Code)
	}

	if cookieNamed(rec, "auth_session") != nil {
		t.Fatal("an unreadable enrolment store must not produce a session")
	}
}
