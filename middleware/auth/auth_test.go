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

// fakeMux is a minimal in-memory mux that satisfies auth.Mux for tests.
type fakeMux struct {
	mu     *http.ServeMux
	routes []string
}

func newFakeMux() *fakeMux { return &fakeMux{mu: http.NewServeMux()} }

func (f *fakeMux) GET(p string, h http.HandlerFunc, _ ...func(http.Handler) http.Handler) {
	f.routes = append(f.routes, "GET "+p)
	f.mu.HandleFunc("GET "+p, h)
}
func (f *fakeMux) POST(p string, h http.HandlerFunc, _ ...func(http.Handler) http.Handler) {
	f.routes = append(f.routes, "POST "+p)
	f.mu.HandleFunc("POST "+p, h)
}
func (f *fakeMux) HandleFunc(p string, h http.HandlerFunc, _ ...func(http.Handler) http.Handler) {
	f.routes = append(f.routes, p)
	f.mu.HandleFunc(p, h)
}
func (f *fakeMux) HandleFuncWildcard(p string, h http.HandlerFunc, _ ...func(http.Handler) http.Handler) {
	f.routes = append(f.routes, "WILDCARD "+p)
	pattern := strings.TrimSuffix(p, "/*") + "/"
	f.mu.HandleFunc(pattern, h)
}

func TestLoginIssuesCookieAndIdentity(t *testing.T) {
	// Default Base="/" → paths: /login/pass/{strategy}, /login/info, /login/me, /logout
	a := auth.New(auth.Config{
		UI: auth.UIConfig{ExternalFolder: true},
	})

	a.Strategy(local.New("local", func(_ context.Context, u, p string) (*identity.Identity, error) {
		if u == "alice" && p == "secret" {
			return &identity.Identity{Subject: "alice", Email: "alice@example.com"}, nil
		}

		return nil, local.ErrInvalidCredentials
	}))

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	// 1. POST /login/pass/local with good creds
	body := strings.NewReader(`{"username":"alice","password":"secret"}`)
	req := httptest.NewRequest("POST", "/login/pass/local", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetPathValue("strategy", "local")

	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	cookies := rec.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "auth_session" {
			sessionCookie = c

			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("expected auth_session cookie, got %+v", cookies)
	}
	if sessionCookie.Value == "" {
		t.Fatalf("empty session cookie value")
	}

	// 2. GET /login/me with the cookie
	req2 := httptest.NewRequest("GET", "/login/me", nil)
	req2.AddCookie(sessionCookie)
	rec2 := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("me: expected 200, got %d body=%s", rec2.Code, rec2.Body.String())
	}

	var got identity.Identity
	if err := json.Unmarshal(rec2.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode /me: %v", err)
	}
	if got.Subject != "alice" || got.Email != "alice@example.com" {
		t.Fatalf("/me identity wrong: %+v", got)
	}
	if got.Provider != "local" {
		t.Fatalf("provider not set: %q", got.Provider)
	}

	// 3. POST /logout clears cookie
	req3 := httptest.NewRequest("POST", "/logout", nil)
	req3.AddCookie(sessionCookie)
	rec3 := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusNoContent {
		t.Fatalf("logout: expected 204, got %d", rec3.Code)
	}

	// 4. /login/me with the now-revoked cookie returns 401
	req4 := httptest.NewRequest("GET", "/login/me", nil)
	req4.AddCookie(sessionCookie)
	rec4 := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec4, req4)

	if rec4.Code != http.StatusUnauthorized {
		t.Fatalf("me after logout: expected 401, got %d", rec4.Code)
	}
}

func TestInfoListsStrategies(t *testing.T) {
	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true, Title: "Hello"}})

	a.Strategy(local.New("local", func(_ context.Context, _, _ string) (*identity.Identity, error) {
		return nil, local.ErrInvalidCredentials
	}, local.WithLabel("Local"), local.WithPriority(0)))

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	req := httptest.NewRequest("GET", "/login/info", nil)
	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("info: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var info struct {
		Title      string `json:"title"`
		Strategies []struct {
			Name  string `json:"name"`
			Kind  string `json:"kind"`
			Label string `json:"label"`
			URL   string `json:"url"`
		} `json:"strategies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("decode info: %v", err)
	}

	if info.Title != "Hello" {
		t.Errorf("title: %q", info.Title)
	}
	if len(info.Strategies) != 1 {
		t.Fatalf("expected 1 strategy, got %d", len(info.Strategies))
	}
	if info.Strategies[0].Name != "local" || info.Strategies[0].Kind != "password" {
		t.Errorf("strategy: %+v", info.Strategies[0])
	}
	if info.Strategies[0].URL != "/login/pass/local" {
		t.Errorf("url: got %q, want /login/pass/local", info.Strategies[0].URL)
	}
}
