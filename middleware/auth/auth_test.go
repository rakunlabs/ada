package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/issuer"
	"github.com/rakunlabs/ada/middleware/auth/issuer/backend"
	"github.com/rakunlabs/ada/middleware/auth/session"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
	"github.com/rakunlabs/ada/middleware/auth/strategy/local"
	"github.com/rakunlabs/ada/middleware/auth/strategy/oauth2"
)

// fakeMux is a minimal in-memory mux that satisfies auth.Mux for tests.
type fakeMux struct {
	mu     *http.ServeMux
	routes []string
}

func newFakeMux() *fakeMux { return &fakeMux{mu: http.NewServeMux()} }

// HandleWithMethod mirrors ada.Mux: an empty method registers a catch-all
// handler, otherwise the route is scoped to that method.
func (f *fakeMux) HandleWithMethod(method, p string, h http.HandlerFunc, _ ...func(http.Handler) http.Handler) {
	if method == "" {
		f.routes = append(f.routes, p)

		// ada.Mux spells a subtree as "/x/*"; http.ServeMux spells it "/x/" and
		// would otherwise treat the star as a literal path segment.
		if strings.HasSuffix(p, "/*") {
			f.mu.HandleFunc(strings.TrimSuffix(p, "*"), h)

			return
		}

		f.mu.HandleFunc(p, h)

		return
	}

	f.routes = append(f.routes, method+" "+p)
	f.mu.HandleFunc(method+" "+p, h)
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

func TestUIConfigOwnsThemeSnapshots(t *testing.T) {
	initialTheme := map[string]string{"primary": "blue"}
	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true, Theme: initialTheme}})
	initialTheme["primary"] = "caller-mutated"

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	mux := newFakeMux()
	a.Mount(mux)

	assertThemeValue(t, mux, "blue")

	updatedTheme := map[string]string{"primary": "green"}
	a.SetUI(auth.UIConfig{Theme: updatedTheme})
	updatedTheme["primary"] = "caller-mutated-again"
	assertThemeValue(t, mux, "green")
}

func assertThemeValue(t *testing.T, mux *fakeMux, want string) {
	t.Helper()

	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login/info", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("info: %d %s", rec.Code, rec.Body)
	}

	var response struct {
		Theme map[string]string `json:"theme"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode info: %v", err)
	}
	if got := response.Theme["primary"]; got != want {
		t.Fatalf("theme primary = %q, want %q", got, want)
	}
}

func TestNewOwnsCookieNameHostSlice(t *testing.T) {
	hosts := []session.HostCookieName{{Host: "app.example", CookieName: "app_session"}}
	a := auth.New(auth.Config{
		UI:              auth.UIConfig{ExternalFolder: true},
		CookieNameHosts: hosts,
	})
	hosts[0] = session.HostCookieName{Host: "mutated.example", CookieName: "mutated"}

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "https://app.example/private", nil)
	if got := a.Session().CookieNameFor(r); got != "app_session" {
		t.Fatalf("cookie name = %q, want app_session", got)
	}
}

func TestInfoOwnsStrategyFieldSlices(t *testing.T) {
	fields := []strategy.Field{
		{Name: "user", Label: "User", Type: "text"},
		{Name: "secret", Label: "Secret", Type: "password"},
	}
	localStrategy := local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
		return nil, local.ErrInvalidCredentials
	}, local.WithFields(fields...))
	fields[0].Label = "caller-mutated"
	descriptor := localStrategy.Descriptor()
	descriptor.Fields[0].Label = "descriptor-mutated"

	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}}).Strategy(localStrategy)
	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	mux := newFakeMux()
	a.Mount(mux)

	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login/info", nil))
	var response struct {
		Strategies []struct {
			Fields []strategy.Field `json:"fields"`
		} `json:"strategies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode info: %v", err)
	}
	if got := response.Strategies[0].Fields[0].Label; got != "User" {
		t.Fatalf("field label = %q, want User", got)
	}
}

type internalErrorStrategy struct{ secret string }

func (s internalErrorStrategy) Name() string { return "broken" }
func (s internalErrorStrategy) Descriptor() strategy.Descriptor {
	return strategy.Descriptor{Name: s.Name(), Kind: "custom", Label: "Broken"}
}
func (s internalErrorStrategy) Login(http.ResponseWriter, *http.Request) (*identity.Identity, strategy.Outcome, error) {
	return nil, strategy.OutcomeFailed, errors.New(s.secret)
}
func (s internalErrorStrategy) Register(http.ResponseWriter, *http.Request) (*identity.Identity, strategy.Outcome, error) {
	return nil, strategy.OutcomeFailed, errors.New(s.secret)
}
func (internalErrorStrategy) Logout(context.Context, *identity.Identity) error { return nil }

type failingIssueIssuer struct {
	issuer.Issuer
	secret string
}

type failingResolveIssuer struct {
	issuer.Issuer
	secret string
}

func (i failingResolveIssuer) Resolve(context.Context, string) (*issuer.Pair, error) {
	return nil, errors.New(i.secret)
}

func (i failingIssueIssuer) Issue(context.Context, *identity.Identity) (*issuer.Pair, error) {
	return nil, errors.New(i.secret)
}

func TestInternalErrorsAreNotReturnedToClients(t *testing.T) {
	const secret = "postgres://admin:password@internal.example/users"

	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}}).
		Strategy(internalErrorStrategy{secret: secret})
	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	mux := newFakeMux()
	a.Mount(mux)

	for _, target := range []string{"/login/pass/broken", "/login/register/broken"} {
		rec := httptest.NewRecorder()
		mux.mu.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, target, nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%s: code = %d", target, rec.Code)
		}
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("%s leaked internal error: %s", target, rec.Body)
		}
	}

	base := issuer.NewDefault(backend.NewMemory(), issuer.Config{})
	a = auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}}).
		WithIssuer(failingIssueIssuer{Issuer: base, secret: secret}).
		Strategy(local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
			return &identity.Identity{Subject: "alice"}, nil
		}))
	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init failing issuer auth: %v", err)
	}
	mux = newFakeMux()
	a.Mount(mux)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login/pass/local", strings.NewReader(`{"username":"alice","password":"pw"}`))
	r.Header.Set("Content-Type", "application/json")
	mux.mu.ServeHTTP(rec, r)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("issue response leaked internal error: %d %s", rec.Code, rec.Body)
	}

	a = auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}}).
		WithIssuer(failingResolveIssuer{Issuer: base, secret: secret})
	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init failing resolve auth: %v", err)
	}
	mux = newFakeMux()
	a.Mount(mux)
	for _, request := range []struct {
		method string
		target string
	}{
		{method: http.MethodPost, target: "/login/refresh"},
		{method: http.MethodGet, target: "/login/me"},
	} {
		rec = httptest.NewRecorder()
		r = httptest.NewRequest(request.method, request.target, nil)
		r.AddCookie(&http.Cookie{Name: "auth_session", Value: "session"})
		mux.mu.ServeHTTP(rec, r)
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("%s leaked backend error: %s", request.target, rec.Body)
		}
	}
}

func TestRegister_AutoLogin_IssuesSessionCookie(t *testing.T) {
	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}})

	// Registrar that always succeeds and returns a new identity.
	reg := func(_ context.Context, req local.RegisterRequest) (*identity.Identity, error) {
		return &identity.Identity{Subject: req.Username, Email: req.Extras["email"]}, nil
	}

	a.Strategy(local.New("local",
		func(_ context.Context, _, _ string) (*identity.Identity, error) {
			return nil, local.ErrInvalidCredentials
		},
		local.WithRegistrar(reg),
		local.WithAutoLogin(true),
	))

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	body := strings.NewReader(`{"username":"carol","password":"s3cret!","password_confirm":"s3cret!","email":"carol@example.com"}`)
	req := httptest.NewRequest("POST", "/login/register/local", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.SetPathValue("strategy", "local")

	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("register: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "auth_session" {
			sessionCookie = c

			break
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatalf("expected auth_session cookie after auto-login signup, got %+v", rec.Result().Cookies())
	}
}

func TestRefreshResponseDoesNotExposeSessionID(t *testing.T) {
	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}}).
		Strategy(local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
			return &identity.Identity{Subject: "alice"}, nil
		}))
	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/login/pass/local", strings.NewReader(`{"username":"alice","password":"pw"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("Accept", "application/json")
	mux.mu.ServeHTTP(loginRec, loginReq)

	var sessionCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "auth_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("login did not issue a session cookie")
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login/refresh", nil)
	r.AddCookie(sessionCookie)
	mux.mu.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body)
	}

	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, exposed := response["session_id"]; exposed {
		t.Fatalf("refresh exposed session_id: %s", rec.Body)
	}
	if response["identity"] == nil {
		t.Fatalf("refresh omitted identity: %s", rec.Body)
	}
}

type authReplicaConflictIssuer struct {
	*issuer.Default
	winner *issuer.Default
	once   sync.Once
}

func (i *authReplicaConflictIssuer) Refresh(ctx context.Context, sessionID, refreshToken string) (*issuer.Pair, error) {
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

func TestRefreshRecoversFromReplicaConflict(t *testing.T) {
	memory := backend.NewMemory()
	first := issuer.NewDefault(memory, issuer.Config{})
	second := issuer.NewDefault(memory, issuer.Config{})
	pair, err := first.Issue(context.Background(), &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	iss := &authReplicaConflictIssuer{Default: first, winner: second}
	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}}).WithIssuer(iss)
	if err := a.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	mux := newFakeMux()
	a.Mount(mux)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login/refresh", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: pair.SessionID})
	mux.mu.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("refresh code = %d, want 200 (%s)", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), pair.Refresh.Value) {
		t.Fatalf("refresh response exposed a bearer token: %s", rec.Body)
	}
}

type conflictRevokeIssuer struct {
	issuer.Issuer
	calls atomic.Int32
}

func (i *conflictRevokeIssuer) Revoke(context.Context, string) error {
	i.calls.Add(1)

	return issuer.ErrTransactionConflict
}

func TestLogoutConflictFailsClosedAndKeepsCookie(t *testing.T) {
	base := issuer.NewDefault(backend.NewMemory(), issuer.Config{})
	pair, err := base.Issue(context.Background(), &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	iss := &conflictRevokeIssuer{Issuer: base}
	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}}).WithIssuer(iss)
	if err := a.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	mux := newFakeMux()
	a.Mount(mux)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: pair.SessionID})
	mux.mu.ServeHTTP(rec, r)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("logout code = %d, want 503 (%s)", rec.Code, rec.Body)
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("failed logout cleared client cookies: %v", got)
	}
	if _, err := base.Resolve(context.Background(), pair.SessionID); err != nil {
		t.Fatalf("failed logout removed server session: %v", err)
	}
	if got := iss.calls.Load(); got != 1 {
		t.Fatalf("custom issuer revoke calls = %d, want 1", got)
	}
}

func TestRegister_NoAutoLogin_ReturnsFlag(t *testing.T) {
	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}})

	reg := func(_ context.Context, req local.RegisterRequest) (*identity.Identity, error) {
		return &identity.Identity{Subject: req.Username}, nil
	}

	a.Strategy(local.New("local",
		func(_ context.Context, _, _ string) (*identity.Identity, error) {
			return nil, local.ErrInvalidCredentials
		},
		local.WithRegistrar(reg),
	))

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	body := strings.NewReader(`{"username":"dan","password":"s3cret!","password_confirm":"s3cret!"}`)
	req := httptest.NewRequest("POST", "/login/register/local", body)
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("strategy", "local")

	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	for _, c := range rec.Result().Cookies() {
		if c.Name == "auth_session" {
			t.Fatalf("did not expect session cookie without auto-login, got %+v", c)
		}
	}

	var body2 map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body2); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body2["auto_login"] != false {
		t.Errorf("expected auto_login=false, got %v", body2["auto_login"])
	}
}

func TestRegister_StrategyWithoutRegistrar_Is404(t *testing.T) {
	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}})

	a.Strategy(local.New("local", func(_ context.Context, _, _ string) (*identity.Identity, error) {
		return nil, local.ErrInvalidCredentials
	}))

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	body := strings.NewReader(`{"username":"x","password":"y"}`)
	req := httptest.NewRequest("POST", "/login/register/local", body)
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("strategy", "local")

	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for strategy without registrar, got %d", rec.Code)
	}
}

func TestInfo_IncludesRegisterAndSignupFirst(t *testing.T) {
	a := auth.New(auth.Config{UI: auth.UIConfig{
		ExternalFolder: true,
		Title:          "Hello",
		SignupFirst:    true,
	}})

	reg := func(_ context.Context, _ local.RegisterRequest) (*identity.Identity, error) {
		return nil, nil
	}

	a.Strategy(local.New("local",
		func(_ context.Context, _, _ string) (*identity.Identity, error) {
			return nil, local.ErrInvalidCredentials
		},
		local.WithRegistrar(reg),
	))

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	req := httptest.NewRequest("GET", "/login/info", nil)
	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, req)

	var info struct {
		SignupFirst bool `json:"signup_first"`
		Strategies  []struct {
			Name     string `json:"name"`
			Register *struct {
				URL    string `json:"url"`
				Fields []struct {
					Name string `json:"name"`
				} `json:"fields"`
			} `json:"register"`
		} `json:"strategies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !info.SignupFirst {
		t.Error("expected signup_first=true in info response")
	}
	if len(info.Strategies) != 1 {
		t.Fatalf("expected 1 strategy, got %d", len(info.Strategies))
	}
	if info.Strategies[0].Register == nil {
		t.Fatal("expected register block on strategy")
	}
	if info.Strategies[0].Register.URL != "/login/register/local" {
		t.Errorf("register url: got %q, want /login/register/local", info.Strategies[0].Register.URL)
	}
	if len(info.Strategies[0].Register.Fields) != 3 {
		t.Errorf("expected 3 default register fields, got %d", len(info.Strategies[0].Register.Fields))
	}
}

// TestBasePath_NonRootMountsUnderPrefix verifies that a non-root Base such as
// "/api/v1/" produces correctly-separated route paths (e.g. /api/v1/login/info)
// rather than the concatenated form /api/v1login/info. It also exercises
// inputs missing a trailing slash ("/api/v1") and a leading slash ("api/v1/")
// to confirm the normalizer is robust.
func TestBasePath_NonRootMountsUnderPrefix(t *testing.T) {
	cases := []struct {
		name string
		base string
	}{
		{"with trailing slash", "/api/v1/"},
		{"no trailing slash", "/api/v1"},
		{"no leading slash", "api/v1/"},
		{"bare", "api/v1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := auth.New(auth.Config{
				Base: tc.base,
				UI:   auth.UIConfig{ExternalFolder: true},
			})
			a.Strategy(local.New("local",
				func(_ context.Context, _, _ string) (*identity.Identity, error) {
					return nil, local.ErrInvalidCredentials
				},
			))
			if err := a.Init(context.Background()); err != nil {
				t.Fatalf("init: %v", err)
			}

			mux := newFakeMux()
			a.Mount(mux)

			wantRoutes := []string{
				"GET /api/v1/login/info",
				"GET /api/v1/login/me",
				"POST /api/v1/logout",
			}
			for _, want := range wantRoutes {
				found := false
				for _, r := range mux.routes {
					if r == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("route %q not registered; got %v", want, mux.routes)
				}
			}

			// Hit /login/info and confirm the strategy login URL is also
			// correctly rooted under the base.
			req := httptest.NewRequest("GET", "/api/v1/login/info", nil)
			rec := httptest.NewRecorder()
			mux.mu.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /api/v1/login/info: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
			}
			var info struct {
				Strategies []struct {
					LoginURL string `json:"url"`
				} `json:"strategies"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
				t.Fatalf("decode info: %v", err)
			}
			if len(info.Strategies) != 1 {
				t.Fatalf("expected 1 strategy, got %d", len(info.Strategies))
			}
			if got, want := info.Strategies[0].LoginURL, "/api/v1/login/pass/local"; got != want {
				t.Errorf("login url: got %q, want %q", got, want)
			}
		})
	}
}

// TestRequire_UnauthenticatedRedirectsToLoginUI verifies that session.Require
// on a guarded route redirects to {Base}login (the login UI), not the bare
// base prefix.
func TestRequire_UnauthenticatedRedirectsToLoginUI(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		wantPath string
	}{
		{"root base", "/", "/login"},
		{"nested base", "/api/v1/", "/api/v1/login"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := auth.New(auth.Config{
				Base: tc.base,
				UI:   auth.UIConfig{ExternalFolder: true},
			})
			a.Strategy(local.New("local",
				func(_ context.Context, _, _ string) (*identity.Identity, error) {
					return nil, local.ErrInvalidCredentials
				},
			))
			if err := a.Init(context.Background()); err != nil {
				t.Fatalf("init: %v", err)
			}

			guarded := a.Require()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("GET", "/whatever", nil)
			rec := httptest.NewRecorder()
			guarded.ServeHTTP(rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("expected 303, got %d body=%s", rec.Code, rec.Body.String())
			}

			loc := rec.Header().Get("Location")
			if !strings.HasPrefix(loc, tc.wantPath) {
				t.Errorf("redirect target: got %q, want prefix %q", loc, tc.wantPath)
			}
		})
	}
}

// TestMount_AutoWiresOAuth2CallbackBasePath verifies that Auth.Mount pushes
// the resolved callback base path ({cfg.Base}login/callback) into any
// registered OAuth2 strategy that left CallbackBasePath empty.
func TestMount_AutoWiresOAuth2CallbackBasePath(t *testing.T) {
	a := auth.New(auth.Config{
		Base: "/api/v1/",
		UI:   auth.UIConfig{ExternalFolder: true},
	})

	oa := oauth2.New("google", oauth2.Config{
		ClientID: "client",
		AuthURL:  "https://idp.example.com/authorize",
	}, oauth2.Options{
		CallbackBaseURL: "https://app.example.com",
		// CallbackBasePath intentionally empty so Mount auto-wires it.
	})
	a.Strategy(oa)

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	// Initiate OAuth2: GET /api/v1/login/pass/google without ?code= → 307 to AuthURL.
	req := httptest.NewRequest("GET", "/api/v1/login/pass/google", nil)
	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d body=%s", rec.Code, rec.Body.String())
	}

	loc := rec.Header().Get("Location")
	wantSub := "redirect_uri=https%3A%2F%2Fapp.example.com%2Fapi%2Fv1%2Flogin%2Fcallback%2Fgoogle"
	if !strings.Contains(loc, wantSub) {
		t.Errorf("redirect Location should contain %q, got %q", wantSub, loc)
	}
}

// The login page reads redirect_path out of window.location and navigates to
// it. Validating only the copy we echo back is not enough — the browser never
// asks us about the one in its address bar — so an unsafe value must be
// stripped before the page can see it.
func TestUIStripsUnsafeRedirectPath(t *testing.T) {
	a := auth.New(auth.Config{})

	a.Strategy(local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
		return nil, local.ErrInvalidCredentials
	}))

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/login/?redirect_path=https%3A%2F%2Fevil.example%2F", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("code = %d, want a redirect stripping the parameter", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "evil.example") {
		t.Fatalf("unsafe redirect_path survived: %q", loc)
	}

	// A safe value is left alone: the page is served, not redirected.
	rec = httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/login/?redirect_path=%2Fdashboard", nil))

	if rec.Code == http.StatusFound {
		t.Fatalf("a same-origin redirect_path should not be stripped: %q", rec.Header().Get("Location"))
	}
}

// A successful login must not echo an attacker-supplied absolute URL back to
// the page that is about to navigate to it.
func TestLoginResponseDropsUnsafeRedirectPath(t *testing.T) {
	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}})

	a.Strategy(local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
		return &identity.Identity{Subject: "alice"}, nil
	}))

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost,
		"/login/pass/local?redirect_path=https%3A%2F%2Fevil.example%2F",
		strings.NewReader(`{"username":"a","password":"b"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")

	mux.mu.ServeHTTP(rec, r)

	if strings.Contains(rec.Body.String(), "evil.example") {
		t.Fatalf("response echoes an off-site redirect: %s", rec.Body)
	}
}
