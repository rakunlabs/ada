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
	"github.com/rakunlabs/ada/middleware/auth/strategy/oauth2"
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

	// ada.Mux spells a subtree as "/x/*"; http.ServeMux spells it "/x/" and
	// would otherwise treat the star as a literal path segment.
	if strings.HasSuffix(p, "/*") {
		f.mu.HandleFunc(strings.TrimSuffix(p, "*"), h)

		return
	}

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

			if rec.Code != http.StatusTemporaryRedirect {
				t.Fatalf("expected 307, got %d body=%s", rec.Code, rec.Body.String())
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
