package users_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/oauthserver"
	"github.com/rakunlabs/ada/middleware/auth/password"
	"github.com/rakunlabs/ada/middleware/auth/strategy/local"
	"github.com/rakunlabs/ada/_examples/authkit/users"
)

// fast keeps tests quick; production uses password.New().
var fast = &password.PBKDF2{Iterations: 1000}

func newService(t *testing.T, mutate func(*users.Config)) *users.Service {
	t.Helper()

	cfg := users.Config{
		Hasher: fast,
		Roles: []users.Role{
			{Name: "admin", Permissions: []string{"*"}},
			{Name: "editor", Permissions: []string{"reports:*", "users:read"}},
			{Name: "user"},
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}

	s, err := users.New(cfg, users.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Init(context.Background()); err != nil {
		t.Fatal(err)
	}

	return s
}

func TestBootstrapAndLogin(t *testing.T) {
	ctx := context.Background()
	s := newService(t, func(c *users.Config) {
		c.Bootstrap = users.Bootstrap{Username: "root", Password: "rootpassword"}
	})

	if s.NoUsers(ctx) || s.SignupOpen(ctx) {
		t.Fatal("bootstrap admin must close signup")
	}

	id, err := s.Verifier()(ctx, "ROOT", "rootpassword")
	if err != nil || !id.HasRole("admin") || !s.Can(id, "anything") {
		t.Fatalf("login: %+v %v", id, err)
	}

	if _, err := s.Verifier()(ctx, "root", "wrong"); !errors.Is(err, local.ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := s.Verifier()(ctx, "nobody", "whatever"); !errors.Is(err, local.ErrInvalidCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestFirstUserSignupBecomesAdmin(t *testing.T) {
	ctx := context.Background()
	s := newService(t, nil)

	if !s.SignupOpen(ctx) {
		t.Fatal("signup must be open with no users")
	}

	id, err := s.Registrar()(ctx, local.RegisterRequest{Username: "first", Password: "longenough"})
	if err != nil || !id.HasRole("admin") {
		t.Fatalf("first signup: %+v %v", id, err)
	}

	if s.SignupOpen(ctx) {
		t.Fatal("signup must close after the first user")
	}
	if _, err := s.Registrar()(ctx, local.RegisterRequest{Username: "second", Password: "longenough"}); !errors.Is(err, local.ErrInvalidInput) {
		t.Fatalf("second signup: %v", err)
	}
}

func TestOpenSignupGetsDefaultRole(t *testing.T) {
	ctx := context.Background()
	s := newService(t, func(c *users.Config) {
		c.Signup = true
		c.Bootstrap = users.Bootstrap{Username: "root", Password: "rootpassword"}
	})

	id, err := s.Registrar()(ctx, local.RegisterRequest{Username: "bob", Password: "longenough", Extras: map[string]string{"email": "bob@example.com"}})
	if err != nil || id.HasRole("admin") || !id.HasRole("user") || id.Email != "bob@example.com" {
		t.Fatalf("signup: %+v %v", id, err)
	}

	if _, err := s.Registrar()(ctx, local.RegisterRequest{Username: "Bob", Password: "longenough"}); !errors.Is(err, local.ErrUserExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := s.Registrar()(ctx, local.RegisterRequest{Username: "carol", Password: "short"}); !errors.Is(err, local.ErrInvalidInput) {
		t.Fatalf("short password: %v", err)
	}
}

func TestPermissions(t *testing.T) {
	s := newService(t, nil)

	editor := &identity.Identity{Subject: "e", Roles: []string{"editor"}}
	if !s.Can(editor, "reports:read") || !s.Can(editor, "reports:delete") || !s.Can(editor, "users:read") {
		t.Fatal("editor should hold reports:* and users:read")
	}
	if s.Can(editor, "users:write") || s.Can(nil, "reports:read") {
		t.Fatal("editor must not write users; nil holds nothing")
	}

	if _, err := users.New(users.Config{Roles: []users.Role{{Name: "admin"}}}, users.NewMemoryStore()); err == nil {
		t.Fatal("an admin role without users:write must be rejected")
	}
}

func TestLastAdminProtection(t *testing.T) {
	ctx := context.Background()
	s := newService(t, nil)

	admin, _ := s.Create(ctx, users.CreateRequest{Username: "admin", Password: "longenough", Roles: []string{"admin"}})

	off := true
	if _, err := s.Update(ctx, admin.ID, users.UpdateRequest{Disabled: &off}); !errors.Is(err, users.ErrLastAdmin) {
		t.Fatalf("disable last admin: %v", err)
	}
	if err := s.Delete(ctx, admin.ID); !errors.Is(err, users.ErrLastAdmin) {
		t.Fatalf("delete last admin: %v", err)
	}

	roles := []string{"user"}
	if _, err := s.Update(ctx, admin.ID, users.UpdateRequest{Roles: &roles}); !errors.Is(err, users.ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}

	if _, err := s.Create(ctx, users.CreateRequest{Username: "admin2", Password: "longenough", Roles: []string{"admin"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(ctx, admin.ID, users.UpdateRequest{Roles: &roles}); err != nil {
		t.Fatalf("demote with another admin: %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	ctx := context.Background()
	s := newService(t, nil)

	u, _ := s.Create(ctx, users.CreateRequest{Username: "amy", Password: "firstpassword"})

	if err := s.ChangePassword(ctx, u.ID, "wrong", "secondpassword"); !errors.Is(err, users.ErrInvalid) {
		t.Fatalf("wrong current: %v", err)
	}
	if err := s.ChangePassword(ctx, u.ID, "firstpassword", "secondpassword"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verifier()(ctx, "amy", "secondpassword"); err != nil {
		t.Fatal("new password rejected")
	}
}

func TestFreshAndIdentityHook(t *testing.T) {
	ctx := context.Background()
	s := newService(t, nil)

	_, _ = s.Create(ctx, users.CreateRequest{Username: "root", Password: "longenough", Roles: []string{"admin"}})
	u, _ := s.Create(ctx, users.CreateRequest{Username: "eve", Password: "longenough", Roles: []string{"editor"}})
	stale := &identity.Identity{Subject: u.ID, Roles: []string{"editor"}, Scopes: []string{"mcp"}, Provider: "oauth"}

	handler := s.Fresh(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(identity.FromContext(r.Context()))
	}))

	call := func(id *identity.Identity) (*httptest.ResponseRecorder, *identity.Identity) {
		req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(identity.WithContext(ctx, id))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		var got identity.Identity
		_ = json.Unmarshal(rec.Body.Bytes(), &got)

		return rec, &got
	}

	roles := []string{"user"}
	_, _ = s.Update(ctx, u.ID, users.UpdateRequest{Roles: &roles})

	rec, got := call(stale)
	if rec.Code != http.StatusOK || got.HasRole("editor") || !got.HasRole("user") || got.Scopes[0] != "mcp" || got.Provider != "oauth" {
		t.Fatalf("fresh: %d %+v", rec.Code, got)
	}

	// A foreign identity passes through.
	if rec, _ := call(&identity.Identity{Subject: "api-key-client"}); rec.Code != http.StatusOK {
		t.Fatalf("passthrough: %d", rec.Code)
	}

	off := true
	_, _ = s.Update(ctx, u.ID, users.UpdateRequest{Disabled: &off})
	if rec, _ := call(stale); rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled: %d", rec.Code)
	}

	if _, err := s.IdentityHook()(ctx, &oauthserver.Token{Identity: stale}); !errors.Is(err, oauthserver.ErrAccessDenied) {
		t.Fatalf("hook for disabled user: %v", err)
	}
}

type testMux struct{ *http.ServeMux }

func (m testMux) HandleWithMethod(method, p string, h http.HandlerFunc, mw ...func(http.Handler) http.Handler) {
	var handler http.Handler = h
	for i := len(mw) - 1; i >= 0; i-- {
		handler = mw[i](handler)
	}

	m.Handle(method+" "+p, handler)
}

func TestAdminAPI(t *testing.T) {
	ctx := context.Background()
	s := newService(t, nil)

	root, _ := s.Create(ctx, users.CreateRequest{Username: "root", Password: "longenough", Roles: []string{"admin"}})
	ed, _ := s.Create(ctx, users.CreateRequest{Username: "ed", Password: "longenough", Roles: []string{"editor"}})

	// The test "session" is the X-User header.
	as := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, err := s.Store().GetUser(r.Context(), r.Header.Get("X-User"))
			if err != nil {
				http.Error(w, "no", http.StatusUnauthorized)

				return
			}

			next.ServeHTTP(w, r.WithContext(identity.WithContext(r.Context(), s.Identity(u))))
		})
	}

	mux := testMux{http.NewServeMux()}
	s.MountAdmin(mux, "/admin/users", as)
	s.MountSelf(mux, "/account", as)
	s.MountAdminUI(mux, "/admin/users/ui", users.UIOptions{API: "/admin/users", AccountAPI: "/account"}, as)

	do := func(user, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("X-User", user)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		return rec
	}

	if rec := do(ed.ID, http.MethodGet, "/admin/users", ""); rec.Code != http.StatusOK {
		t.Fatalf("editor list: %d", rec.Code)
	}
	if rec := do(ed.ID, http.MethodPost, "/admin/users", `{"username":"x","password":"longenough"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("editor create: %d", rec.Code)
	}

	rec := do(root.ID, http.MethodPost, "/admin/users", `{"username":"newbie","password":"longenough","roles":["editor"]}`)
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), "password") {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}

	var created users.User
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	if rec := do(root.ID, http.MethodPatch, "/admin/users/"+created.ID, `{"roles":["nope"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad role: %d", rec.Code)
	}
	if rec := do(root.ID, http.MethodDelete, "/admin/users/"+root.ID, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("self delete: %d", rec.Code)
	}
	if rec := do(root.ID, http.MethodDelete, "/admin/users/"+created.ID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}

	if rec := do(root.ID, http.MethodGet, "/admin/users/roles", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "editor") {
		t.Fatalf("roles: %d", rec.Code)
	}

	rec = do(ed.ID, http.MethodGet, "/account", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"reports:*"`) {
		t.Fatalf("self: %d %s", rec.Code, rec.Body.String())
	}

	if rec := do(ed.ID, http.MethodPost, "/account/password", `{"current":"longenough","password":"evenlongerone"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("change password: %d %s", rec.Code, rec.Body.String())
	}

	rec = do(ed.ID, http.MethodGet, "/admin/users/ui/", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `content="/admin/users"`) || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("ui: %d", rec.Code)
	}

	if rec := do("nobody", http.MethodGet, "/admin/users/ui/", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("ui anonymous: %d", rec.Code)
	}
}

func TestDeletedUserSessionIsRefused(t *testing.T) {
	ctx := context.Background()
	s := newService(t, nil)

	_, _ = s.Create(ctx, users.CreateRequest{Username: "root", Password: "longenough", Roles: []string{"admin"}})
	u, _ := s.Create(ctx, users.CreateRequest{Username: "gone", Password: "longenough", Roles: []string{"admin"}})

	// The identity a session would hold, captured at login.
	session := s.Identity(u)

	if err := s.Delete(ctx, u.ID); err != nil {
		t.Fatal(err)
	}

	handler := s.Fresh(true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(identity.WithContext(ctx, session)))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("deleted user's session: %d, want 401", rec.Code)
	}

	if _, err := s.IdentityHook()(ctx, &oauthserver.Token{Identity: session}); !errors.Is(err, oauthserver.ErrAccessDenied) {
		t.Fatalf("deleted user's token: %v", err)
	}

	// An SSO identity is not ours and passes.
	sso := &identity.Identity{Subject: "google|123", Provider: "google"}
	if got, err := s.IdentityHook()(ctx, &oauthserver.Token{Identity: sso}); err != nil || got.Subject != "google|123" {
		t.Fatalf("sso token: %+v %v", got, err)
	}
}

func TestNoPrivilegeEscalation(t *testing.T) {
	ctx := context.Background()
	s := newService(t, func(c *users.Config) {
		c.Roles = append(c.Roles, users.Role{Name: "manager", Permissions: []string{"users:*"}})
	})

	admin, _ := s.Create(ctx, users.CreateRequest{Username: "root", Password: "longenough", Roles: []string{"admin"}})
	mgr, _ := s.Create(ctx, users.CreateRequest{Username: "mgr", Password: "longenough", Roles: []string{"manager"}})
	plain, _ := s.Create(ctx, users.CreateRequest{Username: "joe", Password: "longenough", Roles: []string{"user"}})

	actor := s.Identity(mgr)
	adminRole := []string{"admin"}
	pw := "takenover1"

	if _, err := s.UpdateAs(ctx, actor, mgr.ID, users.UpdateRequest{Roles: &adminRole}); !errors.Is(err, users.ErrForbidden) {
		t.Fatalf("self-promotion: %v", err)
	}
	if _, err := s.UpdateAs(ctx, actor, admin.ID, users.UpdateRequest{Password: &pw}); !errors.Is(err, users.ErrForbidden) {
		t.Fatalf("admin password reset: %v", err)
	}
	if err := s.DeleteAs(ctx, actor, admin.ID); !errors.Is(err, users.ErrForbidden) {
		t.Fatalf("delete admin: %v", err)
	}
	if _, err := s.CreateAs(ctx, actor, users.CreateRequest{Username: "evil", Password: "longenough", Roles: adminRole}); !errors.Is(err, users.ErrForbidden) {
		t.Fatalf("create admin: %v", err)
	}

	// What the manager may do: manage plain users.
	if _, err := s.UpdateAs(ctx, actor, plain.ID, users.UpdateRequest{Password: &pw}); err != nil {
		t.Fatalf("manage plain user: %v", err)
	}
}

func TestLastAdminWithoutPassword(t *testing.T) {
	ctx := context.Background()
	s := newService(t, nil)

	admin, _ := s.Create(ctx, users.CreateRequest{Username: "root", Password: "longenough", Roles: []string{"admin"}})

	empty := ""
	if _, err := s.Update(ctx, admin.ID, users.UpdateRequest{Password: &empty}); !errors.Is(err, users.ErrLastAdmin) {
		t.Fatalf("removing the last admin's password: %v", err)
	}
}

func TestConcurrentFirstSignup(t *testing.T) {
	ctx := context.Background()
	s := newService(t, nil)

	var wg sync.WaitGroup

	admins := make(chan bool, 8)
	for i := range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			id, err := s.Registrar()(ctx, local.RegisterRequest{Username: fmt.Sprintf("u%d", i), Password: "longenough"})
			admins <- err == nil && id.HasRole("admin")
		}()
	}

	wg.Wait()
	close(admins)

	n := 0
	for a := range admins {
		if a {
			n++
		}
	}

	if n != 1 {
		t.Fatalf("%d admins from concurrent first signup, want 1", n)
	}
}

func TestAdminAPIRejectsTokensAndCrossSite(t *testing.T) {
	ctx := context.Background()
	s := newService(t, nil)

	root, _ := s.Create(ctx, users.CreateRequest{Username: "root", Password: "longenough", Roles: []string{"admin"}})

	asToken := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := s.Identity(root)
			id.Claims[oauthserver.ClaimTokenID] = "tok"
			next.ServeHTTP(w, r.WithContext(identity.WithContext(r.Context(), id)))
		})
	}
	asSession := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(identity.WithContext(r.Context(), s.Identity(root))))
		})
	}

	tokenMux := testMux{http.NewServeMux()}
	s.MountAdmin(tokenMux, "/u", asToken)

	rec := httptest.NewRecorder()
	tokenMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/u", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("token on admin API: %d", rec.Code)
	}

	mux := testMux{http.NewServeMux()}
	s.MountAdmin(mux, "/u", asSession)

	post := httptest.NewRequest(http.MethodPost, "/u", strings.NewReader(`{"username":"x1","password":"longenough"}`))
	post.Header.Set("Content-Type", "text/plain")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, post)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain create: %d", rec.Code)
	}

	post = httptest.NewRequest(http.MethodPost, "/u", strings.NewReader(`{"username":"x2","password":"longenough"}`))
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("Sec-Fetch-Site", "same-site")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, post)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("same-site create: %d", rec.Code)
	}
}

func TestAttributesCannotOverrideClaims(t *testing.T) {
	s := newService(t, nil)

	id := s.Identity(&users.User{ID: "x", Username: "x", Roles: []string{"user"}, Attributes: map[string]any{"permissions": []string{"*"}, "team": "a"}})
	if s.Can(id, "anything") || id.Claims["team"] != "a" {
		t.Fatalf("claims: %v", id.Claims)
	}
	if perms, _ := id.Claims[users.ClaimPermissions].([]string); len(perms) != 0 {
		t.Fatalf("attribute replaced permissions: %v", perms)
	}
}
