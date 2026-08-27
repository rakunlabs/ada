package authz_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth/authz"
	"github.com/rakunlabs/ada/middleware/auth/identity"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/api/users", "/api/users", true},
		{"/api/users", "/api/users/1", false},
		{"/api/*", "/api/users", true},
		{"/api/*", "/api/users/1", false},
		{"/api/**", "/api/users/1/posts", true},
		{"/api/**", "/api", true},
		{"/api/**", "/apix", false},
		{"**", "/anything/at/all", true},
		{"/a/*/c", "/a/b/c", true},
		{"/a/*/c", "/a/b/x/c", false},
		{"/a/**/c", "/a/b/x/c", true},
		{"/a/**/c", "/a/c", true},
		{"/user?", "/users", true},
		{"/user?", "/user/s", false},
		{"", "", true},
		{"", "/", false},
	}

	for _, c := range cases {
		if got := authz.Match(c.pattern, c.path); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestRequirements(t *testing.T) {
	admin := &identity.Identity{Roles: []string{"admin", "staff"}, Scopes: []string{"read", "write"}}
	guest := &identity.Identity{Roles: []string{"guest"}}

	cases := []struct {
		name string
		req  authz.Requirement
		id   *identity.Identity
		want bool
	}{
		{"role match", authz.Role{"admin"}, admin, true},
		{"role all", authz.Role{"admin", "staff"}, admin, true},
		{"role all misses", authz.Role{"admin", "root"}, admin, false},
		{"any role", authz.AnyRole{"root", "staff"}, admin, true},
		{"any role misses", authz.AnyRole{"root"}, admin, false},
		{"scope", authz.Scope{"read", "write"}, admin, true},
		{"any scope", authz.AnyScope{"delete", "read"}, admin, true},
		{"authenticated", authz.Authenticated, guest, true},
		{"authenticated anon", authz.Authenticated, nil, false},
		{"public anon", authz.Public, nil, true},
		{"any of", authz.Any{authz.Role{"root"}, authz.Role{"admin"}}, admin, true},
		{"all of", authz.All{authz.Role{"admin"}, authz.Scope{"read"}}, admin, true},
		{"all of fails", authz.All{authz.Role{"admin"}, authz.Scope{"delete"}}, admin, false},
		{"empty all passes", authz.All{}, nil, true},
		{"nil identity holds nothing", authz.Role{"admin"}, nil, false},
	}

	for _, c := range cases {
		if got := c.req.Allow(c.id); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}

		if c.req.Describe() == "" {
			t.Errorf("%s: Describe is empty", c.name)
		}
	}
}

func TestRequireMiddleware(t *testing.T) {
	h := authz.RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	// Authenticated but unauthorized -> 403.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(identity.WithContext(r.Context(), &identity.Identity{Subject: "bob"}))
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Errorf("authenticated-but-denied = %d, want 403", rec.Code)
	}

	// Anonymous -> 401, because they have not tried yet.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous = %d, want 401", rec.Code)
	}

	// The denial must not name the missing role.
	if body := rec.Body.String(); contains(body, "admin") {
		t.Errorf("denial leaks the required role: %s", body)
	}

	// Allowed.
	rec = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(identity.WithContext(r.Context(), &identity.Identity{Roles: []string{"admin"}}))
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusTeapot {
		t.Errorf("allowed = %d, want 418", rec.Code)
	}
}

func TestWithDenyHandler(t *testing.T) {
	h := authz.Require(authz.Role{"admin"}, authz.WithDenyHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusGone {
		t.Errorf("code = %d", rec.Code)
	}
}

func rules() authz.Rules {
	return authz.Rules{
		Rules: []authz.Rule{
			{
				Name:   "health",
				Paths:  []string{"/health", "/metrics"},
				Public: true,
			},
			{
				Name:    "admin api",
				Paths:   []string{"/api/admin/**"},
				Roles:   []string{"admin"},
				Methods: []string{"GET", "POST"},
			},
			{
				Name:     "api",
				Paths:    []string{"/api/**"},
				Excluded: []authz.Rule{{Paths: []string{"/api/public/**"}}},
				Scopes:   []string{"api"},
			},
		},
	}
}

func TestRulesFor(t *testing.T) {
	rs := rules()

	if err := rs.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	admin := &identity.Identity{Roles: []string{"admin"}, Scopes: []string{"api"}}
	user := &identity.Identity{Scopes: []string{"api"}}

	cases := []struct {
		method, path string
		id           *identity.Identity
		want         bool
	}{
		{"GET", "/health", nil, true},
		{"GET", "/api/admin/users", admin, true},
		{"GET", "/api/admin/users", user, false},
		{"DELETE", "/api/admin/users", user, true}, // falls through to the api rule
		{"GET", "/api/things", user, true},
		{"GET", "/api/things", nil, false},
		{"GET", "/api/public/things", user, true}, // excluded from api rule, hits default
		{"GET", "/api/public/things", nil, false}, // default is Authenticated
		{"GET", "/somewhere/else", user, true},    // default
		{"GET", "/somewhere/else", nil, false},
	}

	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, nil)

		if got := rs.Allow(r, c.id); got != c.want {
			t.Errorf("%s %s (id=%v) = %v, want %v", c.method, c.path, c.id != nil, got, c.want)
		}
	}
}

func TestRulesDefaultOverride(t *testing.T) {
	rs := rules()
	rs.Default = authz.Public

	if !rs.Allow(httptest.NewRequest(http.MethodGet, "/unlisted", nil), nil) {
		t.Error("Default=Public should allow unlisted paths anonymously")
	}
}

func TestRulesHostMatching(t *testing.T) {
	rs := authz.Rules{
		Rules: []authz.Rule{{
			Paths: []string{"/**"},
			Hosts: []string{"admin.example"},
			Roles: []string{"admin"},
		}},
	}

	admin := httptest.NewRequest(http.MethodGet, "/x", nil)
	admin.Host = "admin.example:8443"

	if rs.For(admin).Allow(&identity.Identity{}) {
		t.Error("admin host should require the admin role")
	}

	other := httptest.NewRequest(http.MethodGet, "/x", nil)
	other.Host = "app.example"

	if !rs.For(other).Allow(&identity.Identity{Subject: "x"}) {
		t.Error("non-matching host should fall through to the default")
	}
}

func TestRuleValidate(t *testing.T) {
	if err := (authz.Rule{Name: "x"}).Validate(); err == nil {
		t.Error("a rule with no paths matches nothing and should not validate")
	}

	bad := authz.Rule{Name: "x", Paths: []string{"/a"}, Public: true, Roles: []string{"admin"}}
	if err := bad.Validate(); err == nil {
		t.Error("public plus roles is contradictory and should not validate")
	}
}

func TestPublicPaths(t *testing.T) {
	got := rules().PublicPaths()
	if len(got) != 2 || got[0] != "/health" {
		t.Errorf("public paths = %v", got)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}

			return false
		})()
}
