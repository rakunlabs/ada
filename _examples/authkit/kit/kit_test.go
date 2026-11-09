package kit_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/_examples/authkit/kit"
	"github.com/rakunlabs/ada/middleware/auth/oauthserver"
	"github.com/rakunlabs/ada/middleware/auth/password"
	"github.com/rakunlabs/ada/_examples/authkit/users"
)

// testMux adapts http.ServeMux to auth.Mux, applying route middleware.
type testMux struct{ *http.ServeMux }

func (m testMux) HandleWithMethod(method, p string, h http.HandlerFunc, mw ...func(http.Handler) http.Handler) {
	var handler http.Handler = h
	for i := len(mw) - 1; i >= 0; i-- {
		handler = mw[i](handler)
	}

	pattern := p
	if strings.HasSuffix(p, "/*") {
		pattern = strings.TrimSuffix(p, "*")
	}
	if method != "" {
		pattern = method + " " + pattern
	}

	m.Handle(pattern, handler)
}

func TestKit(t *testing.T) {
	ctx := context.Background()

	var base string

	k, err := kit.New(ctx, kit.Config{
		Login: auth.Config{UI: auth.UIConfig{Title: "Demo", ExternalFolder: true}},
		Users: users.Config{
			Hasher: &password.PBKDF2{Iterations: 1000},
			Roles: []users.Role{
				{Name: "admin", Permissions: []string{"*"}},
				{Name: "analyst", Permissions: []string{"reports:read"}},
				{Name: "user"},
			},
		},
		OAuth: kit.OAuth{
			Enabled: true,
			Server: oauthserver.Config{
				IssuerFunc:                     func(*http.Request) string { return base },
				UnsafeTrustAllForwardedHeaders: true,
			},
		},
	}, kit.Stores{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k.Close() })

	mux := testMux{http.NewServeMux()}
	k.Mount(mux)

	reports := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(identity.FromContext(r.Context()))
	}
	mux.HandleWithMethod(http.MethodGet, "/api/reports", reports, append(k.API(), k.RequirePermission("reports:read"))...)
	mux.HandleWithMethod(http.MethodPost, "/mcp", reports, k.API()...)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	base = ts.URL

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	post := func(c *http.Client, path, body string) *http.Response {
		t.Helper()

		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}

		return resp
	}

	// The login page offers signup while nobody exists.
	resp, _ := http.Get(ts.URL + "/login/info")
	var info map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&info)
	_ = resp.Body.Close()
	if info["signup_first"] != true || !strings.Contains(mustJSON(info["strategies"]), `"register"`) {
		t.Fatalf("info before first user: %v", info)
	}

	// First signup becomes the administrator and is signed in.
	resp = post(browser, "/login/register/local", `{"username":"root","password":"longenough","password_confirm":"longenough"}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first signup: %d", resp.StatusCode)
	}

	resp, _ = http.Get(ts.URL + "/login/info")
	info = map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&info)
	_ = resp.Body.Close()
	if info["signup_first"] == true || strings.Contains(mustJSON(info["strategies"]), `"register"`) {
		t.Fatalf("signup must close after the first user: %v", info)
	}
	if r := post(http.DefaultClient, "/login/register/local", `{"username":"x","password":"longenough","password_confirm":"longenough"}`); r.StatusCode != http.StatusNotFound {
		t.Fatalf("second signup: %d", r.StatusCode)
	}

	// The administrator creates an analyst through the admin API.
	resp = post(browser, "/api/admin/users", `{"username":"ann","password":"longenough","roles":["analyst"]}`)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create analyst: %d", resp.StatusCode)
	}

	// The admin page is served to the admin.
	resp, err = browser.Get(ts.URL + "/api/admin/users/ui/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin ui: %d", resp.StatusCode)
	}

	// The analyst signs in and may read reports but not manage users.
	jar2, _ := cookiejar.New(nil)
	analyst := &http.Client{Jar: jar2, CheckRedirect: browser.CheckRedirect}
	if r := post(analyst, "/login/pass/local", `{"username":"ann","password":"longenough"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("analyst login: %d", r.StatusCode)
	}

	resp, _ = analyst.Get(ts.URL + "/api/reports")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("analyst reports: %d", resp.StatusCode)
	}

	resp, _ = analyst.Get(ts.URL + "/api/admin/users")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("analyst admin: %d", resp.StatusCode)
	}

	// Anonymous API calls get a 401, not a redirect.
	anon, _ := http.Get(ts.URL + "/api/reports")
	_ = anon.Body.Close()
	if anon.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", anon.StatusCode)
	}

	// The analyst connects an MCP client.
	mcp, _ := http.Post(ts.URL+"/mcp", "application/json", nil)
	_ = mcp.Body.Close()
	if !strings.Contains(mcp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("mcp challenge: %q", mcp.Header.Get("WWW-Authenticate"))
	}

	resp = post(http.DefaultClient, "/oauth/register", `{"client_name":"cli","redirect_uris":["http://127.0.0.1:1/cb"]}`)
	var reg map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	_ = resp.Body.Close()

	verifier := strings.Repeat("k", 50)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id": {reg["client_id"].(string)}, "redirect_uri": {"http://127.0.0.1:1/cb"}, "response_type": {"code"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}

	resp, _ = analyst.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	_ = resp.Body.Close()

	var csrf string
	u, _ := url.Parse(ts.URL + "/oauth/authorize")
	for _, c := range jar2.Cookies(u) {
		if strings.HasPrefix(c.Name, "oauth_consent_") {
			csrf = c.Value
		}
	}

	q.Set("csrf", csrf)
	q.Set("action", "approve")
	resp, _ = analyst.PostForm(ts.URL+"/oauth/authorize", q)
	_ = resp.Body.Close()
	back, _ := url.Parse(resp.Header.Get("Location"))

	resp, _ = http.PostForm(ts.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")}, "client_id": {reg["client_id"].(string)},
		"redirect_uri": {"http://127.0.0.1:1/cb"}, "code_verifier": {verifier},
	})
	var tok map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	_ = resp.Body.Close()

	call := func() int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()

		return r.StatusCode
	}

	if code := call(); code != http.StatusOK {
		t.Fatalf("mcp with token: %d", code)
	}

	// Disabling the analyst kills the token at once.
	ann, _ := k.Users.Store().GetUserByUsername(ctx, "ann")
	off := true
	if _, err := k.Users.Update(ctx, ann.ID, users.UpdateRequest{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	if code := call(); code != http.StatusUnauthorized {
		t.Fatalf("mcp after disable: %d", code)
	}

	// And the session too.
	resp, _ = analyst.Get(ts.URL + "/api/reports")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session after disable: %d", resp.StatusCode)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)

	return string(b)
}
