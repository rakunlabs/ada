package auth_test

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
	"github.com/rakunlabs/ada/middleware/auth/authz"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/oauthserver"
	"github.com/rakunlabs/ada/middleware/auth/resource"
	"github.com/rakunlabs/ada/middleware/auth/session"
	"github.com/rakunlabs/ada/middleware/auth/strategy/apikey"
	"github.com/rakunlabs/ada/middleware/auth/strategy/local"
)

// TestOAuthServerEndToEnd runs what an MCP client does against an
// application that is its own authorization server: discover, register, send
// the user through login and consent, exchange the code, call the endpoint.
func TestOAuthServerEndToEnd(t *testing.T) {
	var srvURL string

	oauth, err := oauthserver.New(oauthserver.Config{
		IssuerFunc:      func(*http.Request) string { return srvURL },
		ScopesSupported: []string{"mcp"},
		DefaultScopes:   []string{"mcp"},
	}, oauthserver.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}

	a := auth.New(auth.Config{
		UI:                auth.UIConfig{ExternalFolder: true},
		ProtectedResource: &resource.Config{ResourcePath: "/mcp", ScopesSupported: []string{"mcp"}, UnsafeTrustAllForwardedHeaders: true},
	})
	a.Strategy(local.New("local", func(_ context.Context, u, p string) (*identity.Identity, error) {
		if u == "alice" && p == "secret" {
			return &identity.Identity{Subject: "alice"}, nil
		}

		return nil, local.ErrInvalidCredentials
	}))
	// An API-key strategy registered first must not swallow OAuth tokens.
	a.Strategy(apikey.New("keys", func(context.Context, string) (*identity.Identity, error) {
		return nil, apikey.ErrInvalidKey
	}))
	a.WithOAuthServer(oauth)

	if err := a.Init(context.Background()); err != nil {
		t.Fatal(err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	mcp := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(identity.FromContext(r.Context()))
	}
	mux.HandleWithMethod(http.MethodPost, "/mcp", func(w http.ResponseWriter, r *http.Request) {
		session.DisableRedirect()(a.Require()(authz.RequireScope("mcp")(http.HandlerFunc(mcp)))).ServeHTTP(w, r)
	})

	ts := httptest.NewServer(mux.mu)
	t.Cleanup(ts.Close)
	srvURL = ts.URL

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// 1. Unauthenticated call → 401 pointing at the resource metadata.
	resp, err := http.Post(ts.URL+"/mcp", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	challenge := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(challenge, `resource_metadata="`+ts.URL+`/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("challenge: %d %q", resp.StatusCode, challenge)
	}

	// 2. Resource metadata names this server.
	var prm map[string]any
	getJSON(t, ts.URL+"/.well-known/oauth-protected-resource/mcp", &prm)
	if servers, _ := prm["authorization_servers"].([]any); len(servers) != 1 || servers[0] != ts.URL {
		t.Fatalf("resource metadata: %v", prm)
	}

	// 3. Authorization server metadata.
	var asm map[string]any
	getJSON(t, ts.URL+"/.well-known/oauth-authorization-server", &asm)

	// 4. Register.
	resp, err = http.Post(asm["registration_endpoint"].(string), "application/json",
		strings.NewReader(`{"client_name":"test","redirect_uris":["http://127.0.0.1:9999/cb"]}`))
	if err != nil {
		t.Fatal(err)
	}
	var reg map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	_ = resp.Body.Close()

	verifier := strings.Repeat("a", 64)
	sum := sha256.Sum256([]byte(verifier))
	authURL := asm["authorization_endpoint"].(string) + "?" + url.Values{
		"client_id": {reg["client_id"].(string)}, "redirect_uri": {"http://127.0.0.1:9999/cb"},
		"response_type": {"code"}, "state": {"s1"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"}, "resource": {ts.URL + "/mcp"},
	}.Encode()

	// 5. Not signed in: redirected to the login UI, coming back afterwards.
	resp, err = browser.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || loc.Path != "/login" || !strings.HasPrefix(loc.Query().Get("redirect_path"), "/oauth/authorize?") {
		t.Fatalf("login redirect: %d %s", resp.StatusCode, loc)
	}

	login, _ := http.NewRequest(http.MethodPost, ts.URL+"/login/pass/local", strings.NewReader(`{"username":"alice","password":"secret"}`))
	login.Header.Set("Content-Type", "application/json")
	resp, err = browser.Do(login)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", resp.StatusCode)
	}

	// 6. Consent page, then approve.
	resp, err = browser.Get(ts.URL + loc.Query().Get("redirect_path"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("consent: %d", resp.StatusCode)
	}

	var csrf string
	u, _ := url.Parse(ts.URL + "/oauth/authorize")
	for _, c := range jar.Cookies(u) {
		if strings.HasPrefix(c.Name, "oauth_consent_") {
			csrf = c.Value
		}
	}

	form, _ := url.ParseQuery(strings.SplitN(authURL, "?", 2)[1])
	form.Set("csrf", csrf)
	form.Set("action", "approve")
	resp, err = browser.PostForm(ts.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	back, _ := url.Parse(resp.Header.Get("Location"))
	if back.Query().Get("code") == "" || back.Query().Get("iss") != ts.URL {
		t.Fatalf("approve: %d %s", resp.StatusCode, back)
	}

	// 7. Exchange the code.
	resp, err = http.PostForm(asm["token_endpoint"].(string), url.Values{
		"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")}, "client_id": {reg["client_id"].(string)},
		"redirect_uri": {"http://127.0.0.1:9999/cb"}, "code_verifier": {verifier}, "resource": {ts.URL + "/mcp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var tok map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&tok)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token: %d %v", resp.StatusCode, tok)
	}

	// 8. Call the endpoint.
	call, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", nil)
	call.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	resp, err = http.DefaultClient.Do(call)
	if err != nil {
		t.Fatal(err)
	}
	var id identity.Identity
	_ = json.NewDecoder(resp.Body).Decode(&id)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || id.Subject != "alice" || id.Provider != "oauth" {
		t.Fatalf("mcp: %d %+v", resp.StatusCode, id)
	}
	if info := oauthserver.Info(&id); info == nil || info.Resource != ts.URL+"/mcp" {
		t.Fatalf("info: %+v", info)
	}

	// A bad token of this server is a 401 with invalid credentials.
	call, _ = http.NewRequest(http.MethodPost, ts.URL+"/mcp", nil)
	call.Header.Set("Authorization", "Bearer oat_bogus")
	resp, err = http.DefaultClient.Do(call)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bogus token: %d", resp.StatusCode)
	}
}

func getJSON(t *testing.T, u string, v any) {
	t.Helper()

	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d", u, resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}
