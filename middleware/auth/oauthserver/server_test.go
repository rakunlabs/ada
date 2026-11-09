package oauthserver_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/oauthserver"
	"github.com/rakunlabs/ada/middleware/auth/resource"
)

// testMux adapts http.ServeMux to oauthserver.Mux.
type testMux struct{ *http.ServeMux }

func (m testMux) HandleWithMethod(method, p string, h http.HandlerFunc, _ ...func(http.Handler) http.Handler) {
	if method != "" {
		p = method + " " + p
	}

	m.HandleFunc(p, h)
}

// signedIn plays the application's session middleware: the X-User header is
// the signed-in user.
func signedIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.Header.Get("X-User")
		if user == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)

			return
		}

		id := &identity.Identity{Subject: user, Email: user + "@example.com", Roles: []string{"admin"}, Scopes: []string{"everything"}}
		next.ServeHTTP(w, r.WithContext(identity.WithContext(r.Context(), id)))
	})
}

type fixture struct {
	t      *testing.T
	srv    *oauthserver.Server
	store  *oauthserver.MemoryStore
	mux    testMux
	issuer string
}

func newFixture(t *testing.T, mutate func(*oauthserver.Config)) *fixture {
	t.Helper()

	cfg := oauthserver.Config{
		Issuer:          "https://app.example.com",
		ScopesSupported: []string{"mcp:read", "mcp:write"},
		DefaultScopes:   []string{"mcp:read"},
		Authenticate:    signedIn,
		RootFallback:    true,
	}
	if mutate != nil {
		mutate(&cfg)
	}

	store := oauthserver.NewMemoryStore()

	srv, err := oauthserver.New(cfg, store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mux := testMux{http.NewServeMux()}
	srv.Mount(mux)

	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(identity.FromContext(r.Context()))
	})

	rc := resource.Config{
		Resource:             cfg.Issuer + "/mcp",
		AuthorizationServers: []string{cfg.Issuer},
		Subresources:         true,
	}
	if cfg.Issuer == "" {
		rc = resource.Config{ResourcePath: "/mcp", AuthorizationServersFunc: srv.AuthorizationServers, Subresources: true}
	}

	rs, err := resource.New(rc)
	if err != nil {
		t.Fatal(err)
	}

	mux.Handle("/api", srv.RequireToken(rs)(echo))
	mux.Handle("/mcp/", srv.RequireToken(rs)(echo))
	mux.Handle("/mcp", srv.RequireToken(rs)(echo))

	return &fixture{t: t, srv: srv, store: store, mux: mux, issuer: cfg.Issuer}
}

func (f *fixture) do(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, r)

	return rec
}

func (f *fixture) register(body string) map[string]any {
	f.t.Helper()

	rec := f.do(httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		f.t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}

	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		f.t.Fatal(err)
	}

	return out
}

func pkce() (string, string) {
	verifier := strings.Repeat("v", 50)
	sum := sha256.Sum256([]byte(verifier))

	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizeQuery(clientID, redirect, challenge string, extra url.Values) url.Values {
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"state":                 {"xyz"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		q[k] = v
	}

	return q
}

// approve runs the built-in consent page and returns the redirect it ends
// with.
func (f *fixture) approve(user string, q url.Values, action string, remember bool) *url.URL {
	f.t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	req.Header.Set("X-User", user)
	rec := f.do(req)
	if rec.Code != http.StatusOK {
		f.t.Fatalf("consent page: %d %s", rec.Code, rec.Body.String())
	}

	var csrf *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if strings.HasPrefix(c.Name, "oauth_consent_") {
			csrf = c
		}
	}
	if csrf == nil {
		f.t.Fatal("consent page set no csrf cookie")
	}
	if !strings.Contains(rec.Body.String(), `value="`+csrf.Value+`"`) {
		f.t.Fatal("consent form does not carry the csrf token")
	}

	form := url.Values{}
	for k, v := range q {
		form[k] = v
	}
	form.Set("csrf", csrf.Value)
	form.Set("action", action)
	if remember {
		form.Set("remember", "1")
	}

	post := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("X-User", user)
	post.AddCookie(csrf)

	rec = f.do(post)
	if rec.Code != http.StatusSeeOther {
		f.t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}

	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		f.t.Fatal(err)
	}

	return u
}

func (f *fixture) token(form url.Values) (*httptest.ResponseRecorder, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := f.do(req)

	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)

	return rec, out
}

func (f *fixture) callAPI(token string) *httptest.ResponseRecorder {
	return f.callPath(token, "/api")
}

func (f *fixture) callPath(token, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	return f.do(req)
}

func TestMetadata(t *testing.T) {
	f := newFixture(t, nil)

	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		rec := f.do(httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("%s: no CORS", path)
		}

		var meta map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
			t.Fatal(err)
		}

		want := map[string]string{
			"issuer":                 "https://app.example.com",
			"authorization_endpoint": "https://app.example.com/oauth/authorize",
			"token_endpoint":         "https://app.example.com/oauth/token",
			"registration_endpoint":  "https://app.example.com/oauth/register",
			"revocation_endpoint":    "https://app.example.com/oauth/revoke",
		}
		for k, v := range want {
			if meta[k] != v {
				t.Errorf("%s: %s = %v, want %s", path, k, meta[k], v)
			}
		}
	}

	rec := f.do(httptest.NewRequest(http.MethodOptions, "/oauth/token", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight: %d", rec.Code)
	}
}

func TestMetadataUnderBasePath(t *testing.T) {
	f := newFixture(t, func(c *oauthserver.Config) {
		c.Issuer = ""
		c.BasePath = "/dataport/"
	})

	for _, path := range []string{"/.well-known/oauth-authorization-server/dataport", "/dataport/.well-known/oauth-authorization-server"} {
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com"+path, nil)
		rec := f.do(req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, rec.Code)
		}

		var meta map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &meta)
		if meta["issuer"] != "http://app.example.com/dataport" || meta["token_endpoint"] != "http://app.example.com/dataport/oauth/token" {
			t.Fatalf("%s: %v", path, meta)
		}
	}
}

func TestFullFlow(t *testing.T) {
	f := newFixture(t, nil)

	reg := f.register(`{"client_name":"Claude Code","redirect_uris":["http://localhost:3000/callback"],"unknown":"ignored"}`)
	clientID := reg["client_id"].(string)
	if reg["token_endpoint_auth_method"] != "none" || reg["client_secret"] != nil {
		t.Fatalf("expected a public client: %v", reg)
	}

	verifier, challenge := pkce()
	// A different loopback port must be accepted (RFC 8252 §7.3).
	redirect := "http://localhost:51234/callback"
	q := authorizeQuery(clientID, redirect, challenge, url.Values{"scope": {"mcp:read mcp:write"}})

	back := f.approve("alice", q, "approve", false)
	if back.Host != "localhost:51234" || back.Query().Get("state") != "xyz" || back.Query().Get("iss") != f.issuer {
		t.Fatalf("redirect: %s", back)
	}

	code := back.Query().Get("code")

	rec, tok := f.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirect}, "code_verifier": {verifier},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("token: %d %s", rec.Code, rec.Body.String())
	}
	if tok["token_type"] != "Bearer" || tok["scope"] != "mcp:read mcp:write" || tok["expires_in"].(float64) != 3600 {
		t.Fatalf("token response: %v", tok)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token response must not be cached")
	}

	access := tok["access_token"].(string)
	refresh := tok["refresh_token"].(string)
	if !strings.HasPrefix(access, "oat_") || !strings.HasPrefix(refresh, "ort_") {
		t.Fatalf("prefixes: %s %s", access, refresh)
	}

	// The code works once.
	if rec, _ := f.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirect}, "code_verifier": {verifier},
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("code reuse: %d", rec.Code)
	}

	api := f.callAPI(access)
	if api.Code != http.StatusOK {
		t.Fatalf("api: %d %s", api.Code, api.Body.String())
	}

	var id identity.Identity
	_ = json.Unmarshal(api.Body.Bytes(), &id)
	if id.Subject != "alice" || len(id.Roles) != 1 {
		t.Fatalf("identity: %+v", id)
	}
	// The token's scopes replace the session's.
	if strings.Join(id.Scopes, " ") != "mcp:read mcp:write" {
		t.Fatalf("scopes: %v", id.Scopes)
	}
	if oauthserver.Info(&id) == nil || oauthserver.Info(&id).ClientID != clientID {
		t.Fatalf("info: %+v", oauthserver.Info(&id))
	}

	// Refresh rotates; the old refresh token dies.
	rec, tok2 := f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}})
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
	}
	if f.callAPI(access).Code != http.StatusUnauthorized {
		t.Fatal("old access token still works after refresh")
	}
	if f.callAPI(tok2["access_token"].(string)).Code != http.StatusOK {
		t.Fatal("new access token rejected")
	}
	if rec, _ := f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("refresh reuse: %d", rec.Code)
	}

	// Revocation by refresh token kills the access token too.
	revoke := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(url.Values{
		"token": {tok2["refresh_token"].(string)}, "client_id": {clientID},
	}.Encode()))
	revoke.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if rec := f.do(revoke); rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if f.callAPI(tok2["access_token"].(string)).Code != http.StatusUnauthorized {
		t.Fatal("token works after revocation")
	}
}

func TestPKCEAndRedirectChecks(t *testing.T) {
	f := newFixture(t, nil)

	clientID := f.register(`{"client_name":"x","redirect_uris":["https://client.example.com/cb"]}`)["client_id"].(string)
	_, challenge := pkce()

	// An unregistered redirect is shown to the user, never followed.
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authorizeQuery(clientID, "https://evil.example.com/cb", challenge, nil).Encode(), nil)
	req.Header.Set("X-User", "alice")
	if rec := f.do(req); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("bad redirect: %d %s", rec.Code, rec.Header().Get("Location"))
	}

	// Missing PKCE goes back to the client.
	q := authorizeQuery(clientID, "https://client.example.com/cb", "", nil)
	q.Del("code_challenge_method")
	req = httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	req.Header.Set("X-User", "alice")
	rec := f.do(req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Query().Get("error") != "invalid_request" || loc.Query().Get("state") != "xyz" {
		t.Fatalf("missing pkce: %d %s", rec.Code, loc)
	}

	// Unsupported scope.
	req = httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authorizeQuery(clientID, "https://client.example.com/cb", challenge, url.Values{"scope": {"admin"}}).Encode(), nil)
	req.Header.Set("X-User", "alice")
	rec = f.do(req)
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("error") != "invalid_scope" {
		t.Fatalf("bad scope: %s", loc)
	}

	// Not signed in: the application's middleware takes over.
	req = httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authorizeQuery(clientID, "https://client.example.com/cb", challenge, nil).Encode(), nil)
	if rec := f.do(req); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("anonymous: %d", rec.Code)
	}

	// Wrong verifier burns the code.
	back := f.approve("alice", authorizeQuery(clientID, "https://client.example.com/cb", challenge, nil), "approve", false)
	code := back.Query().Get("code")
	if rec, out := f.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {"https://client.example.com/cb"}, "code_verifier": {strings.Repeat("w", 50)},
	}); rec.Code != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("bad verifier: %d %v", rec.Code, out)
	}

	// Deny.
	back = f.approve("alice", authorizeQuery(clientID, "https://client.example.com/cb", challenge, nil), "deny", false)
	if back.Query().Get("error") != "access_denied" || back.Query().Get("code") != "" {
		t.Fatalf("deny: %s", back)
	}
}

func TestConsentNeedsCSRF(t *testing.T) {
	f := newFixture(t, nil)

	clientID := f.register(`{"redirect_uris":["https://client.example.com/cb"]}`)["client_id"].(string)
	_, challenge := pkce()

	form := authorizeQuery(clientID, "https://client.example.com/cb", challenge, nil)
	form.Set("action", "approve")
	form.Set("csrf", "guess")

	post := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("X-User", "alice")
	for _, name := range []string{"oauth_consent_x", "oauth_consent_csrf"} {
		post.AddCookie(&http.Cookie{Name: name, Value: "other"})
	}

	if rec := f.do(post); rec.Code != http.StatusForbidden {
		t.Fatalf("csrf: %d", rec.Code)
	}
}

func TestRememberedConsentAndDedup(t *testing.T) {
	f := newFixture(t, nil)

	first := f.register(`{"client_name":"Cursor","redirect_uris":["http://127.0.0.1:4000/cb"]}`)
	second := f.register(`{"client_name":"Cursor","redirect_uris":["http://127.0.0.1:5000/cb"]}`)
	if first["client_id"] != second["client_id"] {
		t.Fatal("same client registered twice")
	}
	if second["redirect_uris"].([]any)[0] != "http://127.0.0.1:5000/cb" {
		t.Fatal("dedup must echo the caller's redirect")
	}

	clientID := first["client_id"].(string)
	_, challenge := pkce()
	q := authorizeQuery(clientID, "http://127.0.0.1:5000/cb", challenge, nil)

	f.approve("alice", q, "approve", true)

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	req.Header.Set("X-User", "alice")
	rec := f.do(req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Query().Get("code") == "" {
		t.Fatalf("remembered consent: %d %s", rec.Code, rec.Body.String())
	}

	// More scope than remembered asks again.
	q.Set("scope", "mcp:read mcp:write")
	req = httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	req.Header.Set("X-User", "alice")
	if rec := f.do(req); rec.Code != http.StatusOK {
		t.Fatalf("wider scope must ask: %d", rec.Code)
	}

	// Another user is asked.
	req = httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authorizeQuery(clientID, "http://127.0.0.1:5000/cb", challenge, nil).Encode(), nil)
	req.Header.Set("X-User", "bob")
	if rec := f.do(req); rec.Code != http.StatusOK {
		t.Fatalf("other user: %d", rec.Code)
	}
}

func TestHooks(t *testing.T) {
	var disabled sync.Map

	f := newFixture(t, func(c *oauthserver.Config) {
		c.Hooks.Authorize = func(_ context.Context, req *oauthserver.AuthorizeRequest) error {
			if strings.HasSuffix(req.Resource, "/secret") {
				return &oauthserver.Error{Code: "invalid_target", Description: "no access"}
			}

			req.Extra = map[string]any{"connection": "shop"}

			return nil
		}
		c.Hooks.Identity = func(_ context.Context, t *oauthserver.Token) (*identity.Identity, error) {
			if _, ok := disabled.Load(t.Subject()); ok {
				return nil, oauthserver.ErrAccessDenied
			}

			return t.Identity, nil
		}
	})

	clientID := f.register(`{"redirect_uris":["https://client.example.com/cb"]}`)["client_id"].(string)
	verifier, challenge := pkce()

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authorizeQuery(clientID, "https://client.example.com/cb", challenge, url.Values{"resource": {"https://app.example.com/mcp/secret"}}).Encode(), nil)
	req.Header.Set("X-User", "alice")
	rec := f.do(req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("error") != "invalid_target" {
		t.Fatalf("hook refusal: %s", loc)
	}

	q := authorizeQuery(clientID, "https://client.example.com/cb", challenge, url.Values{"resource": {"https://app.example.com/mcp/shop"}})
	back := f.approve("alice", q, "approve", false)
	_, tok := f.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")}, "client_id": {clientID},
		"redirect_uri": {"https://client.example.com/cb"}, "code_verifier": {verifier},
	})

	access := tok["access_token"].(string)

	api := f.callPath(access, "/mcp/shop")
	var id identity.Identity
	_ = json.Unmarshal(api.Body.Bytes(), &id)
	info := oauthserver.Info(&id)
	if info == nil || info.Extra["connection"] != "shop" || info.Resource != "https://app.example.com/mcp/shop" {
		t.Fatalf("info: %d %+v", api.Code, info)
	}

	// Audience: the /mcp/shop token is refused on other resources.
	for _, other := range []string{"/mcp/admin", "/mcp", "/api"} {
		if rec := f.callPath(access, other); rec.Code != http.StatusUnauthorized {
			t.Fatalf("shop token on %s: %d, want 401", other, rec.Code)
		}
	}

	disabled.Store("alice", true)
	if f.callPath(access, "/mcp/shop").Code != http.StatusUnauthorized {
		t.Fatal("disabled user's token still accepted")
	}
	if rec, _ := f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("disabled refresh: %d", rec.Code)
	}
}

func TestConfidentialClient(t *testing.T) {
	f := newFixture(t, func(c *oauthserver.Config) { c.DisableRegistration = true })

	if rec := f.do(httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(`{}`))); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("registration should be off: %d", rec.Code)
	}

	reg, err := f.srv.RegisterClient(context.Background(), oauthserver.RegistrationRequest{
		ClientName:              "backend",
		RedirectURIs:            []string{"https://client.example.com/cb"},
		TokenEndpointAuthMethod: oauthserver.AuthMethodBasic,
	})
	if err != nil || reg.ClientSecret == "" {
		t.Fatalf("register: %v %+v", err, reg)
	}

	verifier, challenge := pkce()
	back := f.approve("alice", authorizeQuery(reg.ClientID, "https://client.example.com/cb", challenge, nil), "approve", false)

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")},
		"redirect_uri": {"https://client.example.com/cb"}, "code_verifier": {verifier},
	}

	bad := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bad.SetBasicAuth(reg.ClientID, "wrong")
	if rec := f.do(bad); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", rec.Code)
	}

	good := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	good.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	good.SetBasicAuth(reg.ClientID, reg.ClientSecret)
	if rec := f.do(good); rec.Code != http.StatusOK {
		t.Fatalf("basic auth: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPersonalToken(t *testing.T) {
	f := newFixture(t, nil)

	raw, tok, err := f.srv.IssueToken(context.Background(), oauthserver.IssueRequest{
		Name:     "ci",
		Identity: &identity.Identity{Subject: "alice"},
		Scopes:   []string{"mcp:read"},
		TTL:      time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	if f.callAPI(raw).Code != http.StatusOK {
		t.Fatal("personal token rejected")
	}

	list, _ := f.store.TokensBySubject(context.Background(), "alice")
	if len(list) != 1 || list[0].Name != "ci" {
		t.Fatalf("list: %+v", list)
	}

	if err := f.srv.RevokeToken(context.Background(), tok.ID); err != nil {
		t.Fatal(err)
	}
	if f.callAPI(raw).Code != http.StatusUnauthorized {
		t.Fatal("revoked token accepted")
	}
}

func TestExpiry(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	f := newFixture(t, func(c *oauthserver.Config) { c.Now = clock })

	raw, _, err := f.srv.IssueToken(context.Background(), oauthserver.IssueRequest{
		Identity: &identity.Identity{Subject: "alice"},
		TTL:      time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(2 * time.Minute)
	if f.callAPI(raw).Code != http.StatusUnauthorized {
		t.Fatal("expired token accepted")
	}
}

func TestRequireTokenIgnoresForeignTokens(t *testing.T) {
	f := newFixture(t, nil)

	rec := f.callAPI("some-jwt")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "invalid_token") {
		t.Fatalf("foreign token: %d %s", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}

	if _, _, err := f.srv.Validate(context.Background(), "some-jwt"); err == nil || errors.Is(err, oauthserver.ErrInvalidToken) {
		t.Fatalf("Validate must report no credentials for foreign tokens: %v", err)
	}
}

func TestRootFallback(t *testing.T) {
	f := newFixture(t, nil)

	if rec := f.do(httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{"redirect_uris":["https://c.example.com/cb"]}`))); rec.Code != http.StatusCreated {
		t.Fatalf("/register: %d", rec.Code)
	}

	rec := f.do(httptest.NewRequest(http.MethodGet, "/authorize?a=b", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://app.example.com/oauth/authorize?a=b" {
		t.Fatalf("/authorize: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestRegistrationValidation(t *testing.T) {
	f := newFixture(t, nil)

	for _, body := range []string{
		`{"redirect_uris":[]}`,
		`{"redirect_uris":["http://example.com/cb"]}`,
		`{"redirect_uris":["javascript:alert(1)"]}`,
		`{"redirect_uris":["https://c.example.com/cb#x"]}`,
		`{"redirect_uris":["https://c.example.com/cb"],"grant_types":["client_credentials"]}`,
		`not json`,
	} {
		rec := f.do(httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, rec.Code)
		}
	}

	reg := f.register(`{"redirect_uris":["cursor://anysphere.cursor-retrieval/oauth/callback"]}`)
	if reg["client_id"] == "" {
		t.Fatal("app scheme rejected")
	}
}

func TestResourceValidation(t *testing.T) {
	f := newFixture(t, nil)

	clientID := f.register(`{"redirect_uris":["https://client.example.com/cb"]}`)["client_id"].(string)
	verifier, challenge := pkce()

	for _, res := range []string{"https://evil.example.com/mcp", "urn:anything", "https://app.example.com/mcp?x=1"} {
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+authorizeQuery(clientID, "https://client.example.com/cb", challenge, url.Values{"resource": {res}}).Encode(), nil)
		req.Header.Set("X-User", "alice")
		rec := f.do(req)
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if loc.Query().Get("error") != "invalid_target" {
			t.Fatalf("resource %s accepted: %d %s", res, rec.Code, loc)
		}
	}

	// A resource the user never approved cannot be added at the token step.
	back := f.approve("alice", authorizeQuery(clientID, "https://client.example.com/cb", challenge, nil), "approve", false)
	rec, out := f.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")}, "client_id": {clientID},
		"redirect_uri": {"https://client.example.com/cb"}, "code_verifier": {verifier}, "resource": {"https://app.example.com/mcp"},
	})
	if rec.Code != http.StatusBadRequest || out["error"] != "invalid_target" {
		t.Fatalf("resource added at token step: %d %v", rec.Code, out)
	}
}

func TestRefreshReuseRevokesGrant(t *testing.T) {
	now := time.Now()
	f := newFixture(t, func(c *oauthserver.Config) { c.Now = func() time.Time { return now } })

	clientID := f.register(`{"redirect_uris":["https://client.example.com/cb"]}`)["client_id"].(string)
	verifier, challenge := pkce()
	back := f.approve("alice", authorizeQuery(clientID, "https://client.example.com/cb", challenge, url.Values{"scope": {"mcp:read mcp:write"}}), "approve", false)

	_, tok := f.token(url.Values{
		"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")}, "client_id": {clientID},
		"redirect_uri": {"https://client.example.com/cb"}, "code_verifier": {verifier},
	})
	stolen := tok["refresh_token"].(string)

	// The legitimate client refreshes, narrowing to read only.
	rec, fresh := f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {stolen}, "scope": {"mcp:read"}})
	if rec.Code != http.StatusOK || fresh["scope"] != "mcp:read" {
		t.Fatalf("narrowing refresh: %d %v", rec.Code, fresh)
	}

	// Narrowing was for that access token only: the next refresh gets both
	// scopes back.
	rec, again := f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {fresh["refresh_token"].(string)}})
	if rec.Code != http.StatusOK || again["scope"] != "mcp:read mcp:write" {
		t.Fatalf("scopes after narrowing: %d %v", rec.Code, again)
	}

	replay := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {fresh["refresh_token"].(string)}}

	// Right after the rotation, a second use is a raced retry: refused, but
	// the grant survives.
	if rec, _ := f.token(replay); rec.Code != http.StatusBadRequest {
		t.Fatalf("raced retry: %d", rec.Code)
	}
	if f.callAPI(again["access_token"].(string)).Code != http.StatusOK {
		t.Fatal("a raced retry revoked the grant")
	}

	// Later, the same rotated-out refresh token is a replay.
	now = now.Add(time.Minute)
	if rec, _ := f.token(replay); rec.Code != http.StatusBadRequest {
		t.Fatalf("replay: %d", rec.Code)
	}

	// The whole grant is gone: the current tokens stop working too.
	if f.callAPI(again["access_token"].(string)).Code != http.StatusUnauthorized {
		t.Fatal("access token survived refresh-token replay")
	}
	if rec, _ := f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {again["refresh_token"].(string)}}); rec.Code != http.StatusBadRequest {
		t.Fatal("current refresh token survived replay")
	}
}

func TestRegistrationRateLimit(t *testing.T) {
	f := newFixture(t, func(c *oauthserver.Config) { c.RegistrationsPerHour = 2 })

	codes := []int{}
	for i := range 4 {
		body := fmt.Sprintf(`{"client_name":"c%d","redirect_uris":["https://c.example.com/cb"]}`, i)
		codes = append(codes, f.do(httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))).Code)
	}

	if fmt.Sprint(codes) != "[201 201 429 429]" {
		t.Fatalf("codes: %v", codes)
	}

	// Re-registering a known client does not count against the budget.
	if rec := f.do(httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(`{"client_name":"c0","redirect_uris":["https://c.example.com/cb"]}`))); rec.Code != http.StatusCreated {
		t.Fatalf("dedup registration: %d", rec.Code)
	}
}
