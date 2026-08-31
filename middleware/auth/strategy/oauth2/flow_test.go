package oauth2_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/strategy"
	"github.com/rakunlabs/ada/middleware/auth/strategy/oauth2"
)

// idp is a minimal OpenID Provider: discovery, JWKS, and a token endpoint that
// mints real RS256 id_tokens. Every assertion below runs against genuinely
// signed material rather than a stub, because the thing under test is exactly
// whether signatures are checked.
type idp struct {
	t   *testing.T
	key *rsa.PrivateKey
	srv *httptest.Server

	issuerOverride   string
	audienceOverride string
	nonceOverride    *string
	expOverride      *time.Time
	signWithOther    bool
	other            *rsa.PrivateKey

	lastForm url.Values
	nonce    string
}

func newIDP(t *testing.T) *idp {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	p := &idp{t: t, key: key, other: other}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", p.jwks)
	mux.HandleFunc("/token", p.token)
	mux.HandleFunc("/authorize", func(http.ResponseWriter, *http.Request) {})

	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)

	return p
}

func (p *idp) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                 p.srv.URL,
		"authorization_endpoint": p.srv.URL + "/authorize",
		"token_endpoint":         p.srv.URL + "/token",
		"jwks_uri":               p.srv.URL + "/jwks",
	})
}

func (p *idp) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := p.key.PublicKey

	writeJSON(w, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": "test-key",
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

func (p *idp) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	p.lastForm = r.PostForm

	iss := p.srv.URL
	if p.issuerOverride != "" {
		iss = p.issuerOverride
	}

	aud := "test-client"
	if p.audienceOverride != "" {
		aud = p.audienceOverride
	}

	nonce := p.nonce
	if p.nonceOverride != nil {
		nonce = *p.nonceOverride
	}

	exp := time.Now().Add(time.Hour)
	if p.expOverride != nil {
		exp = *p.expOverride
	}

	claims := map[string]any{
		"iss":   iss,
		"aud":   aud,
		"sub":   "user-123",
		"email": "alice@example.com",
		"name":  "Alice",
		"exp":   exp.Unix(),
		"iat":   time.Now().Unix(),
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	signer := p.key
	if p.signWithOther {
		signer = p.other
	}

	writeJSON(w, map[string]any{
		"access_token": "upstream-access-token",
		"token_type":   "Bearer",
		"id_token":     signRS256(p.t, signer, "test-key", claims),
		"expires_in":   3600,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()

	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	payload, _ := json.Marshal(claims)

	signing := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)

	sum := sha256.Sum256([]byte(signing))

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func newStrategy(t *testing.T, p *idp, mutate func(*oauth2.Config)) *oauth2.Strategy {
	t.Helper()

	cfg := oauth2.Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		IssuerURL:    p.srv.URL,
		Scopes:       []string{"openid", "email"},
	}

	if mutate != nil {
		mutate(&cfg)
	}

	s, err := oauth2.NewWithContext(context.Background(), "idp", cfg, oauth2.Options{
		HTTPClient:       p.srv.Client(),
		CallbackBaseURL:  "https://app.example",
		CallbackBasePath: "/auth/login/callback",
	})
	if err != nil {
		t.Fatalf("new strategy: %v", err)
	}

	return s
}

// initiate runs the first leg and returns the authorize URL plus the flow
// cookie the callback will need.
func initiate(t *testing.T, s *oauth2.Strategy) (*url.URL, *http.Cookie) {
	t.Helper()

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://app.example/auth/login/pass/idp", nil)

	_, outcome, err := s.Login(rec, r)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}

	if outcome != strategy.OutcomePending {
		t.Fatalf("outcome = %v, want Pending", outcome)
	}

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected exactly one flow cookie, got %d: %+v", len(cookies), cookies)
	}

	return loc, cookies[0]
}

func TestInitiateSetsStateNoncePKCE(t *testing.T) {
	p := newIDP(t)
	s := newStrategy(t, p, nil)

	loc, flow := initiate(t, s)

	q := loc.Query()

	for _, k := range []string{"state", "nonce", "code_challenge"} {
		if q.Get(k) == "" {
			t.Errorf("authorize URL missing %s: %s", k, loc)
		}
	}

	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("challenge method = %q", got)
	}

	if got := q.Get("redirect_uri"); got != "https://app.example/auth/login/callback/idp" {
		t.Errorf("redirect_uri = %q", got)
	}

	// The regression that mattered: state used to live in a cookie created
	// with hardcoded Secure=false, HttpOnly=false.
	if !flow.HttpOnly {
		t.Error("flow cookie must be HttpOnly")
	}

	if flow.Name != "auth_flow_idp" {
		t.Errorf("flow cookie name = %q", flow.Name)
	}

	// State and nonce must not be readable from the redirect alone without
	// also holding the cookie — i.e. the cookie is not simply the state.
	if flow.Value == q.Get("state") {
		t.Error("flow cookie should not be the bare state value")
	}
}

func TestCallbackHappyPath(t *testing.T) {
	p := newIDP(t)
	s := newStrategy(t, p, nil)

	loc, flow := initiate(t, s)
	p.nonce = loc.Query().Get("nonce")

	rec := httptest.NewRecorder()
	r := callbackRequest(loc.Query().Get("state"), flow)

	id, outcome, err := s.Login(rec, r)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}

	if outcome != strategy.OutcomeContinue {
		t.Fatalf("outcome = %v (body %s)", outcome, rec.Body.String())
	}

	if id.Subject != "user-123" || id.Email != "alice@example.com" {
		t.Fatalf("identity = %+v", id)
	}

	if p.lastForm.Get("code_verifier") == "" {
		t.Error("PKCE verifier was not sent to the token endpoint")
	}

	if p.lastForm.Get("code") != "the-code" {
		t.Errorf("code = %q", p.lastForm.Get("code"))
	}
}

func callbackRequest(state string, flow *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet,
		"https://app.example/auth/login/callback/idp?code=the-code&state="+url.QueryEscape(state), nil)
	r.AddCookie(flow)

	return r
}

func TestCallbackRejectsForgedIDToken(t *testing.T) {
	p := newIDP(t)
	p.signWithOther = true

	s := newStrategy(t, p, nil)

	loc, flow := initiate(t, s)
	p.nonce = loc.Query().Get("nonce")

	rec := httptest.NewRecorder()

	_, outcome, _ := s.Login(rec, callbackRequest(loc.Query().Get("state"), flow))

	if outcome != strategy.OutcomeFailed {
		t.Fatal("an id_token signed by an unknown key must be rejected")
	}
}

func TestCallbackRejectsWrongAudience(t *testing.T) {
	p := newIDP(t)
	p.audienceOverride = "some-other-client"

	s := newStrategy(t, p, nil)

	loc, flow := initiate(t, s)
	p.nonce = loc.Query().Get("nonce")

	rec := httptest.NewRecorder()

	_, outcome, _ := s.Login(rec, callbackRequest(loc.Query().Get("state"), flow))

	if outcome != strategy.OutcomeFailed {
		t.Fatal("an id_token minted for another client must be rejected")
	}
}

func TestCallbackRejectsWrongIssuer(t *testing.T) {
	p := newIDP(t)
	p.issuerOverride = "https://evil.example"

	s := newStrategy(t, p, nil)

	loc, flow := initiate(t, s)
	p.nonce = loc.Query().Get("nonce")

	rec := httptest.NewRecorder()

	_, outcome, _ := s.Login(rec, callbackRequest(loc.Query().Get("state"), flow))

	if outcome != strategy.OutcomeFailed {
		t.Fatal("issuer mismatch must be rejected")
	}
}

func TestCallbackRejectsExpiredIDToken(t *testing.T) {
	p := newIDP(t)

	past := time.Now().Add(-2 * time.Hour)
	p.expOverride = &past

	s := newStrategy(t, p, nil)

	loc, flow := initiate(t, s)
	p.nonce = loc.Query().Get("nonce")

	rec := httptest.NewRecorder()

	_, outcome, _ := s.Login(rec, callbackRequest(loc.Query().Get("state"), flow))

	if outcome != strategy.OutcomeFailed {
		t.Fatal("expired id_token must be rejected")
	}
}

func TestCallbackRejectsReplayedNonce(t *testing.T) {
	p := newIDP(t)
	s := newStrategy(t, p, nil)

	// Two independent authorization requests. The IdP is told to echo the
	// *first* nonce, simulating an id_token captured from an earlier login.
	first, _ := initiate(t, s)
	second, flow2 := initiate(t, s)

	stale := first.Query().Get("nonce")
	p.nonceOverride = &stale

	if stale == second.Query().Get("nonce") {
		t.Fatal("nonces should differ between flows")
	}

	rec := httptest.NewRecorder()

	_, outcome, _ := s.Login(rec, callbackRequest(second.Query().Get("state"), flow2))

	if outcome != strategy.OutcomeFailed {
		t.Fatal("an id_token carrying another flow's nonce must be rejected")
	}
}

func TestCallbackRejectsStateMismatch(t *testing.T) {
	p := newIDP(t)
	s := newStrategy(t, p, nil)

	_, flow := initiate(t, s)

	rec := httptest.NewRecorder()

	_, outcome, _ := s.Login(rec, callbackRequest("not-the-state", flow))

	if outcome != strategy.OutcomeFailed {
		t.Fatal("state mismatch must be rejected")
	}

	if !strings.Contains(rec.Body.String(), "state_invalid") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestCallbackRejectsMissingFlowCookie(t *testing.T) {
	p := newIDP(t)
	s := newStrategy(t, p, nil)

	loc, _ := initiate(t, s)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet,
		"https://app.example/auth/login/callback/idp?code=x&state="+loc.Query().Get("state"), nil)

	_, outcome, _ := s.Login(rec, r)

	if outcome != strategy.OutcomeFailed {
		t.Fatal("a callback with no flow cookie must be rejected")
	}
}

func TestFlowCookieIsOneShot(t *testing.T) {
	p := newIDP(t)
	s := newStrategy(t, p, nil)

	loc, flow := initiate(t, s)
	p.nonce = loc.Query().Get("nonce")

	rec := httptest.NewRecorder()

	_, _, _ = s.Login(rec, callbackRequest(loc.Query().Get("state"), flow))

	cleared := false

	for _, c := range rec.Result().Cookies() {
		if c.Name == "auth_flow_idp" && c.MaxAge < 0 {
			cleared = true
		}
	}

	if !cleared {
		t.Error("flow cookie must be cleared after one use")
	}
}

func TestCallbackRedactsIdPErrorDetails(t *testing.T) {
	p := newIDP(t)
	s := newStrategy(t, p, nil)

	loc, flow := initiate(t, s)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet,
		"https://app.example/auth/login/callback/idp?error=access_denied&error_description=nope&state="+
			loc.Query().Get("state"), nil)
	r.AddCookie(flow)

	_, outcome, _ := s.Login(rec, r)

	if outcome != strategy.OutcomeFailed {
		t.Fatal("an IdP error response must fail the login")
	}

	if strings.Contains(rec.Body.String(), "access_denied") || strings.Contains(rec.Body.String(), "nope") {
		t.Errorf("the IdP's raw error should be redacted, got %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "authorization_denied") {
		t.Errorf("body = %s, want generic denial", rec.Body.String())
	}

	assertFlowCookieCleared(t, rec)
}

func TestCallbackDenialRequiresValidStateAndFlow(t *testing.T) {
	p := newIDP(t)
	s := newStrategy(t, p, nil)

	loc, flow := initiate(t, s)

	tests := []struct {
		name   string
		state  string
		cookie *http.Cookie
	}{
		{name: "missing flow cookie", state: loc.Query().Get("state")},
		{name: "state mismatch", state: "not-the-state", cookie: flow},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet,
				"https://app.example/auth/login/callback/idp?error=access_denied&state="+
					url.QueryEscape(tc.state), nil)
			if tc.cookie != nil {
				r.AddCookie(tc.cookie)
			}

			_, outcome, _ := s.Login(rec, r)
			if outcome != strategy.OutcomeFailed {
				t.Fatalf("outcome = %v, want failed", outcome)
			}
			if !strings.Contains(rec.Body.String(), "state_invalid") {
				t.Errorf("body = %s, want state_invalid", rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "authorization_denied") {
				t.Errorf("invalid flow was reported as a provider denial: %s", rec.Body.String())
			}
		})
	}
}

func assertFlowCookieCleared(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	for _, c := range rec.Result().Cookies() {
		if c.Name == "auth_flow_idp" && c.MaxAge < 0 {
			return
		}
	}

	t.Error("flow cookie must be cleared after callback denial")
}

// Without a key set and without a userinfo endpoint there is nothing that can
// vouch for the id_token, so the login must fail rather than trusting it.
func TestNoJWKSAndNoUserInfoFailsClosed(t *testing.T) {
	p := newIDP(t)

	s := newStrategy(t, p, func(c *oauth2.Config) {
		c.IssuerURL = ""
		c.AuthURL = p.srv.URL + "/authorize"
		c.TokenURL = p.srv.URL + "/token"
	})

	loc, flow := initiate(t, s)
	p.nonce = loc.Query().Get("nonce")

	rec := httptest.NewRecorder()

	_, outcome, _ := s.Login(rec, callbackRequest(loc.Query().Get("state"), flow))

	if outcome != strategy.OutcomeFailed {
		t.Fatal("unverifiable id_token with no userinfo fallback must fail closed")
	}
}

func TestSkipVerifyIsAnExplicitOptIn(t *testing.T) {
	p := newIDP(t)
	p.signWithOther = true

	s := newStrategy(t, p, func(c *oauth2.Config) {
		c.SkipIDTokenVerify = true
	})

	loc, flow := initiate(t, s)
	p.nonce = loc.Query().Get("nonce")

	rec := httptest.NewRecorder()

	id, outcome, _ := s.Login(rec, callbackRequest(loc.Query().Get("state"), flow))

	if outcome != strategy.OutcomeContinue {
		t.Fatalf("SkipIDTokenVerify should accept anything, got %v (%s)", outcome, rec.Body)
	}

	if id.Subject != "user-123" {
		t.Errorf("identity = %+v", id)
	}
}

func TestDiscoveryFailureIsReportedNotFatal(t *testing.T) {
	s, err := oauth2.NewWithContext(context.Background(), "idp", oauth2.Config{
		ClientID:  "c",
		IssuerURL: "http://127.0.0.1:1/nowhere",
		AuthURL:   "https://idp.example/authorize",
	}, oauth2.Options{})
	if err == nil {
		t.Error("expected a discovery error to be reported")
	}

	if s == nil {
		t.Fatal("strategy must still be usable with explicit endpoints")
	}

	if s.Name() != "idp" {
		t.Errorf("name = %q", s.Name())
	}
}
