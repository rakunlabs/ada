package oauth2_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/strategy"
	"github.com/rakunlabs/ada/middleware/auth/strategy/oauth2"
)

func TestRequireIDTokenCallback(t *testing.T) {
	for _, name := range []string{
		"valid signed token", "valid userinfo", "valid multiple audiences", "missing token", "wrong signature", "unavailable keys",
		"wrong issuer", "wrong audience", "wrong nonce", "missing nonce",
		"missing flow nonce", "expired", "missing expiry", "string expiry", "missing subject",
		"empty subject", "non-string subject", "wrong userinfo subject",
		"missing userinfo subject", "wrong authorized party", "multiple audiences without authorized party",
	} {
		t.Run(name, func(t *testing.T) {
			p := newIDP(t)
			p.userInfo = map[string]any{"sub": "user-123", "name": "Userinfo Name"}
			p.mutateClaims = func(c map[string]any) {
				switch name {
				case "wrong issuer":
					c["iss"] = p.srv.URL + "/"
				case "wrong audience":
					c["aud"] = "another-client"
				case "wrong nonce":
					c["nonce"] = "another-flow"
				case "missing nonce":
					delete(c, "nonce")
				case "expired":
					c["exp"] = time.Now().Add(-time.Hour).Unix()
				case "missing expiry":
					delete(c, "exp")
				case "string expiry":
					c["exp"] = "4102444800junk"
				case "missing subject":
					delete(c, "sub")
				case "empty subject":
					c["sub"] = ""
				case "non-string subject":
					c["sub"] = 123
				case "wrong authorized party":
					c["azp"] = "another-client"
				case "multiple audiences without authorized party":
					c["aud"] = []string{"test-client", "another-client"}
				case "valid multiple audiences":
					c["aud"] = []string{"test-client", "another-client"}
					c["azp"] = "test-client"
				}
			}
			p.omitIDToken = name == "missing token"
			p.signWithOther = name == "wrong signature"
			if name == "wrong userinfo subject" {
				p.userInfo["sub"] = "another-user"
			}
			if name == "missing userinfo subject" {
				delete(p.userInfo, "sub")
			}
			var store oauth2.FlowStore
			if name == "missing flow nonce" {
				store = &missingNonceStore{}
			}
			s := newStrategy(t, p, func(c *oauth2.Config) {
				c.RequireIDToken = true
				if name == "unavailable keys" {
					c.JWKSURL = p.srv.URL + "/missing"
				}
				if name != "valid signed token" && name != "valid multiple audiences" {
					c.UserInfoURL = p.srv.URL + "/userinfo"
				}
			}, store)
			loc, flow := initiate(t, s)
			p.nonce = loc.Query().Get("nonce")
			if p.nonce == "" || loc.Query().Get("code_challenge_method") != "S256" {
				t.Fatal("missing nonce or PKCE")
			}
			rec := httptest.NewRecorder()
			id, outcome, err := s.Login(rec, callbackRequest(loc.Query().Get("state"), flow))
			if err != nil {
				t.Fatal(err)
			}
			valid := strings.HasPrefix(name, "valid")
			if valid {
				if outcome != strategy.OutcomeContinue || id == nil || id.Subject != "user-123" {
					t.Fatalf("valid login: identity=%+v outcome=%v body=%s", id, outcome, rec.Body)
				}
				if name == "valid userinfo" && id.Name != "Userinfo Name" {
					t.Fatalf("userinfo not used: %+v", id)
				}
			} else if outcome != strategy.OutcomeFailed || id != nil {
				t.Fatalf("invalid login accepted: identity=%+v outcome=%v", id, outcome)
			}
			wantCalls := int32(0)
			if name == "valid userinfo" || strings.Contains(name, "userinfo subject") {
				wantCalls = 1
			}
			if got := p.userInfoCalls.Load(); got != wantCalls {
				t.Fatalf("userinfo calls=%d, want %d (no fallback on verification failure)", got, wantCalls)
			}
		})
	}
}

// Simulate corrupt server state, rather than the retired client-held JSON.
type missingNonceStore struct{ flow oauth2.FlowData }

func (m *missingNonceStore) Save(_ context.Context, _ string, f oauth2.FlowData) error {
	f.Nonce = ""
	m.flow = f
	return nil
}
func (m *missingNonceStore) Consume(context.Context, string) (oauth2.FlowData, error) {
	f := m.flow
	m.flow = oauth2.FlowData{}
	return f, nil
}

func TestRequireIDTokenRejectsUnsafeConfiguration(t *testing.T) {
	p := newIDP(t)
	for _, name := range []string{"no keys", "no issuer", "no client", "no openid", "different audience", "skip verify", "disable nonce", "password flow", "discovery failure"} {
		t.Run(name, func(t *testing.T) {
			cfg := oauth2.Config{
				RequireIDToken: true, ClientID: "test-client", Scopes: []string{"openid"},
				IssuerURL: p.srv.URL, AuthURL: p.srv.URL + "/authorize",
				UserInfoURL: p.srv.URL + "/userinfo",
			}
			opts := oauth2.Options{}
			switch name {
			case "no keys":
				// A valid discovery document without jwks_uri must not permit userinfo fallback.
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					writeJSON(w, map[string]string{"issuer": "http://" + r.Host})
				}))
				defer srv.Close()
				cfg.IssuerURL = srv.URL
			case "no issuer":
				cfg.IssuerURL = ""
				cfg.JWKSURL = p.srv.URL + "/jwks"
			case "no client":
				cfg.ClientID = ""
			case "no openid":
				cfg.Scopes = []string{"email"}
			case "different audience":
				cfg.Audience = "another-client"
			case "skip verify":
				cfg.SkipIDTokenVerify = true
			case "disable nonce":
				cfg.DisableNonce = true
			case "password flow":
				cfg.PasswordFlow = true
			case "discovery failure":
				cfg.IssuerURL = p.srv.URL + "/missing"
				cfg.JWKSURL = p.srv.URL + "/jwks"
			}
			s, err := oauth2.NewWithContext(context.Background(), "idp", cfg, opts)
			if err == nil {
				t.Fatal("unsafe strict configuration accepted")
			}
			for _, s := range []*oauth2.Strategy{s, oauth2.New("idp", cfg, opts)} {
				for _, method := range []string{http.MethodGet, http.MethodPost} {
					rec := httptest.NewRecorder()
					id, outcome, _ := s.Login(rec, httptest.NewRequest(method, "https://app.example/login", nil))
					if id != nil || outcome != strategy.OutcomeFailed || rec.Code != http.StatusServiceUnavailable {
						t.Fatalf("invalid strategy not disabled: id=%+v outcome=%v status=%d", id, outcome, rec.Code)
					}
				}
			}
		})
	}
}

func TestDiscoveryIssuerExactMatch(t *testing.T) {
	for _, tc := range []struct {
		name, requestedPath, returnedPath string
		valid                             bool
	}{
		{"root", "", "", true},
		{"root slash", "/", "/", true},
		{"path", "/tenant", "/tenant", true},
		{"path slash", "/tenant/", "/tenant/", true},
		{"extra slash", "", "/", false},
		{"missing slash", "/", "", false},
		{"different path", "/tenant", "/other", false},
		{"path missing slash", "/tenant/", "/tenant", false},
		{"different issuer", "", "https://other.example", false},
		{"missing issuer", "", "missing", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wantPath := strings.TrimSuffix(tc.requestedPath, "/") + "/.well-known/openid-configuration"
				if r.URL.Path != wantPath {
					t.Errorf("discovery path=%q, want %q", r.URL.Path, wantPath)
				}
				issuer := "http://" + r.Host + tc.returnedPath
				if tc.name == "different issuer" {
					issuer = tc.returnedPath
				} else if tc.name == "missing issuer" {
					issuer = ""
				}
				writeJSON(w, map[string]string{"issuer": issuer, "authorization_endpoint": "https://untrusted.example/auth"})
			}))
			defer srv.Close()
			cfg := oauth2.Config{IssuerURL: srv.URL + tc.requestedPath}
			s, err := oauth2.NewWithContext(context.Background(), "idp", cfg, oauth2.Options{})
			if tc.valid {
				if err != nil || s.Discovery() == nil {
					t.Fatalf("exact issuer rejected: %v", err)
				}
				return
			}
			if !errors.Is(err, oauth2.ErrIssuerMismatch) || s.Discovery() != nil {
				t.Fatalf("mismatched discovery accepted/cached: %v", err)
			}
			for _, s := range []*oauth2.Strategy{s, oauth2.New("idp", cfg, oauth2.Options{})} {
				rec := httptest.NewRecorder()
				id, outcome, _ := s.Login(rec, httptest.NewRequest("GET", "https://app.example/login", nil))
				if id != nil || outcome != strategy.OutcomeFailed || rec.Header().Get("Location") != "" {
					t.Fatal("mismatched issuer strategy allowed login")
				}
			}
		})
	}
}

func TestGenericOAuthUserinfoWithoutIDToken(t *testing.T) {
	p := newIDP(t)
	p.omitIDToken = true
	p.userInfo = map[string]any{"login": "octocat", "email": "octocat@example.com"}
	s, err := oauth2.NewWithContext(context.Background(), "idp", oauth2.Config{
		ClientID: "test-client", Scopes: []string{"read:user"},
		AuthURL: p.srv.URL + "/authorize", TokenURL: p.srv.URL + "/token",
		UserInfoURL: p.srv.URL + "/userinfo",
	}, oauth2.Options{CallbackBasePath: "/auth/login/callback", XUserClaims: oauth2.XUserClaims{Subject: []string{"login"}}})
	if err != nil {
		t.Fatal(err)
	}
	loc, flow := initiate(t, s)
	rec := httptest.NewRecorder()
	id, outcome, err := s.Login(rec, callbackRequest(loc.Query().Get("state"), flow))
	if err != nil || outcome != strategy.OutcomeContinue || id == nil || id.Subject != "octocat" {
		t.Fatalf("generic OAuth login: identity=%+v outcome=%v err=%v body=%s", id, outcome, err, rec.Body)
	}
}

func TestRequireIDTokenSubjectCannotBeRemapped(t *testing.T) {
	p := newIDP(t)
	s, err := oauth2.NewWithContext(context.Background(), "idp", oauth2.Config{
		RequireIDToken: true, ClientID: "test-client", Scopes: []string{"openid"}, IssuerURL: p.srv.URL,
	}, oauth2.Options{CallbackBasePath: "/auth/login/callback", XUserClaims: oauth2.XUserClaims{Subject: []string{"email"}}})
	if err != nil {
		t.Fatal(err)
	}
	loc, flow := initiate(t, s)
	p.nonce = loc.Query().Get("nonce")
	rec := httptest.NewRecorder()
	id, outcome, err := s.Login(rec, callbackRequest(loc.Query().Get("state"), flow))
	if err != nil || outcome != strategy.OutcomeContinue || id == nil || id.Subject != "user-123" {
		t.Fatalf("strict subject remapped: identity=%+v outcome=%v err=%v", id, outcome, err)
	}
}

func TestGenericOAuthVerifiedIDTokenUserinfoSubject(t *testing.T) {
	for _, name := range []string{"missing userinfo sub", "missing token sub", "matching subs", "mismatched subs"} {
		t.Run(name, func(t *testing.T) {
			p := newIDP(t)
			p.userInfo = map[string]any{"login": "alice", "sub": "user-123"}
			switch name {
			case "missing userinfo sub":
				delete(p.userInfo, "sub")
			case "missing token sub":
				p.mutateClaims = func(c map[string]any) { delete(c, "sub") }
			case "mismatched subs":
				p.userInfo["sub"] = "another-user"
			}
			s, err := oauth2.NewWithContext(context.Background(), "idp", oauth2.Config{
				ClientID: "test-client", IssuerURL: p.srv.URL, UserInfoURL: p.srv.URL + "/userinfo",
			}, oauth2.Options{CallbackBasePath: "/auth/login/callback", XUserClaims: oauth2.XUserClaims{Subject: []string{"login"}}})
			if err != nil {
				t.Fatal(err)
			}
			loc, flow := initiate(t, s)
			p.nonce = loc.Query().Get("nonce")
			rec := httptest.NewRecorder()
			id, outcome, err := s.Login(rec, callbackRequest(loc.Query().Get("state"), flow))
			if err != nil {
				t.Fatal(err)
			}
			if name == "mismatched subs" {
				if id != nil || outcome != strategy.OutcomeFailed {
					t.Fatalf("mismatched subs accepted: %+v, %v", id, outcome)
				}
			} else if id == nil || outcome != strategy.OutcomeContinue || id.Subject != "alice" {
				t.Fatalf("generic subject mapping failed: %+v, %v, %s", id, outcome, rec.Body)
			}
		})
	}
}

func TestRequireIDTokenRejectsCriticalHeaders(t *testing.T) {
	for _, tc := range []struct {
		name string
		crit any
	}{
		{"unsupported extension", []string{"extension"}},
		{"registered header", []string{"alg"}},
		{"empty", []string{}},
		{"null", nil},
		{"malformed", "extension"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newIDP(t)
			// The protected header is included before signing with the trusted key.
			p.tokenHeaders = map[string]any{"crit": tc.crit, "extension": true}
			s := newStrategy(t, p, func(c *oauth2.Config) { c.RequireIDToken = true })
			loc, flow := initiate(t, s)
			p.nonce = loc.Query().Get("nonce")
			rec := httptest.NewRecorder()
			id, outcome, err := s.Login(rec, callbackRequest(loc.Query().Get("state"), flow))
			if err != nil || id != nil || outcome != strategy.OutcomeFailed {
				t.Fatalf("critical header accepted: %+v, %v, %v", id, outcome, err)
			}
		})
	}
}

func TestRequireIDTokenSignedUserinfo(t *testing.T) {
	for _, name := range []string{
		"valid", "valid audience array", "missing issuer", "wrong issuer",
		"missing audience", "wrong audience", "wrong subject", "missing subject", "critical header",
	} {
		t.Run(name, func(t *testing.T) {
			p := newIDP(t)
			// Signed UserInfo requires iss/aud/sub, not ID-token exp or nonce.
			claims := map[string]any{"iss": p.srv.URL, "aud": "test-client", "sub": "user-123", "name": "Signed Userinfo"}
			var headers map[string]any
			switch name {
			case "valid audience array":
				claims["aud"] = []string{"test-client"}
			case "missing issuer":
				delete(claims, "iss")
			case "wrong issuer":
				claims["iss"] = p.srv.URL + "/"
			case "missing audience":
				delete(claims, "aud")
			case "wrong audience":
				claims["aud"] = "another-client"
			case "wrong subject":
				claims["sub"] = "another-user"
			case "missing subject":
				delete(claims, "sub")
			case "critical header":
				headers = map[string]any{"crit": []string{"extension"}, "extension": true}
			}
			p.userInfoJWT = signRS256(t, p.key, "test-key", claims, headers)
			s := newStrategy(t, p, func(c *oauth2.Config) {
				c.RequireIDToken = true
				c.UserInfoURL = p.srv.URL + "/userinfo"
			})
			loc, flow := initiate(t, s)
			p.nonce = loc.Query().Get("nonce")
			rec := httptest.NewRecorder()
			id, outcome, err := s.Login(rec, callbackRequest(loc.Query().Get("state"), flow))
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(name, "valid") {
				if id == nil || outcome != strategy.OutcomeContinue || id.Subject != "user-123" || id.Name != "Signed Userinfo" {
					t.Fatalf("signed userinfo rejected: %+v, %v, %s", id, outcome, rec.Body)
				}
			} else if id != nil || outcome != strategy.OutcomeFailed {
				t.Fatalf("invalid signed userinfo accepted: %+v, %v", id, outcome)
			}
			if p.userInfoCalls.Load() != 1 {
				t.Fatal("signed userinfo endpoint was not called exactly once")
			}
		})
	}
}
