package oauth2_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth/strategy/oauth2"
)

// TestSetCallbackBasePath_UsedWhenEmpty verifies that an auto-wired callback
// base path (e.g. pushed by the auth middleware from cfg.Base) is honored
// when the caller did not set CallbackBasePath explicitly.
func TestSetCallbackBasePath_UsedWhenEmpty(t *testing.T) {
	s := oauth2.New("google", oauth2.Config{
		ClientID: "client",
		AuthURL:  "https://idp.example.com/authorize",
	}, oauth2.Options{
		CallbackBaseURL: "https://app.example.com",
		// CallbackBasePath intentionally left empty.
	})

	s.SetCallbackBasePath("/api/v1/login/callback")

	req := httptest.NewRequest("GET", "/login/pass/google", nil)
	rec := httptest.NewRecorder()

	_, _, _ = s.Login(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307 redirect, got %d body=%s", rec.Code, rec.Body.String())
	}

	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}

	got := u.Query().Get("redirect_uri")
	want := "https://app.example.com/api/v1/login/callback/google"
	if got != want {
		t.Errorf("redirect_uri: got %q, want %q", got, want)
	}
}

// TestSetCallbackBasePath_DoesNotOverrideExplicit verifies that an explicit
// Options.CallbackBasePath always wins over a later SetCallbackBasePath call.
func TestSetCallbackBasePath_DoesNotOverrideExplicit(t *testing.T) {
	s := oauth2.New("google", oauth2.Config{
		ClientID: "client",
		AuthURL:  "https://idp.example.com/authorize",
	}, oauth2.Options{
		CallbackBaseURL:  "https://app.example.com",
		CallbackBasePath: "/explicit/callback",
	})

	s.SetCallbackBasePath("/should/be/ignored")

	req := httptest.NewRequest("GET", "/login/pass/google", nil)
	rec := httptest.NewRecorder()

	_, _, _ = s.Login(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307 redirect, got %d body=%s", rec.Code, rec.Body.String())
	}

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "redirect_uri=https%3A%2F%2Fapp.example.com%2Fexplicit%2Fcallback%2Fgoogle") {
		t.Errorf("redirect_uri: got %q, want explicit path to survive", loc)
	}
}

func TestCallbackOriginIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	s := oauth2.New("google", oauth2.Config{
		ClientID: "client",
		AuthURL:  "https://idp.example.com/authorize",
	}, oauth2.Options{TrustedProxies: []string{"10.0.0.0/8"}})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://internal.example/login/pass/google", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "attacker.example")

	_, _, _ = s.Login(rec, req)
	if got := redirectURI(t, rec); got != "http://internal.example/auth/callback/google" {
		t.Fatalf("redirect_uri = %q, want direct request origin", got)
	}
}

func TestCallbackOriginUsesForwardedHeadersFromTrustedPeer(t *testing.T) {
	s := oauth2.New("google", oauth2.Config{
		ClientID: "client",
		AuthURL:  "https://idp.example.com/authorize",
	}, oauth2.Options{TrustedProxies: []string{"10.0.0.0/8"}})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://internal.example/login/pass/google", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "Public.Example:8443")

	_, _, _ = s.Login(rec, req)
	if got := redirectURI(t, rec); got != "https://public.example:8443/auth/callback/google" {
		t.Fatalf("redirect_uri = %q, want trusted forwarded origin", got)
	}
}

func TestCallbackOriginUnsafeLegacyTrustAllRequiresExplicitOptIn(t *testing.T) {
	s := oauth2.New("google", oauth2.Config{
		ClientID: "client",
		AuthURL:  "https://idp.example.com/authorize",
	}, oauth2.Options{UnsafeTrustAllForwardedHeaders: true})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://internal.example/login/pass/google", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "legacy-public.example")

	_, _, _ = s.Login(rec, req)
	if got := redirectURI(t, rec); got != "https://legacy-public.example/auth/callback/google" {
		t.Fatalf("redirect_uri = %q, want explicit unsafe forwarded origin", got)
	}
}

func TestCallbackOriginsAreValidated(t *testing.T) {
	for name, opts := range map[string]oauth2.Options{
		"fixed origin": {
			CallbackBaseURL: "https://app.example/callback",
		},
		"trusted forwarded origin": {
			TrustedProxies: []string{"10.0.0.0/8"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := oauth2.New("google", oauth2.Config{
				ClientID: "client",
				AuthURL:  "https://idp.example.com/authorize",
			}, opts)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://internal.example/login/pass/google", nil)
			req.RemoteAddr = "10.1.2.3:1234"
			req.Header.Set("X-Forwarded-Proto", "javascript")
			req.Header.Set("X-Forwarded-Host", "public.example")

			_, _, _ = s.Login(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("code = %d, want 500 (%s)", rec.Code, rec.Body)
			}
			if rec.Header().Get("Location") != "" {
				t.Fatalf("invalid origin produced redirect %q", rec.Header().Get("Location"))
			}
		})
	}
}

func redirectURI(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}

	return u.Query().Get("redirect_uri")
}

func TestNewOwnsMutableScopeConfig(t *testing.T) {
	scopes := []string{"openid", "email"}
	s := oauth2.New("google", oauth2.Config{
		ClientID: "client",
		AuthURL:  "https://idp.example.com/authorize",
		Scopes:   scopes,
	}, oauth2.Options{CallbackBaseURL: "https://app.example.com"})
	scopes[0] = "caller-mutated"

	rec := httptest.NewRecorder()
	_, _, _ = s.Login(rec, httptest.NewRequest(http.MethodGet, "/login/pass/google", nil))
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if got := u.Query().Get("scope"); got != "openid email" {
		t.Fatalf("scope = %q, want original snapshot", got)
	}
}

func TestInternalOAuthErrorIsGeneric(t *testing.T) {
	const internal = "http://internal.example/%zz-secret"
	s := oauth2.New("google", oauth2.Config{
		ClientID: "client",
		AuthURL:  internal,
	}, oauth2.Options{CallbackBaseURL: "https://app.example.com"})

	rec := httptest.NewRecorder()
	_, _, _ = s.Login(rec, httptest.NewRequest(http.MethodGet, "/login/pass/google", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500 (%s)", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), internal) || strings.Contains(rec.Body.String(), "invalid URL escape") {
		t.Fatalf("response leaked internal error: %s", rec.Body)
	}
}

func TestProviderResponseBodyIsNotReturned(t *testing.T) {
	const providerBody = "database host internal-db.example password=hunter2"
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(providerBody))
	}))
	t.Cleanup(provider.Close)

	s := oauth2.New("provider", oauth2.Config{
		ClientID:     "client",
		ClientSecret: "secret",
		TokenURL:     provider.URL,
		PasswordFlow: true,
	}, oauth2.Options{})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login/pass/provider",
		strings.NewReader(`{"username":"alice","password":"pw"}`))
	r.Header.Set("Content-Type", "application/json")
	_, _, _ = s.Login(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 (%s)", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), providerBody) || strings.Contains(rec.Body.String(), "internal-db.example") {
		t.Fatalf("provider body leaked: %s", rec.Body)
	}
}
