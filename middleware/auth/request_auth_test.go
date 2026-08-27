package auth_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
	"github.com/rakunlabs/ada/middleware/auth/strategy/apikey"
	"github.com/rakunlabs/ada/middleware/auth/strategy/basic"
	"github.com/rakunlabs/ada/middleware/auth/strategy/header"
	"github.com/rakunlabs/ada/middleware/auth/strategy/local"
	"github.com/rakunlabs/ada/middleware/auth/strategy/oauth2"
)

// whoami reports the authenticated subject so tests can assert not just
// that a request was allowed, but that it was allowed *as the right user*.
func whoami() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identity.FromContext(r.Context())
		if id == nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("no identity in context"))

			return
		}

		_, _ = w.Write([]byte(id.Subject + "@" + id.Provider))
	})
}

// keyValidator accepts exactly one key, and reports a backend fault for a
// designated one so the 401-vs-500 split can be exercised.
func keyValidator(good string) apikey.Validator {
	return func(_ context.Context, key string) (*identity.Identity, error) {
		switch key {
		case good:
			return &identity.Identity{Subject: "svc"}, nil
		case "boom":
			return nil, errors.New("database is on fire")
		default:
			return nil, apikey.ErrInvalidKey
		}
	}
}

func newAPIKeyAuth(t *testing.T, cfg auth.Config, good string) *auth.Auth {
	t.Helper()

	cfg.UI.ExternalFolder = true
	a := auth.New(cfg)
	a.Strategy(apikey.New("apikey", keyValidator(good), apikey.WithHeaders("Authorization")))

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	return a
}

// TestRequireAcceptsAPIKey is the point of the whole feature: a client
// holding an API key must be able to call a protected route directly.
// Before request authentication existed, Require only understood the
// session cookie, so this request was answered with a 307 to an
// interactive login page the client could never complete.
func TestRequireAcceptsAPIKey(t *testing.T) {
	a := newAPIKeyAuth(t, auth.Config{}, "s3cret")
	handler := a.Require()(whoami())

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s loc=%q", rec.Code, rec.Body.String(), rec.Header().Get("Location"))
	}
	if got := rec.Body.String(); got != "svc@apikey" {
		t.Errorf("identity not attached to context: %q", got)
	}
}

// TestRequireAPIKeyOutcomes covers the three ways a request can be
// resolved, including the distinction that matters most: a bad credential
// must be rejected outright, not quietly downgraded to anonymous and
// redirected to a login page where the real cause disappears.
func TestRequireAPIKeyOutcomes(t *testing.T) {
	a := newAPIKeyAuth(t, auth.Config{}, "s3cret")
	handler := a.Require()(whoami())

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
		wantChal   bool
	}{
		{
			name:       "valid key authenticates",
			authHeader: "Bearer s3cret",
			wantStatus: http.StatusOK,
		},
		{
			name:       "rejected key is a 401, not a redirect",
			authHeader: "Bearer wrong",
			wantStatus: http.StatusUnauthorized,
			wantChal:   true,
		},
		{
			name: "no credentials falls through to the session redirect",
			// The cookie path is untouched: browsers still get the login page.
			wantStatus: http.StatusTemporaryRedirect,
		},
		{
			name: "validator fault is a 500, not a 401",
			// Telling a caller "your token is invalid" when the token store
			// is down sends them off to rotate a perfectly good credential.
			authHeader: "Bearer boom",
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("expected %d, got %d body=%s", tt.wantStatus, rec.Code, rec.Body.String())
			}
			if tt.wantChal && rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("401 should advertise WWW-Authenticate so a client can discover how to authenticate")
			}
		})
	}
}

// TestRequireAcceptsBasicAuth checks the other verified request
// credential. RFC 7617 clients re-send the header on every request; they
// have no notion of exchanging it for a cookie first.
func TestRequireAcceptsBasicAuth(t *testing.T) {
	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}})
	a.Strategy(basic.New("basic", func(_ context.Context, user, pass string) (*identity.Identity, error) {
		if user == "alice" && pass == "secret" {
			return &identity.Identity{Subject: user}, nil
		}

		return nil, basic.ErrInvalidCredentials
	}))
	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	handler := a.Require()(whoami())

	tests := []struct {
		name       string
		creds      string
		wantStatus int
	}{
		{name: "valid", creds: "alice:secret", wantStatus: http.StatusOK},
		{name: "invalid", creds: "alice:wrong", wantStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(tt.creds)))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("expected %d, got %d body=%s", tt.wantStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestRequireRequestCredentialsWinOverCookie pins the precedence. A client
// that deliberately sends an API key must be authorized as that key, even
// if a session cookie also rides along — otherwise a narrow token would
// silently inherit whatever the browser session happens to grant, which is
// the opposite of what the caller asked for.
func TestRequireRequestCredentialsWinOverCookie(t *testing.T) {
	a := newAPIKeyAuth(t, auth.Config{}, "s3cret")
	handler := a.Require()(whoami())

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: "some-session-id"})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "svc@apikey" {
		t.Errorf("expected the key's identity, got %q", got)
	}
}

// TestRequireDisableRequestAuth verifies the escape hatch still produces
// the old cookie-only behavior.
func TestRequireDisableRequestAuth(t *testing.T) {
	a := newAPIKeyAuth(t, auth.Config{DisableRequestAuth: true}, "s3cret")
	handler := a.Require()(whoami())

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected the legacy redirect, got %d", rec.Code)
	}
}

// TestRequireIgnoresInteractiveStrategies makes sure the new path is inert
// for deployments that only run browser strategies — those must keep
// redirecting, including when an unrelated Authorization header rides
// along on the request.
func TestRequireIgnoresInteractiveStrategies(t *testing.T) {
	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}})
	a.Strategy(local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
		return nil, local.ErrInvalidCredentials
	}))
	a.Strategy(oauth2.New("google", oauth2.Config{
		ClientID: "client",
		AuthURL:  "https://idp.example.com/authorize",
	}, oauth2.Options{CallbackBaseURL: "https://app.example.com"}))

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	handler := a.Require()(whoami())

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer something")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected redirect, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestRequireHeaderStrategyStaysLoginOnly pins the deliberate omission:
// the proxy-header strategy verifies nothing, so letting it authorize
// every protected route would make a single misrouted deployment a full
// authentication bypass. It stays confined to the login endpoint.
func TestRequireHeaderStrategyStaysLoginOnly(t *testing.T) {
	if _, ok := any(header.New("proxy")).(strategy.RequestAuthenticator); ok {
		t.Fatal("header strategy must not implement RequestAuthenticator")
	}

	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}})
	a.Strategy(header.New("proxy"))
	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	handler := a.Require()(whoami())

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Forwarded-User", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("spoofable proxy headers must not authenticate a protected route")
	}
}

// TestRegistryAuthenticateRequestStopsAtFirstRejection documents the walk
// order guarantee: once a strategy claims a request and rejects it, the
// walk stops. Continuing would let a caller probe which strategy owns
// which header by watching the response change, and would turn a clear
// 401 into a redirect.
func TestRegistryAuthenticateRequestStopsAtFirstRejection(t *testing.T) {
	reg := strategy.NewRegistry()

	// Both read Authorization; the first one rejects.
	if err := reg.Add(apikey.New("first", keyValidator("never-sent"), apikey.WithHeaders("Authorization"))); err != nil {
		t.Fatalf("add first: %v", err)
	}
	if err := reg.Add(apikey.New("second", keyValidator("open-sesame"), apikey.WithHeaders("Authorization"))); err != nil {
		t.Fatalf("add second: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer open-sesame")

	id, err := reg.AuthenticateRequest(context.Background(), req)
	if !errors.Is(err, strategy.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got id=%+v err=%v", id, err)
	}
}

// TestRegistryAuthenticateRequestSkipsNonClaimants confirms the fall-through
// half: a strategy that sees none of its credentials must not block a later
// one that does.
func TestRegistryAuthenticateRequestSkipsNonClaimants(t *testing.T) {
	reg := strategy.NewRegistry()

	if err := reg.Add(apikey.New("by-custom-header", keyValidator("nope"), apikey.WithHeaders("X-Custom-Key"))); err != nil {
		t.Fatalf("add first: %v", err)
	}
	if err := reg.Add(apikey.New("by-authorization", keyValidator("open-sesame"), apikey.WithHeaders("Authorization"))); err != nil {
		t.Fatalf("add second: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer open-sesame")

	id, err := reg.AuthenticateRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("AuthenticateRequest: %v", err)
	}
	if id.Provider != "by-authorization" {
		t.Errorf("wrong strategy authenticated: %+v", id)
	}
}

// TestRegistryAuthenticateRequestNoCredentials is the anonymous case.
func TestRegistryAuthenticateRequestNoCredentials(t *testing.T) {
	reg := strategy.NewRegistry()
	if err := reg.Add(apikey.New("apikey", keyValidator("x"), apikey.WithHeaders("Authorization"))); err != nil {
		t.Fatalf("add: %v", err)
	}

	if reg.HasRequestAuthenticator() != true {
		t.Error("registry should report a request authenticator")
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if _, err := reg.AuthenticateRequest(context.Background(), req); !errors.Is(err, strategy.ErrNoCredentials) {
		t.Errorf("expected ErrNoCredentials, got %v", err)
	}
}
