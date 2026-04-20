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
