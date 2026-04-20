package apikey_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy/apikey"
)

// staticValidator returns a fixed Identity for a matching key and
// ErrInvalidKey otherwise. Simple stand-in for tests that don't care about
// the validator's internals.
func staticValidator(wantKey string) apikey.Validator {
	return func(_ context.Context, got string) (*identity.Identity, error) {
		if got != wantKey {
			return nil, apikey.ErrInvalidKey
		}
		return &identity.Identity{Subject: "test"}, nil
	}
}

func login(s *apikey.Strategy, headers map[string]string) (*httptest.ResponseRecorder, *identity.Identity) {
	req := httptest.NewRequest(http.MethodPost, "/auth/login/apikey", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	id, _, _ := s.Login(rec, req)
	return rec, id
}

func TestDefault_AcceptsAuthorizationBearer(t *testing.T) {
	s := apikey.New("apikey", staticValidator("k1"))
	rec, id := login(s, map[string]string{"Authorization": "Bearer k1"})
	if id == nil {
		t.Fatalf("expected success, got status=%d", rec.Code)
	}
}

func TestDefault_FallsBackToXAPIKey(t *testing.T) {
	s := apikey.New("apikey", staticValidator("k1"))
	rec, id := login(s, map[string]string{"X-API-Key": "k1"})
	if id == nil {
		t.Fatalf("default fallback to X-API-Key should work, status=%d", rec.Code)
	}
}

// TestWithHeaders_Single_DisablesFallback verifies that restricting the
// strategy to a single header causes the ada-side X-API-Key fallback to be
// dropped, which is the behavior pika wants for its Access Tokens.
func TestWithHeaders_Single_DisablesFallback(t *testing.T) {
	s := apikey.New("apikey", staticValidator("k1"),
		apikey.WithHeaders("Authorization"),
	)

	if _, id := login(s, map[string]string{"Authorization": "Bearer k1"}); id == nil {
		t.Error("Authorization should be accepted")
	}

	rec, id := login(s, map[string]string{"X-API-Key": "k1"})
	if id != nil {
		t.Error("X-API-Key must be rejected when WithHeaders restricts to Authorization")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("X-API-Key: expected 401, got %d", rec.Code)
	}
}

// TestWithHeaders_Multiple_EnforcesPriority verifies that WithHeaders honors
// the caller's priority order — the first non-empty header wins, later ones
// are tried only when earlier ones are absent.
func TestWithHeaders_Multiple_EnforcesPriority(t *testing.T) {
	// Validator only accepts "goodkey"; if the strategy reads from the
	// wrong header it'll get "badkey" and fail.
	s := apikey.New("apikey", staticValidator("goodkey"),
		apikey.WithHeaders("X-First", "X-Second"),
	)

	// Both present: X-First wins.
	if _, id := login(s, map[string]string{
		"X-First":  "goodkey",
		"X-Second": "badkey",
	}); id == nil {
		t.Error("X-First should have priority over X-Second")
	}

	// Only X-Second present: used as fallback.
	if _, id := login(s, map[string]string{"X-Second": "goodkey"}); id == nil {
		t.Error("X-Second should be used when X-First is absent")
	}
}

// TestWithAdditionalHeader_PreservesDefaults verifies that appending one
// header keeps the default Authorization → X-API-Key chain intact.
func TestWithAdditionalHeader_PreservesDefaults(t *testing.T) {
	s := apikey.New("apikey", staticValidator("k1"),
		apikey.WithAdditionalHeader("X-Pika-Token"),
	)

	// Default Authorization still works.
	if _, id := login(s, map[string]string{"Authorization": "Bearer k1"}); id == nil {
		t.Error("Authorization default should still work with WithAdditionalHeader")
	}
	// Default X-API-Key fallback still works.
	if _, id := login(s, map[string]string{"X-API-Key": "k1"}); id == nil {
		t.Error("X-API-Key default should still work with WithAdditionalHeader")
	}
	// New custom header also works.
	if _, id := login(s, map[string]string{"X-Pika-Token": "k1"}); id == nil {
		t.Error("custom X-Pika-Token header should be accepted")
	}
}

// TestBearerPrefixStripping verifies that Bearer prefix handling applies
// to ALL configured headers (not just Authorization), since there's no
// reason a custom header couldn't carry a `Bearer ` prefix too. Disabled
// when WithBearerPrefix(false).
func TestBearerPrefixStripping(t *testing.T) {
	// Default (true): strips Bearer on any header.
	s := apikey.New("apikey", staticValidator("k1"),
		apikey.WithHeaders("X-Custom"),
	)
	if _, id := login(s, map[string]string{"X-Custom": "Bearer k1"}); id == nil {
		t.Error("Bearer prefix should be stripped on custom headers too (default behavior)")
	}

	// Disabled: raw value reaches validator.
	sRaw := apikey.New("apikey",
		func(_ context.Context, got string) (*identity.Identity, error) {
			if got != "Bearer k1" {
				return nil, apikey.ErrInvalidKey
			}
			return &identity.Identity{Subject: "test"}, nil
		},
		apikey.WithHeaders("X-Custom"),
		apikey.WithBearerPrefix(false),
	)
	if _, id := login(sRaw, map[string]string{"X-Custom": "Bearer k1"}); id == nil {
		t.Error("with WithBearerPrefix(false), validator should see raw \"Bearer k1\"")
	}
}

// TestMissingKey_Is401 verifies that no matching header yields 401
// missing_key (not a silent pass-through to the next strategy).
func TestMissingKey_Is401(t *testing.T) {
	s := apikey.New("apikey", staticValidator("k1"))
	rec, id := login(s, map[string]string{"Wrong-Header": "k1"})
	if id != nil {
		t.Error("no matching header should not produce an identity")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// TestWithHeaderName_DeprecatedButWorks verifies the back-compat alias
// still does what it always did: single-header, no default fallback.
func TestWithHeaderName_DeprecatedButWorks(t *testing.T) {
	s := apikey.New("apikey", staticValidator("k1"),
		apikey.WithHeaderName("X-Legacy"),
	)
	if _, id := login(s, map[string]string{"X-Legacy": "k1"}); id == nil {
		t.Error("X-Legacy should be accepted")
	}
	if _, id := login(s, map[string]string{"Authorization": "Bearer k1"}); id != nil {
		t.Error("Authorization should be rejected when WithHeaderName restricts to X-Legacy")
	}
}
