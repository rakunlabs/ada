package local

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

func aliceVerifier(_ context.Context, user, pass string) (*identity.Identity, error) {
	if user == "alice" && pass == "secret" {
		return &identity.Identity{Subject: "alice"}, nil
	}

	return nil, ErrInvalidCredentials
}

func TestLogin_HappyPath_JSON(t *testing.T) {
	s := New("local", aliceVerifier)

	req := httptest.NewRequest("POST", "/auth/login/local",
		strings.NewReader(`{"username":"alice","password":"secret"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	id, outcome, err := s.Login(rec, req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if outcome != strategy.OutcomeContinue {
		t.Fatalf("expected OutcomeContinue, got %v", outcome)
	}
	if id == nil || id.Subject != "alice" {
		t.Fatalf("expected alice identity, got %+v", id)
	}
	if id.Provider != "local" {
		t.Fatalf("expected provider=local, got %q", id.Provider)
	}
}

func TestLogin_BadCredentials(t *testing.T) {
	s := New("local", aliceVerifier)

	req := httptest.NewRequest("POST", "/auth/login/local",
		strings.NewReader(`{"username":"alice","password":"wrong"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	_, outcome, _ := s.Login(rec, req)
	if outcome != strategy.OutcomeFailed {
		t.Fatalf("expected OutcomeFailed, got %v", outcome)
	}

	if rec.Code != 401 {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "invalid_credentials" {
		t.Fatalf("expected invalid_credentials, got %q", body["error"])
	}
}

func TestLogin_FormEncoded(t *testing.T) {
	s := New("local", aliceVerifier)

	req := httptest.NewRequest("POST", "/auth/login/local",
		strings.NewReader("username=alice&password=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	id, outcome, _ := s.Login(rec, req)
	if outcome != strategy.OutcomeContinue {
		t.Fatalf("expected OutcomeContinue, got %v", outcome)
	}
	if id.Subject != "alice" {
		t.Fatalf("expected alice, got %+v", id)
	}
}

func TestLogin_VerifierError_Is500(t *testing.T) {
	s := New("local", func(_ context.Context, _, _ string) (*identity.Identity, error) {
		return nil, errors.New("db down")
	})

	req := httptest.NewRequest("POST", "/auth/login/local",
		strings.NewReader(`{"username":"x","password":"y"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	_, _, _ = s.Login(rec, req)
	if rec.Code != 500 {
		t.Fatalf("expected 500 for verifier error, got %d", rec.Code)
	}
}

func TestLogin_GET_Is405(t *testing.T) {
	s := New("local", aliceVerifier)

	req := httptest.NewRequest("GET", "/auth/login/local", nil)
	rec := httptest.NewRecorder()

	_, outcome, _ := s.Login(rec, req)
	if outcome != strategy.OutcomeFailed {
		t.Fatalf("expected OutcomeFailed, got %v", outcome)
	}
	if rec.Code != 405 {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestDescriptor(t *testing.T) {
	s := New("local", aliceVerifier, WithLabel("Sign in"), WithPriority(5))
	d := s.Descriptor()

	if d.Kind != "password" {
		t.Errorf("expected kind=password, got %q", d.Kind)
	}
	if d.Label != "Sign in" {
		t.Errorf("expected label=Sign in, got %q", d.Label)
	}
	if d.Priority != 5 {
		t.Errorf("expected priority=5, got %d", d.Priority)
	}
	if len(d.Fields) != 2 {
		t.Errorf("expected 2 default fields, got %d", len(d.Fields))
	}
}
