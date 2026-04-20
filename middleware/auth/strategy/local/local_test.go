package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	if d.Register != nil {
		t.Errorf("expected no register info without WithRegistrar, got %+v", d.Register)
	}
}

func TestDescriptor_WithRegistrar_IncludesRegisterBlock(t *testing.T) {
	reg := func(_ context.Context, _ RegisterRequest) (*identity.Identity, error) {
		return &identity.Identity{Subject: "new"}, nil
	}
	s := New("local", aliceVerifier, WithRegistrar(reg))
	d := s.Descriptor()

	if d.Register == nil {
		t.Fatal("expected Register info")
	}
	if len(d.Register.Fields) != 3 {
		t.Errorf("expected 3 default register fields, got %d", len(d.Register.Fields))
	}
	if d.Register.Fields[2].Name != "password_confirm" {
		t.Errorf("expected password_confirm as third field, got %q", d.Register.Fields[2].Name)
	}
}

func TestRegister_NoRegistrar_Is404(t *testing.T) {
	s := New("local", aliceVerifier)

	req := httptest.NewRequest("POST", "/auth/login/register/local",
		strings.NewReader(`{"username":"bob","password":"s3cret!"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	_, outcome, _ := s.Register(rec, req)
	if outcome != strategy.OutcomeFailed {
		t.Fatalf("expected OutcomeFailed, got %v", outcome)
	}
	if rec.Code != 404 {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestRegister_HappyPath_NoAutoLogin(t *testing.T) {
	called := 0
	reg := func(_ context.Context, req RegisterRequest) (*identity.Identity, error) {
		called++
		if req.Username != "bob" || req.Password != "s3cret!" {
			t.Fatalf("unexpected register req: %+v", req)
		}

		return &identity.Identity{Subject: "bob"}, nil
	}

	s := New("local", aliceVerifier, WithRegistrar(reg))

	req := httptest.NewRequest("POST", "/auth/login/register/local",
		strings.NewReader(`{"username":"bob","password":"s3cret!","password_confirm":"s3cret!"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	id, outcome, err := s.Register(rec, req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if outcome != strategy.OutcomePending {
		t.Fatalf("expected OutcomePending without auto-login, got %v", outcome)
	}
	if id != nil {
		t.Errorf("expected nil identity (no auto-login), got %+v", id)
	}
	if called != 1 {
		t.Errorf("registrar called %d times, expected 1", called)
	}
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["registered"] != true {
		t.Errorf("expected registered=true, got %v", body["registered"])
	}
	if body["auto_login"] != false {
		t.Errorf("expected auto_login=false, got %v", body["auto_login"])
	}
}

func TestRegister_HappyPath_AutoLogin(t *testing.T) {
	reg := func(_ context.Context, _ RegisterRequest) (*identity.Identity, error) {
		return &identity.Identity{Subject: "bob"}, nil
	}

	s := New("local", aliceVerifier, WithRegistrar(reg), WithAutoLogin(true))

	req := httptest.NewRequest("POST", "/auth/login/register/local",
		strings.NewReader(`{"username":"bob","password":"s3cret!","password_confirm":"s3cret!"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	id, outcome, err := s.Register(rec, req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if outcome != strategy.OutcomeContinue {
		t.Fatalf("expected OutcomeContinue with auto-login, got %v", outcome)
	}
	if id == nil || id.Subject != "bob" {
		t.Fatalf("expected bob identity, got %+v", id)
	}
	if id.Provider != "local" {
		t.Errorf("expected provider=local, got %q", id.Provider)
	}
}

func TestRegister_UserExists_Is409(t *testing.T) {
	reg := func(_ context.Context, _ RegisterRequest) (*identity.Identity, error) {
		return nil, ErrUserExists
	}

	s := New("local", aliceVerifier, WithRegistrar(reg))

	req := httptest.NewRequest("POST", "/auth/login/register/local",
		strings.NewReader(`{"username":"bob","password":"s3cret!","password_confirm":"s3cret!"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	_, outcome, _ := s.Register(rec, req)
	if outcome != strategy.OutcomeFailed {
		t.Fatalf("expected OutcomeFailed, got %v", outcome)
	}
	if rec.Code != 409 {
		t.Fatalf("expected 409, got %d", rec.Code)
	}

	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "user_exists" {
		t.Errorf("expected error=user_exists, got %q", body["error"])
	}
}

func TestRegister_InvalidInput_Is400(t *testing.T) {
	reg := func(_ context.Context, _ RegisterRequest) (*identity.Identity, error) {
		return nil, fmt.Errorf("password too short: %w", ErrInvalidInput)
	}

	s := New("local", aliceVerifier, WithRegistrar(reg))

	req := httptest.NewRequest("POST", "/auth/login/register/local",
		strings.NewReader(`{"username":"bob","password":"x","password_confirm":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	_, _, _ = s.Register(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "invalid_input" {
		t.Errorf("expected error=invalid_input, got %q", body["error"])
	}
}

func TestRegister_MissingFields_Is400(t *testing.T) {
	reg := func(_ context.Context, _ RegisterRequest) (*identity.Identity, error) {
		t.Fatal("registrar should not be called with missing fields")

		return nil, nil
	}

	s := New("local", aliceVerifier, WithRegistrar(reg))

	req := httptest.NewRequest("POST", "/auth/login/register/local",
		strings.NewReader(`{"username":"bob"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	_, outcome, _ := s.Register(rec, req)
	if outcome != strategy.OutcomeFailed {
		t.Fatalf("expected OutcomeFailed, got %v", outcome)
	}
	if rec.Code != 400 {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestRegister_ExtrasCollected(t *testing.T) {
	var got RegisterRequest
	reg := func(_ context.Context, req RegisterRequest) (*identity.Identity, error) {
		got = req

		return &identity.Identity{Subject: req.Username}, nil
	}

	// Declare `email` as a register field; undeclared keys are dropped.
	s := New("local", aliceVerifier,
		WithRegistrar(reg),
		WithRegisterFields(
			strategy.Field{Name: "username", Label: "Username", Type: "text", Required: true},
			strategy.Field{Name: "password", Label: "Password", Type: "password", Required: true},
			strategy.Field{Name: "password_confirm", Label: "Confirm password", Type: "password", Required: true},
			strategy.Field{Name: "email", Label: "Email", Type: "email", Required: false},
		),
	)

	req := httptest.NewRequest("POST", "/auth/login/register/local",
		strings.NewReader(`{"username":"bob","password":"s3cret!","email":"bob@example.com","password_confirm":"s3cret!"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	_, _, _ = s.Register(rec, req)
	if got.Extras["email"] != "bob@example.com" {
		t.Errorf("expected extras.email=bob@example.com, got %q", got.Extras["email"])
	}
	if _, ok := got.Extras["password_confirm"]; ok {
		t.Error("password_confirm should be stripped from Extras")
	}
}

// TestRegister_PasswordMismatch_Is400 verifies that the backend rejects a
// signup where password and password_confirm differ, yielding 400 with
// error=password_mismatch. This is defense-in-depth: the UI should also
// validate, but a UI bug or malicious client must never create an account
// whose password the user can't reproduce.
func TestRegister_PasswordMismatch_Is400(t *testing.T) {
	called := false
	reg := func(_ context.Context, _ RegisterRequest) (*identity.Identity, error) {
		called = true

		return &identity.Identity{Subject: "bob"}, nil
	}

	s := New("local", aliceVerifier, WithRegistrar(reg))

	req := httptest.NewRequest("POST", "/auth/login/register/local",
		strings.NewReader(`{"username":"bob","password":"s3cret!","password_confirm":"typo"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	_, outcome, _ := s.Register(rec, req)
	if outcome != strategy.OutcomeFailed {
		t.Fatalf("expected OutcomeFailed, got %v", outcome)
	}
	if rec.Code != 400 {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if called {
		t.Error("registrar must not be called when passwords mismatch")
	}

	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "password_mismatch" {
		t.Errorf("expected error=password_mismatch, got %q", body["error"])
	}
}

// TestRegister_MissingPasswordConfirm_Is400 verifies that omitting the
// confirm field (when the strategy declares it) is also an error, not a
// silent pass-through.
func TestRegister_MissingPasswordConfirm_Is400(t *testing.T) {
	reg := func(_ context.Context, _ RegisterRequest) (*identity.Identity, error) {
		t.Fatal("registrar must not be called")

		return nil, nil
	}

	s := New("local", aliceVerifier, WithRegistrar(reg))

	req := httptest.NewRequest("POST", "/auth/login/register/local",
		strings.NewReader(`{"username":"bob","password":"s3cret!"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	_, outcome, _ := s.Register(rec, req)
	if outcome != strategy.OutcomeFailed {
		t.Fatalf("expected OutcomeFailed, got %v", outcome)
	}
	if rec.Code != 400 {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "password_mismatch" {
		t.Errorf("expected error=password_mismatch, got %q", body["error"])
	}
}

// TestRegister_WithoutConfirmField_NoConfirmRequired verifies that machine
// clients that override register fields to omit password_confirm are not
// forced to send it. This preserves backward-compat for programmatic signup.
func TestRegister_WithoutConfirmField_NoConfirmRequired(t *testing.T) {
	var got RegisterRequest
	reg := func(_ context.Context, req RegisterRequest) (*identity.Identity, error) {
		got = req

		return &identity.Identity{Subject: req.Username}, nil
	}

	s := New("local", aliceVerifier,
		WithRegistrar(reg),
		WithRegisterFields(
			strategy.Field{Name: "username", Label: "Username", Type: "text", Required: true},
			strategy.Field{Name: "password", Label: "Password", Type: "password", Required: true},
		),
	)

	req := httptest.NewRequest("POST", "/auth/login/register/local",
		strings.NewReader(`{"username":"bob","password":"s3cret!"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	_, outcome, _ := s.Register(rec, req)
	if outcome == strategy.OutcomeFailed {
		t.Fatalf("expected success, got %d body=%s", rec.Code, rec.Body.String())
	}
	if got.Username != "bob" || got.Password != "s3cret!" {
		t.Errorf("unexpected registrar call: %+v", got)
	}
}

func TestRegister_GET_Is405(t *testing.T) {
	s := New("local", aliceVerifier, WithRegistrar(func(_ context.Context, _ RegisterRequest) (*identity.Identity, error) {
		return nil, nil
	}))

	req := httptest.NewRequest("GET", "/auth/login/register/local", nil)
	rec := httptest.NewRecorder()

	_, _, _ = s.Register(rec, req)
	if rec.Code != 405 {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
