package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/issuer"
	"github.com/rakunlabs/ada/middleware/auth/issuer/backend"
	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
	"github.com/rakunlabs/ada/middleware/auth/strategy/local"
)

// secondFactor is a stand-in for a TOTP verifier: the code is always "123456".
type secondFactor struct {
	required bool
	err      error
	calls    atomic.Int32
}

func (s *secondFactor) Required(context.Context, *identity.Identity) (bool, error) {
	return s.required, s.err
}

func (s *secondFactor) Verify(_ context.Context, r *http.Request, _ *identity.Identity) error {
	s.calls.Add(1)

	var body struct {
		Code string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return err
	}

	if body.Code != "123456" {
		return http.ErrNoCookie // any error rejects
	}

	return nil
}

func newMFAAuth(t *testing.T, sf auth.SecondFactor) (*auth.Auth, *fakeMux) {
	t.Helper()

	a := auth.New(auth.Config{Base: "/auth", UI: auth.UIConfig{ExternalFolder: true}}).
		Strategy(local.New("local", func(_ context.Context, u, p string) (*identity.Identity, error) {
			if u == "alice" && p == "pw" {
				return &identity.Identity{Subject: "alice"}, nil
			}

			return nil, local.ErrInvalidCredentials
		}))

	if sf != nil {
		a = a.WithSecondFactor(sf)
	}

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	return a, mux
}

func login(t *testing.T, mux *fakeMux) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login/pass/local",
		strings.NewReader(`{"username":"alice","password":"pw"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")

	mux.mu.ServeHTTP(rec, r)

	return rec
}

func postMFA(t *testing.T, mux *fakeMux, cookie *http.Cookie, body string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login/mfa", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	if cookie != nil {
		r.AddCookie(cookie)
	}

	mux.mu.ServeHTTP(rec, r)

	return rec
}

func cookieNamed(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}

	return nil
}

func TestNoSecondFactorIssuesSessionDirectly(t *testing.T) {
	_, mux := newMFAAuth(t, nil)

	rec := login(t, mux)

	if cookieNamed(rec, "auth_session") == nil {
		t.Fatalf("expected a session cookie, got %v", rec.Result().Cookies())
	}
}

func TestSecondFactorNotRequiredIssuesSessionDirectly(t *testing.T) {
	_, mux := newMFAAuth(t, &secondFactor{required: false})

	rec := login(t, mux)

	if cookieNamed(rec, "auth_session") == nil {
		t.Fatal("expected a session cookie")
	}

	if cookieNamed(rec, "auth_mfa") != nil {
		t.Fatal("no pending cookie should be set when MFA is not required")
	}
}

func TestSecondFactorParksTheLogin(t *testing.T) {
	_, mux := newMFAAuth(t, &secondFactor{required: true})

	rec := login(t, mux)

	// The first factor must not, on its own, produce a session.
	if cookieNamed(rec, "auth_session") != nil {
		t.Fatal("a session was issued before the second factor")
	}

	pending := cookieNamed(rec, "auth_mfa")
	if pending == nil {
		t.Fatalf("expected a pending cookie, got %v", rec.Result().Cookies())
	}

	if !pending.HttpOnly {
		t.Error("pending cookie must be HttpOnly")
	}

	if pending.Path != "/auth/login/mfa" {
		t.Errorf("pending cookie path = %q; it should not travel with every request", pending.Path)
	}

	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)

	if body["mfa_required"] != true {
		t.Errorf("response = %s", rec.Body)
	}
}

func TestSecondFactorCompletesLogin(t *testing.T) {
	sf := &secondFactor{required: true}
	_, mux := newMFAAuth(t, sf)

	pending := cookieNamed(login(t, mux), "auth_mfa")

	rec := postMFA(t, mux, pending, `{"code":"123456"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d (%s)", rec.Code, rec.Body)
	}

	if cookieNamed(rec, "auth_session") == nil {
		t.Fatal("expected a session cookie after the second factor")
	}

	if sf.calls.Load() != 1 {
		t.Errorf("verifier called %d times", sf.calls.Load())
	}
}

func TestAutoLoginRegistrationRequiresSecondFactor(t *testing.T) {
	sf := &secondFactor{required: true}
	a := auth.New(auth.Config{Base: "/auth", UI: auth.UIConfig{ExternalFolder: true}}).
		WithSecondFactor(sf).
		Strategy(local.New("local",
			func(context.Context, string, string) (*identity.Identity, error) {
				return nil, local.ErrInvalidCredentials
			},
			local.WithRegistrar(func(_ context.Context, req local.RegisterRequest) (*identity.Identity, error) {
				return &identity.Identity{Subject: req.Username}, nil
			}),
			local.WithAutoLogin(true),
		))
	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login/register/local",
		strings.NewReader(`{"username":"alice","password":"pw","password_confirm":"pw"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	mux.mu.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	if cookieNamed(rec, "auth_session") != nil {
		t.Fatal("auto-login registration issued a real session before MFA")
	}
	if cookieNamed(rec, "auth_mfa") == nil {
		t.Fatal("auto-login registration did not start MFA")
	}
}

func TestSecondFactorRejectsWrongCode(t *testing.T) {
	_, mux := newMFAAuth(t, &secondFactor{required: true})

	pending := cookieNamed(login(t, mux), "auth_mfa")

	rec := postMFA(t, mux, pending, `{"code":"000000"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d", rec.Code)
	}

	if cookieNamed(rec, "auth_session") != nil {
		t.Fatal("a wrong code must not produce a session")
	}
}

func TestSecondFactorAttemptsAreCapped(t *testing.T) {
	a, mux := newMFAAuth(t, &secondFactor{required: true})
	_ = a

	pending := cookieNamed(login(t, mux), "auth_mfa")

	// Default MaxAttempts is 5.
	for i := range 5 {
		rec := postMFA(t, mux, pending, `{"code":"000000"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: code = %d", i+1, rec.Code)
		}
	}

	rec := postMFA(t, mux, pending, `{"code":"123456"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("code = %d, want 429 after exhausting attempts (%s)", rec.Code, rec.Body)
	}

	// The pending login is destroyed, so even the right code no longer works.
	again := postMFA(t, mux, pending, `{"code":"123456"}`)
	if again.Code == http.StatusOK {
		t.Fatal("a burned pending login must not be usable")
	}
}

type blockingSecondFactor struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (s *blockingSecondFactor) Required(context.Context, *identity.Identity) (bool, error) {
	return true, nil
}

func (s *blockingSecondFactor) Verify(context.Context, *http.Request, *identity.Identity) error {
	s.calls.Add(1)
	s.entered <- struct{}{}
	<-s.release

	return nil
}

func TestConcurrentMFAIsAttemptLimitedAndIssuesOneSession(t *testing.T) {
	sf := &blockingSecondFactor{
		entered: make(chan struct{}, 5),
		release: make(chan struct{}),
	}
	_, mux := newMFAAuth(t, sf)
	pending := cookieNamed(login(t, mux), "auth_mfa")

	const requests = 24
	results := make(chan *httptest.ResponseRecorder, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- postMFA(t, mux, pending, `{"code":"123456"}`)
		}()
	}

	for range 5 {
		select {
		case <-sf.entered:
		case <-time.After(2 * time.Second):
			close(sf.release)
			t.Fatal("five verifier calls did not start")
		}
	}
	close(sf.release)
	wg.Wait()
	close(results)

	sessions := 0
	for rec := range results {
		if cookieNamed(rec, "auth_session") != nil {
			sessions++
		}
	}

	if got := sf.calls.Load(); got != 5 {
		t.Fatalf("Verify calls = %d, want MaxAttempts 5", got)
	}
	if sessions != 1 {
		t.Fatalf("real sessions issued = %d, want 1", sessions)
	}
}

type issuerWithoutUpdater struct{ issuer.Issuer }

type nonAtomicBackend struct{ issuer.Backend }

type nonAtomicDirectStore struct{}

func (nonAtomicDirectStore) Get(*http.Request, string) (*sessionstore.Session, error) {
	return nil, nil
}

func (nonAtomicDirectStore) Save(*http.Request, http.ResponseWriter, *sessionstore.Session) error {
	return nil
}

func (nonAtomicDirectStore) LoadByID(context.Context, string) (map[string]any, error) {
	return nil, sessionstore.ErrNoSession
}

func (nonAtomicDirectStore) SaveByID(context.Context, string, map[string]any, time.Duration) error {
	return nil
}

func (nonAtomicDirectStore) DeleteByID(context.Context, string) error { return nil }

type failingUpdateIssuer struct{ *issuer.Default }

func (f failingUpdateIssuer) Update(context.Context, string, func(*identity.Identity) error) (*issuer.Pair, error) {
	return nil, context.DeadlineExceeded
}

type conflictingMFAUpdater struct {
	*issuer.Default
	mu        sync.Mutex
	conflicts int
	calls     int
}

func (i *conflictingMFAUpdater) Update(
	ctx context.Context,
	sessionID string,
	fn func(*identity.Identity) error,
) (*issuer.Pair, error) {
	i.mu.Lock()
	i.calls++
	conflict := i.conflicts > 0
	if conflict {
		i.conflicts--
	}
	i.mu.Unlock()

	if !conflict {
		return i.Default.Update(ctx, sessionID, fn)
	}
	pair, err := i.Resolve(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if err := fn(pair.Identity); err != nil {
		return nil, err
	}

	return nil, issuer.ErrTransactionConflict
}

func (i *conflictingMFAUpdater) callCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()

	return i.calls
}

func mfaAuthWithIssuer(t *testing.T, iss, pendingIssuer issuer.Issuer, sf auth.SecondFactor) *fakeMux {
	t.Helper()

	a := auth.New(auth.Config{Base: "/auth", UI: auth.UIConfig{ExternalFolder: true}}).
		WithIssuer(iss).
		WithPendingIssuer(pendingIssuer).
		WithSecondFactor(sf).
		Strategy(local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
			return &identity.Identity{Subject: "alice"}, nil
		}))
	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	return mux
}

func TestMFAFailsClosedWithoutAttemptPersistence(t *testing.T) {
	base := issuer.NewDefault(backend.NewMemory(), issuer.Config{})
	a := auth.New(auth.Config{}).
		WithIssuer(base).
		WithSecondFactor(&secondFactor{required: true})

	if err := a.Init(context.Background()); err == nil || !strings.Contains(err.Error(), "WithPendingIssuer") {
		t.Fatalf("Init error = %v, want explicit pending issuer requirement", err)
	}
}

func TestMFAInitRejectsPendingIssuerWithoutAtomicUpdater(t *testing.T) {
	mainIssuer := issuer.NewDefault(backend.NewMemory(), issuer.Config{})
	pending := issuerWithoutUpdater{Issuer: issuer.NewDefault(backend.NewMemory(), issuer.Config{})}
	a := auth.New(auth.Config{}).
		WithIssuer(mainIssuer).
		WithPendingIssuer(pending).
		WithSecondFactor(&secondFactor{required: true})

	if err := a.Init(context.Background()); err == nil || !strings.Contains(err.Error(), "issuer.Updater") {
		t.Fatalf("Init error = %v, want atomic updater requirement", err)
	}
}

func TestMFAInitRejectsNonAtomicCustomUpdater(t *testing.T) {
	mainIssuer := issuer.NewDefault(backend.NewMemory(), issuer.Config{})
	pending := issuer.NewDefault(nonAtomicBackend{Backend: backend.NewMemory()}, issuer.Config{})
	a := auth.New(auth.Config{}).
		WithIssuer(mainIssuer).
		WithPendingIssuer(pending).
		WithSecondFactor(&secondFactor{required: true})

	if err := a.Init(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "custom pending issuer") ||
		!strings.Contains(err.Error(), "atomic updates") {
		t.Fatalf("Init error = %v, want atomic update requirement", err)
	}
}

func TestMFAWithBackendBuildsPendingIssuer(t *testing.T) {
	a := auth.New(auth.Config{Base: "/auth", UI: auth.UIConfig{ExternalFolder: true}}).
		WithBackend(backend.NewMemory()).
		WithSecondFactor(&secondFactor{required: true}).
		Strategy(local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
			return &identity.Identity{Subject: "alice"}, nil
		}))
	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	mux := newFakeMux()
	a.Mount(mux)

	rec := login(t, mux)
	if cookieNamed(rec, "auth_mfa") == nil || cookieNamed(rec, "auth_session") != nil {
		t.Fatalf("backend-backed MFA did not park login: %v", rec.Result().Cookies())
	}
}

func TestMFAInitRejectsNonAtomicAutomaticPendingIssuers(t *testing.T) {
	tests := map[string]func(*auth.Auth) *auth.Auth{
		"WithBackend": func(a *auth.Auth) *auth.Auth {
			return a.WithBackend(nonAtomicBackend{Backend: backend.NewMemory()})
		},
		"WithSessionStore": func(a *auth.Auth) *auth.Auth {
			return a.WithSessionStore(nonAtomicDirectStore{})
		},
	}

	for name, configure := range tests {
		t.Run(name, func(t *testing.T) {
			a := configure(auth.New(auth.Config{})).
				WithSecondFactor(&secondFactor{required: true})

			err := a.Init(context.Background())
			if err == nil || !strings.Contains(err.Error(), "pending issuer") ||
				!strings.Contains(err.Error(), "atomic updates") {
				t.Fatalf("Init error = %v, want automatic pending issuer atomic update requirement", err)
			}
			if strings.Contains(err.Error(), "custom pending issuer") {
				t.Fatalf("Init error = %v, automatic issuer reported as custom", err)
			}
		})
	}
}

func TestMFAFailsClosedWhenAttemptPersistenceFails(t *testing.T) {
	sf := &secondFactor{required: true}
	iss := issuer.NewDefault(backend.NewMemory(), issuer.Config{})
	pendingIssuer := failingUpdateIssuer{Default: issuer.NewDefault(backend.NewMemory(), issuer.Config{})}
	mux := mfaAuthWithIssuer(t, iss, pendingIssuer, sf)
	pending := cookieNamed(login(t, mux), "auth_mfa")
	if pending == nil {
		t.Fatal("login did not create a pending session")
	}

	rec := postMFA(t, mux, pending, `{"code":"123456"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500 (%s)", rec.Code, rec.Body)
	}
	if cookieNamed(rec, "auth_session") != nil {
		t.Fatal("failed attempt persistence produced a real session")
	}
	if sf.calls.Load() != 0 {
		t.Fatal("Verify was called after attempt persistence failed")
	}
}

func TestMFARetriesPureUpdatesAfterConflicts(t *testing.T) {
	sf := &secondFactor{required: true}
	mainIssuer := issuer.NewDefault(backend.NewMemory(), issuer.Config{})
	pendingIssuer := &conflictingMFAUpdater{
		Default:   issuer.NewDefault(backend.NewMemory(), issuer.Config{}),
		conflicts: 2,
	}
	mux := mfaAuthWithIssuer(t, mainIssuer, pendingIssuer, sf)
	pending := cookieNamed(login(t, mux), "auth_mfa")
	if pending == nil {
		t.Fatal("login did not create a pending session")
	}

	rec := postMFA(t, mux, pending, `{"code":"123456"}`)
	if rec.Code != http.StatusOK || cookieNamed(rec, "auth_session") == nil {
		t.Fatalf("MFA did not recover from conflicts: %d %s", rec.Code, rec.Body)
	}
	if got := pendingIssuer.callCount(); got != 4 {
		t.Fatalf("Update calls = %d, want two conflicts plus reserve and completion commits", got)
	}
	if got := sf.calls.Load(); got != 1 {
		t.Fatalf("Verify calls = %d, want 1", got)
	}
}

func TestMFAConflictExhaustionLeavesBookkeepingAndCookieIntact(t *testing.T) {
	sf := &secondFactor{required: true}
	mainIssuer := issuer.NewDefault(backend.NewMemory(), issuer.Config{})
	pendingIssuer := &conflictingMFAUpdater{
		Default:   issuer.NewDefault(backend.NewMemory(), issuer.Config{}),
		conflicts: 3,
	}
	mux := mfaAuthWithIssuer(t, mainIssuer, pendingIssuer, sf)
	pending := cookieNamed(login(t, mux), "auth_mfa")
	if pending == nil {
		t.Fatal("login did not create a pending session")
	}

	rec := postMFA(t, mux, pending, `{"code":"123456"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500 (%s)", rec.Code, rec.Body)
	}
	if got := pendingIssuer.callCount(); got != 3 {
		t.Fatalf("Update calls = %d, want bounded 3 attempts", got)
	}
	if got := sf.calls.Load(); got != 0 {
		t.Fatalf("Verify calls = %d after persistence conflicts, want 0", got)
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("transient conflicts modified the pending cookie: %v", got)
	}
	pair, err := pendingIssuer.Resolve(context.Background(), pending.Value)
	if err != nil {
		t.Fatalf("resolve pending session: %v", err)
	}
	attempts, ok := pair.Identity.Claims["__auth_mfa_attempts"].(int)
	if !ok || attempts != 0 {
		t.Fatalf("conflicted callbacks changed stored attempts: %#v", pair.Identity.Claims["__auth_mfa_attempts"])
	}
}

func TestCustomPendingIssuerCannotExtendMFAWindow(t *testing.T) {
	sf := &secondFactor{required: true}
	mainIssuer := issuer.NewDefault(backend.NewMemory(), issuer.Config{RefreshTTL: time.Hour})
	pendingIssuer := issuer.NewDefault(backend.NewMemory(), issuer.Config{RefreshTTL: time.Hour})
	a := auth.New(auth.Config{
		Base: "/auth",
		UI:   auth.UIConfig{ExternalFolder: true},
		MFA:  auth.MFAConfig{TTL: 20 * time.Millisecond},
	}).
		WithIssuer(mainIssuer).
		WithPendingIssuer(pendingIssuer).
		WithSecondFactor(sf).
		Strategy(local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
			return &identity.Identity{Subject: "alice"}, nil
		}))
	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	mux := newFakeMux()
	a.Mount(mux)
	pending := cookieNamed(login(t, mux), "auth_mfa")
	if pending == nil {
		t.Fatal("login did not create a pending session")
	}

	time.Sleep(50 * time.Millisecond)
	rec := postMFA(t, mux, pending, `{"code":"123456"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired MFA code = %d, want 401 (%s)", rec.Code, rec.Body)
	}
	if sf.calls.Load() != 0 {
		t.Fatal("Verify was called after the auth-level MFA deadline")
	}
}

func TestDefaultPendingSessionIsStorageIsolated(t *testing.T) {
	sf := &secondFactor{required: true}
	a, mux := newMFAAuth(t, sf)
	pending := cookieNamed(login(t, mux), "auth_mfa")
	if pending == nil {
		t.Fatal("login did not create a pending session")
	}

	if _, err := a.Issuer().Resolve(context.Background(), pending.Value); !errors.Is(err, issuer.ErrNotFound) {
		t.Fatalf("normal issuer resolved raw pending ID: %v", err)
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login/refresh", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: pending.Value})
	mux.mu.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("pending refresh code = %d, want 401 (%s)", rec.Code, rec.Body)
	}

	completed := postMFA(t, mux, pending, `{"code":"123456"}`)
	if completed.Code != http.StatusOK || cookieNamed(completed, "auth_session") == nil {
		t.Fatalf("pending login was rotated or damaged: %d %s", completed.Code, completed.Body)
	}
}

func TestRefreshRejectsPendingIdentityBeforeRotation(t *testing.T) {
	sf := &secondFactor{required: true}
	shared := issuer.NewDefault(backend.NewMemory(), issuer.Config{})
	mux := mfaAuthWithIssuer(t, shared, shared, sf)
	pending := cookieNamed(login(t, mux), "auth_mfa")
	if pending == nil {
		t.Fatal("login did not create a pending session")
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login/refresh", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: pending.Value})
	mux.mu.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("pending refresh code = %d, want 401 (%s)", rec.Code, rec.Body)
	}

	completed := postMFA(t, mux, pending, `{"code":"123456"}`)
	if completed.Code != http.StatusOK {
		t.Fatalf("refresh rotated pending credentials: %d %s", completed.Code, completed.Body)
	}
}

func TestParkingClearsReservedMFAClaims(t *testing.T) {
	sf := &secondFactor{required: true}
	mainIssuer := issuer.NewDefault(backend.NewMemory(), issuer.Config{})
	pendingIssuer := issuer.NewDefault(backend.NewMemory(), issuer.Config{})
	a := auth.New(auth.Config{Base: "/auth", UI: auth.UIConfig{ExternalFolder: true}}).
		WithIssuer(mainIssuer).
		WithPendingIssuer(pendingIssuer).
		WithSecondFactor(sf).
		Strategy(local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
			return &identity.Identity{Subject: "alice", Claims: map[string]any{
				"__auth_mfa_pending":   "attacker",
				"__auth_mfa_expires":   "attacker",
				"__auth_mfa_attempts":  -100,
				"__auth_mfa_completed": true,
			}}, nil
		}))
	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	mux := newFakeMux()
	a.Mount(mux)
	pending := cookieNamed(login(t, mux), "auth_mfa")
	pair, err := pendingIssuer.Resolve(context.Background(), pending.Value)
	if err != nil {
		t.Fatalf("resolve pending: %v", err)
	}
	claims := pair.Identity.Claims
	if claims["__auth_mfa_pending"] != "local" || claims["__auth_mfa_attempts"] != 0 {
		t.Fatalf("reserved claims were not initialized: %+v", claims)
	}
	if _, exists := claims["__auth_mfa_completed"]; exists || claims["__auth_mfa_expires"] == "attacker" {
		t.Fatalf("attacker-controlled reserved claims survived: %+v", claims)
	}
}

func TestInvalidMFAAttemptValuesFailClosed(t *testing.T) {
	tests := map[string]any{
		"negative int":      -1,
		"negative float":    -0.5,
		"non-integral":      1.5,
		"positive infinity": math.Inf(1),
		"float overflow":    math.Exp2(63),
		"unsigned overflow": ^uint64(0),
		"unexpected type":   "1",
	}

	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			sf := &secondFactor{required: true}
			mainIssuer := issuer.NewDefault(backend.NewMemory(), issuer.Config{})
			pendingIssuer := issuer.NewDefault(backend.NewMemory(), issuer.Config{})
			mux := mfaAuthWithIssuer(t, mainIssuer, pendingIssuer, sf)
			pending := cookieNamed(login(t, mux), "auth_mfa")
			if _, err := pendingIssuer.Update(context.Background(), pending.Value, func(id *identity.Identity) error {
				id.Claims["__auth_mfa_attempts"] = value

				return nil
			}); err != nil {
				t.Fatalf("corrupt attempts: %v", err)
			}

			rec := postMFA(t, mux, pending, `{"code":"123456"}`)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("code = %d, want 401 (%s)", rec.Code, rec.Body)
			}
			if sf.calls.Load() != 0 {
				t.Fatal("Verify was called with an invalid attempt count")
			}
		})
	}
}

func TestMFAWithoutPendingCookie(t *testing.T) {
	_, mux := newMFAAuth(t, &secondFactor{required: true})

	rec := postMFA(t, mux, nil, `{"code":"123456"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d", rec.Code)
	}
}

// A pending session ID must not be usable as a real one.
func TestPendingSessionIsNotASession(t *testing.T) {
	a, mux := newMFAAuth(t, &secondFactor{required: true})

	pending := cookieNamed(login(t, mux), "auth_mfa")

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.AddCookie(&http.Cookie{Name: "auth_session", Value: pending.Value})

	a.Require()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a half-authenticated identity must not pass Require")
	})).ServeHTTP(rec, r)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code = %d, want a redirect to login", rec.Code)
	}
}

func TestMFARouteAbsentWhenNotConfigured(t *testing.T) {
	_, mux := newMFAAuth(t, nil)

	rec := postMFA(t, mux, nil, `{"code":"1"}`)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404 when no second factor is registered", rec.Code)
	}
}

// A failing Required must fail the login, not silently downgrade it.
func TestSecondFactorCheckFailsClosed(t *testing.T) {
	_, mux := newMFAAuth(t, &secondFactor{required: true, err: context.DeadlineExceeded})

	rec := login(t, mux)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500", rec.Code)
	}

	if cookieNamed(rec, "auth_session") != nil {
		t.Fatal("an unreadable enrolment store must not produce a session")
	}
}
