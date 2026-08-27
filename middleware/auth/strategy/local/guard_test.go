package local_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/guard"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy/local"
)

func attempt(s *local.Strategy, username, pw string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login/pass/local",
		strings.NewReader(`{"username":"`+username+`","password":"`+pw+`"}`))
	r.Header.Set("Content-Type", "application/json")

	s.Login(rec, r) //nolint:errcheck // the recorded status is the assertion

	return rec
}

func newGuard(t *testing.T, max int) *guard.Guard {
	t.Helper()

	g := guard.New(guard.Config{MaxFailures: max, Window: time.Minute, Lockout: time.Minute})
	t.Cleanup(func() { _ = g.Close() })

	return g
}

// Nothing counted failed logins before: the Verifier was called once per
// request, forever.
func TestLimiterLocksOutAfterRepeatedFailures(t *testing.T) {
	calls := 0

	s := local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
		calls++

		return nil, local.ErrInvalidCredentials
	}, local.WithLimiter(newGuard(t, 3)))

	for i := range 3 {
		if got := attempt(s, "alice", "wrong").Code; got != http.StatusUnauthorized {
			t.Fatalf("attempt %d: code = %d", i+1, got)
		}
	}

	rec := attempt(s, "alice", "wrong")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("code = %d, want 429", rec.Code)
	}

	if rec.Header().Get("Retry-After") == "" {
		t.Error("a lockout should say when to come back")
	}

	// The verifier must not be reached once the account is locked.
	if calls != 3 {
		t.Errorf("verifier called %d times, want 3", calls)
	}
}

func TestLockoutIsPerAccount(t *testing.T) {
	s := local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
		return nil, local.ErrInvalidCredentials
	}, local.WithLimiter(newGuard(t, 2)))

	attempt(s, "alice", "wrong")
	attempt(s, "alice", "wrong")

	if attempt(s, "alice", "wrong").Code != http.StatusTooManyRequests {
		t.Fatal("alice should be locked")
	}

	if got := attempt(s, "bob", "wrong").Code; got != http.StatusUnauthorized {
		t.Fatalf("bob was affected by alice's lockout: %d", got)
	}
}

func TestLimiterResetsOnSuccess(t *testing.T) {
	s := local.New("local", func(_ context.Context, _, p string) (*identity.Identity, error) {
		if p == "right" {
			return &identity.Identity{Subject: "alice"}, nil
		}

		return nil, local.ErrInvalidCredentials
	}, local.WithLimiter(newGuard(t, 3)))

	attempt(s, "alice", "wrong")
	attempt(s, "alice", "wrong")
	attempt(s, "alice", "right")

	// The counter is cleared, so three more failures are needed to lock.
	attempt(s, "alice", "wrong")
	attempt(s, "alice", "wrong")

	if code := attempt(s, "alice", "wrong").Code; code != http.StatusUnauthorized {
		t.Fatalf("code = %d; the counter did not reset on success", code)
	}
}

// A verifier that blew up is a server fault, not a wrong password. Counting it
// would let a database outage lock out the entire user base.
func TestVerifierErrorDoesNotCountAgainstTheUser(t *testing.T) {
	s := local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
		return nil, errors.New("database is down")
	}, local.WithLimiter(newGuard(t, 2)))

	for range 5 {
		if code := attempt(s, "alice", "x").Code; code != http.StatusInternalServerError {
			t.Fatalf("code = %d, want 500", code)
		}
	}
}

func TestUsernameKeyIsCaseInsensitive(t *testing.T) {
	s := local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
		return nil, local.ErrInvalidCredentials
	}, local.WithLimiter(newGuard(t, 2)))

	attempt(s, "Alice", "wrong")
	attempt(s, "alice", "wrong")

	if code := attempt(s, "ALICE", "wrong").Code; code != http.StatusTooManyRequests {
		t.Fatalf("code = %d; case variants must share one bucket", code)
	}
}

func TestNoLimiterMeansNoLockout(t *testing.T) {
	s := local.New("local", func(context.Context, string, string) (*identity.Identity, error) {
		return nil, local.ErrInvalidCredentials
	})

	for range 20 {
		if code := attempt(s, "alice", "wrong").Code; code != http.StatusUnauthorized {
			t.Fatalf("code = %d", code)
		}
	}
}
