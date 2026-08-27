package guard_test

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/guard"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

func newGuard(t *testing.T, cfg guard.Config) (*guard.Guard, *clock) {
	t.Helper()

	c := &clock{now: time.Unix(1_700_000_000, 0)}
	cfg.Now = c.Now

	g := guard.New(cfg)
	t.Cleanup(func() { _ = g.Close() })

	return g, c
}

func TestLockoutAfterMaxFailures(t *testing.T) {
	g, _ := newGuard(t, guard.Config{MaxFailures: 3, Window: time.Minute, Lockout: time.Minute})

	for i := range 2 {
		if d := g.Fail("bob"); !d.Allowed {
			t.Fatalf("locked too early at failure %d", i+1)
		}
	}

	d := g.Fail("bob")
	if d.Allowed {
		t.Fatal("third failure should lock")
	}

	if d.RetryAfter <= 0 {
		t.Errorf("RetryAfter = %v", d.RetryAfter)
	}

	if g.Check("bob").Allowed {
		t.Error("Check should report the lockout")
	}
}

func TestLockoutExpires(t *testing.T) {
	g, c := newGuard(t, guard.Config{MaxFailures: 2, Window: time.Minute, Lockout: time.Minute})

	g.Fail("bob")
	g.Fail("bob")

	if g.Check("bob").Allowed {
		t.Fatal("expected lockout")
	}

	c.advance(2 * time.Minute)

	if !g.Check("bob").Allowed {
		t.Error("lockout should expire")
	}
}

func TestSuccessClearsFailures(t *testing.T) {
	g, _ := newGuard(t, guard.Config{MaxFailures: 3, Window: time.Minute, Lockout: time.Minute})

	g.Fail("bob")
	g.Fail("bob")
	g.Succeed("bob")

	if g.Len() != 0 {
		t.Errorf("success should forget the key, len = %d", g.Len())
	}

	if d := g.Fail("bob"); d.Failures != 1 {
		t.Errorf("counter did not reset: %d", d.Failures)
	}
}

// An occasional typo, spread out over time, must never accumulate into a
// lockout — otherwise the guard turns into a denial-of-service on real users.
func TestFailuresOutsideWindowDoNotAccumulate(t *testing.T) {
	g, c := newGuard(t, guard.Config{MaxFailures: 3, Window: time.Minute, Lockout: time.Minute})

	for range 10 {
		g.Fail("bob")
		c.advance(2 * time.Minute)
	}

	if !g.Check("bob").Allowed {
		t.Error("spaced-out failures should not lock the account")
	}
}

func TestBackoffIsExponentialAndCapped(t *testing.T) {
	g, c := newGuard(t, guard.Config{
		MaxFailures: 2,
		Window:      time.Hour,
		Lockout:     time.Minute,
		MaxLockout:  4 * time.Minute,
	})

	g.Fail("bob")

	d := g.Fail("bob") // 2nd failure -> 1m
	if d.RetryAfter != time.Minute {
		t.Errorf("first lockout = %v, want 1m", d.RetryAfter)
	}

	c.advance(time.Minute + time.Second)

	d = g.Fail("bob") // 3rd -> 2m
	if d.RetryAfter != 2*time.Minute {
		t.Errorf("second lockout = %v, want 2m", d.RetryAfter)
	}

	c.advance(2*time.Minute + time.Second)

	d = g.Fail("bob") // 4th -> 4m (cap)
	if d.RetryAfter != 4*time.Minute {
		t.Errorf("third lockout = %v, want 4m", d.RetryAfter)
	}

	c.advance(5 * time.Minute)

	d = g.Fail("bob") // 5th -> still capped at 4m
	if d.RetryAfter != 4*time.Minute {
		t.Errorf("capped lockout = %v, want 4m", d.RetryAfter)
	}
}

func TestEmptyKeyIsIgnored(t *testing.T) {
	g, _ := newGuard(t, guard.Config{MaxFailures: 1})

	if d := g.Fail(""); !d.Allowed {
		t.Error("an empty key should not be tracked")
	}

	if g.Len() != 0 {
		t.Error("an empty key should not allocate")
	}
}

func TestWriteLocked(t *testing.T) {
	rec := httptest.NewRecorder()
	guard.WriteLocked(rec, guard.Decision{RetryAfter: 90 * time.Second})

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("code = %d, want 429", rec.Code)
	}

	if got := rec.Header().Get("Retry-After"); got != "90" {
		t.Errorf("Retry-After = %q", got)
	}
}

func TestClientIPIgnoresUntrustedForwardedFor(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	// No trusted proxies: the header is attacker-controlled and must be
	// ignored, or the guard hands out unlimited fresh identities.
	if got := guard.ClientIP(r, nil); got != "203.0.113.9" {
		t.Errorf("got %q, want the peer address", got)
	}
}

func TestClientIPUsesForwardedForBehindTrustedProxy(t *testing.T) {
	nets, err := guard.ParseCIDRs([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:1234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.9.9.9")

	if got := guard.ClientIP(r, nets); got != "1.2.3.4" {
		t.Errorf("got %q, want the first untrusted hop", got)
	}
}

func TestParseCIDRs(t *testing.T) {
	nets, err := guard.ParseCIDRs([]string{"10.0.0.0/8", "192.168.1.5", "", "  "})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(nets) != 2 {
		t.Fatalf("len = %d", len(nets))
	}

	if _, err := guard.ParseCIDRs([]string{"not-an-ip"}); err == nil {
		t.Error("expected error for garbage")
	}
}

func TestConcurrentFailures(t *testing.T) {
	g, _ := newGuard(t, guard.Config{MaxFailures: 1000, Window: time.Hour})

	var wg sync.WaitGroup

	for range 50 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for range 20 {
				g.Fail("shared")
			}
		}()
	}

	wg.Wait()

	if d := g.Check("shared"); d.Failures != 1000 {
		t.Errorf("failures = %d, want 1000", d.Failures)
	}
}
