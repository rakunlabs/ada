package ratelimit_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rakunlabs/tummy"

	"github.com/rakunlabs/ada/middleware/ratelimit"
)

// newStore constructs an in-memory ratelimit store for tests. Wraps the
// package's public constructor so tests exercise the same path as
// production callers.
func newStore(t *testing.T) ratelimit.Store {
	t.Helper()
	s, err := ratelimit.NewMemoryStore(1024)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	return s
}

// useTummy enables tummy with a fixed start time and pauses it so tests
// observe a stable Now() until they explicitly call tummy.AddDuration.
// Restores real time on teardown.
func useTummy(t *testing.T) {
	t.Helper()
	tummy.Enable()
	tummy.SetTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	tummy.Pause()
	t.Cleanup(func() {
		tummy.Resume()
		tummy.Disable()
	})
}

// failingHandler always returns 401, simulating a bad-password response.
func failingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
}

// successHandler always returns 200.
func successHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func defaultConfig(s ratelimit.Store) ratelimit.Config {
	return ratelimit.Config{
		Window:        time.Minute,
		SoftThreshold: 3,
		HardThreshold: 5,
		BackoffBase:   0, // disable real sleeps in tests; we assert behavior, not timing
		BackoffMax:    time.Second,
		KeyFunc:       func(_ *http.Request) []string { return []string{"static"} },
		ShouldCount:   func(_ *http.Request, status int) bool { return status == http.StatusUnauthorized },
		Store:         s,
	}
}

func send(handler http.Handler) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(""))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestPassthroughBelowThresholds(t *testing.T) {
	useTummy(t)
	s := newStore(t)
	mw := ratelimit.Middleware(defaultConfig(s))
	guarded := mw(failingHandler())

	for i := 0; i < 4; i++ {
		rec := send(guarded)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, rec.Code)
		}
	}
}

func TestHardThresholdReturns429WithRetryAfter(t *testing.T) {
	useTummy(t)
	s := newStore(t)
	mw := ratelimit.Middleware(defaultConfig(s))
	guarded := mw(failingHandler())

	// 5 failed attempts fill the bucket to HardThreshold.
	for i := 0; i < 5; i++ {
		send(guarded)
	}
	// 6th must be rejected with 429.
	rec := send(guarded)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Error("Retry-After header missing")
	}
	if !strings.Contains(rec.Body.String(), "rate_limited") {
		t.Errorf("expected rate_limited body, got %q", rec.Body.String())
	}
}

func TestHandlerNotInvokedAfterReject(t *testing.T) {
	useTummy(t)
	s := newStore(t)

	called := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusUnauthorized)
	})
	mw := ratelimit.Middleware(defaultConfig(s))
	guarded := mw(handler)

	for i := 0; i < 5; i++ {
		send(guarded)
	}
	send(guarded) // would be 6th

	if called != 5 {
		t.Errorf("handler called %d times, want 5 (last must be short-circuited)", called)
	}
}

func TestWindowRolloverDropsOldEntries(t *testing.T) {
	useTummy(t)
	s := newStore(t)
	cfg := defaultConfig(s)
	mw := ratelimit.Middleware(cfg)
	guarded := mw(failingHandler())

	// Fill to hard threshold.
	for i := 0; i < 5; i++ {
		send(guarded)
	}
	if rec := send(guarded); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("setup: expected 429, got %d", rec.Code)
	}

	// Advance past the window — every entry should fall off.
	tummy.AddDuration(2 * time.Minute)

	rec := send(guarded)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("after window rollover expected 401, got %d", rec.Code)
	}
}

func TestShouldCountFalseDoesNotCount(t *testing.T) {
	useTummy(t)
	s := newStore(t)
	cfg := defaultConfig(s)
	mw := ratelimit.Middleware(cfg)
	guarded := mw(successHandler()) // returns 200; ShouldCount only counts 401

	for i := 0; i < 100; i++ {
		rec := send(guarded)
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d", i, rec.Code)
		}
	}
}

func TestEmptyKeysSkipsLimiter(t *testing.T) {
	useTummy(t)
	s := newStore(t)
	cfg := defaultConfig(s)
	cfg.KeyFunc = func(_ *http.Request) []string { return nil }
	mw := ratelimit.Middleware(cfg)
	guarded := mw(failingHandler())

	for i := 0; i < 100; i++ {
		rec := send(guarded)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401 (limiter skipped), got %d", i, rec.Code)
		}
	}
}

func TestMultipleKeysIndependent(t *testing.T) {
	useTummy(t)
	s := newStore(t)
	cfg := defaultConfig(s)

	// Key derived from the request's User-Agent.
	cfg.KeyFunc = func(r *http.Request) []string {
		return []string{r.Header.Get("User-Agent")}
	}
	mw := ratelimit.Middleware(cfg)
	guarded := mw(failingHandler())

	makeReq := func(ua string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.Header.Set("User-Agent", ua)
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		return rec
	}

	// Fill key A to 5; key B should still be unrestricted.
	for i := 0; i < 5; i++ {
		makeReq("A")
	}
	if rec := makeReq("A"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("A 6th: expected 429, got %d", rec.Code)
	}
	if rec := makeReq("B"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("B 1st: expected 401 (independent key), got %d", rec.Code)
	}
}

func TestOnRejectAndOnAttemptHooks(t *testing.T) {
	useTummy(t)
	s := newStore(t)
	cfg := defaultConfig(s)

	var attempts []ratelimit.Decision
	var rejects []ratelimit.RejectReason
	cfg.OnAttempt = func(_ *http.Request, d ratelimit.Decision, _ int) {
		attempts = append(attempts, d)
	}
	cfg.OnReject = func(_ *http.Request, _ string, reason ratelimit.RejectReason, _ time.Duration) {
		rejects = append(rejects, reason)
	}

	mw := ratelimit.Middleware(cfg)
	guarded := mw(failingHandler())

	for i := 0; i < 5; i++ {
		send(guarded)
	}
	send(guarded) // rejected

	if len(attempts) != 5 {
		t.Errorf("OnAttempt fired %d times, want 5", len(attempts))
	}
	for i, d := range attempts {
		if d.Count != i+1 {
			t.Errorf("attempts[%d].Count = %d, want %d", i, d.Count, i+1)
		}
	}
	if len(rejects) != 1 || rejects[0] != ratelimit.ReasonHardThreshold {
		t.Errorf("OnReject = %v, want one ReasonHardThreshold", rejects)
	}
}

func TestSuccessAfterFailuresDoesNotResetButStaysBelowThreshold(t *testing.T) {
	// The limiter intentionally does NOT clear state on success — that
	// would let an attacker reset the counter by occasionally guessing a
	// real password. The window rollover is the only reset path.
	useTummy(t)
	s := newStore(t)
	cfg := defaultConfig(s)

	mw := ratelimit.Middleware(cfg)
	mixed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Outcome") == "ok" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	guarded := mw(mixed)

	mk := func(outcome string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.Header.Set("X-Outcome", outcome)
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		return rec
	}

	mk("fail") // 1
	mk("fail") // 2
	mk("ok")   // 200, NOT counted by ShouldCount
	mk("fail") // 3
	mk("fail") // 4
	mk("fail") // 5 — at hard threshold
	if rec := mk("fail"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after 5 fails (success not counted), got %d", rec.Code)
	}
}

func TestComputeBackoffShape(t *testing.T) {
	useTummy(t)
	s := newStore(t)
	var got []time.Duration
	cfg := defaultConfig(s)
	cfg.BackoffBase = 10 * time.Millisecond
	cfg.BackoffMax = 50 * time.Millisecond
	cfg.HardThreshold = 100 // disable the hard cut so we observe many attempts
	cfg.OnAttempt = func(_ *http.Request, d ratelimit.Decision, _ int) {
		got = append(got, d.Delay)
	}
	mw := ratelimit.Middleware(cfg)
	guarded := mw(failingHandler())

	// SoftThreshold=3 with BackoffBase=10ms:
	//   counts 1,2: pre-handler count is 0,1 → no delay, then count becomes 1,2
	//   count 3: pre-handler count = 2 → no delay, becomes 3
	//   count 4: pre-handler count = 3 (== soft) → 10ms
	//   count 5: pre-handler count = 4 → 20ms
	//   count 6: pre-handler count = 5 → 40ms
	//   count 7: pre-handler count = 6 → 80ms capped to 50ms
	for i := 0; i < 7; i++ {
		send(guarded)
	}
	want := []time.Duration{
		0, 0, 0,
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
		50 * time.Millisecond,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d delays, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("delay[%d] = %v, want %v", i, got[i], w)
		}
	}
}

func TestConcurrentRequestsAllCounted(t *testing.T) {
	useTummy(t)
	s := newStore(t)

	// Observe the counter directly via OnAttempt (fires exactly once per
	// counted request) rather than reaching into the store's internal
	// state. The OnAttempt decision's Count reflects the bucket size at
	// the moment of write, so the highest value we see equals the total
	// number of counted attempts.
	var maxCount int32
	cfg := defaultConfig(s)
	cfg.HardThreshold = 0 // disable hard cut so all requests run
	cfg.OnAttempt = func(_ *http.Request, d ratelimit.Decision, _ int) {
		for {
			cur := atomic.LoadInt32(&maxCount)
			if int32(d.Count) <= cur {
				return
			}
			if atomic.CompareAndSwapInt32(&maxCount, cur, int32(d.Count)) {
				return
			}
		}
	}
	mw := ratelimit.Middleware(cfg)
	guarded := mw(failingHandler())

	const N = 50
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			send(guarded)
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&maxCount); got != N {
		t.Errorf("peak Count = %d, want %d (some attempts were not counted)", got, N)
	}
}

func TestRetryAfterCountsTimeUntilOldestEntryRollsOff(t *testing.T) {
	useTummy(t)
	s := newStore(t)
	cfg := defaultConfig(s)
	mw := ratelimit.Middleware(cfg)
	guarded := mw(failingHandler())

	// Fill at t=0.
	for i := 0; i < 5; i++ {
		send(guarded)
	}

	// Advance 20s into the 60s window.
	tummy.AddDuration(20 * time.Second)

	rec := send(guarded)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	got := rec.Header().Get("Retry-After")
	// Retry-After should be ~40s (window 60s - 20s elapsed).
	if got != "40" {
		t.Errorf("Retry-After = %q, want \"40\"", got)
	}
}

func TestPanicsOnMissingRequiredConfig(t *testing.T) {
	s := newStore(t)
	cases := []struct {
		name string
		cfg  ratelimit.Config
	}{
		{"missing store", ratelimit.Config{KeyFunc: func(*http.Request) []string { return nil }, ShouldCount: func(*http.Request, int) bool { return false }}},
		{"missing keyfunc", ratelimit.Config{Store: s, ShouldCount: func(*http.Request, int) bool { return false }}},
		{"missing shouldcount", ratelimit.Config{Store: s, KeyFunc: func(*http.Request) []string { return nil }}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("expected panic")
				}
			}()
			_ = ratelimit.Middleware(tc.cfg)
		})
	}
}
