package ratelimit_test

import (
	"context"
	"errors"
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

type errorStore struct {
	getErr error
	setErr error
	gets   atomic.Int32
	sets   atomic.Int32
}

type waitStore struct {
	once sync.Once
	got  chan struct{}
}

type legacyStore struct {
	ratelimit.Store
}

func (s *waitStore) Get(context.Context, string) (*ratelimit.Bucket, bool, error) {
	s.once.Do(func() { close(s.got) })
	return &ratelimit.Bucket{Attempts: []time.Time{time.Now()}}, true, nil
}

func (*waitStore) Set(context.Context, string, *ratelimit.Bucket) error { return nil }

func (s *errorStore) Get(context.Context, string) (*ratelimit.Bucket, bool, error) {
	s.gets.Add(1)
	if s.getErr != nil {
		return nil, false, s.getErr
	}
	return nil, false, nil
}

func (s *errorStore) Set(context.Context, string, *ratelimit.Bucket) error {
	s.sets.Add(1)
	return s.setErr
}

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

func TestStoreGetErrorFailsClosedAndIsObservable(t *testing.T) {
	sentinel := errors.New("get failed")
	store := &errorStore{getErr: sentinel}
	cfg := defaultConfig(store)
	var observed error
	cfg.OnError = func(_ *http.Request, err error) { observed = err }

	var handlerCalls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	})
	rec := send(ratelimit.Middleware(cfg)(handler))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if handlerCalls.Load() != 0 {
		t.Fatal("downstream handler ran after Store.Get failure")
	}
	if !errors.Is(observed, sentinel) {
		t.Fatalf("OnError error = %v, want wrapping %v", observed, sentinel)
	}
	var storeErr *ratelimit.StoreError
	if !errors.As(observed, &storeErr) || storeErr.Operation != ratelimit.StoreOperationGet || storeErr.Key != "static" {
		t.Fatalf("OnError error = %#v, want get operation and static key", observed)
	}
}

func TestStoreSetErrorFailsClosedWithoutOnAttempt(t *testing.T) {
	sentinel := errors.New("set failed")
	store := &errorStore{setErr: sentinel}
	cfg := defaultConfig(store)
	var attempts atomic.Int32
	var observed error
	cfg.OnAttempt = func(*http.Request, ratelimit.Decision, int) { attempts.Add(1) }
	cfg.OnError = func(_ *http.Request, err error) { observed = err }

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Downstream", "must-not-leak")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("downstream response"))
	})
	rec := send(ratelimit.Middleware(cfg)(handler))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("X-Downstream") != "" || strings.Contains(rec.Body.String(), "downstream response") {
		t.Fatalf("failed-closed response exposed downstream response: headers=%v body=%q", rec.Header(), rec.Body.String())
	}
	if attempts.Load() != 0 {
		t.Fatalf("OnAttempt called %d times after failed persistence", attempts.Load())
	}
	if !errors.Is(observed, sentinel) {
		t.Fatalf("OnError error = %v, want wrapping %v", observed, sentinel)
	}
	var storeErr *ratelimit.StoreError
	if !errors.As(observed, &storeErr) || storeErr.Operation != ratelimit.StoreOperationSet {
		t.Fatalf("OnError error = %#v, want set operation", observed)
	}
}

func TestStoreErrorFailOpenPolicy(t *testing.T) {
	t.Run("get", func(t *testing.T) {
		store := &errorStore{getErr: errors.New("get failed")}
		cfg := defaultConfig(store)
		cfg.ErrorPolicy = ratelimit.ErrorPolicyFailOpen

		rec := send(ratelimit.Middleware(cfg)(failingHandler()))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want downstream 401", rec.Code)
		}
		if store.sets.Load() != 0 {
			t.Fatalf("Store.Set called %d times after failed-open Get", store.sets.Load())
		}
	})

	t.Run("set", func(t *testing.T) {
		store := &errorStore{setErr: errors.New("set failed")}
		cfg := defaultConfig(store)
		cfg.ErrorPolicy = ratelimit.ErrorPolicyFailOpen
		var attempts atomic.Int32
		cfg.OnAttempt = func(*http.Request, ratelimit.Decision, int) { attempts.Add(1) }

		rec := send(ratelimit.Middleware(cfg)(failingHandler()))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want downstream 401", rec.Code)
		}
		if attempts.Load() != 0 {
			t.Fatalf("OnAttempt called %d times after failed persistence", attempts.Load())
		}
	})
}

func TestBackoffWaitHonorsRequestCancellation(t *testing.T) {
	store := &waitStore{got: make(chan struct{})}
	cfg := defaultConfig(store)
	cfg.SoftThreshold = 1
	cfg.BackoffBase = time.Hour
	cfg.BackoffMax = time.Hour

	var handlerCalls atomic.Int32
	handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/login", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(rec, req)
		close(done)
	}()

	select {
	case <-store.got:
	case <-time.After(time.Second):
		t.Fatal("middleware did not read the seeded bucket")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("middleware did not stop its backoff wait after cancellation")
	}
	if handlerCalls.Load() != 0 {
		t.Fatal("downstream handler ran after cancellation")
	}
}

func TestMiddlewarePanicDoesNotPoisonKeyLock(t *testing.T) {
	store := newStore(t)
	var calls atomic.Int32

	handler := ratelimit.Middleware(ratelimit.Config{
		Window:        time.Minute,
		HardThreshold: 10,
		KeyFunc:       func(*http.Request) []string { return []string{"same-key"} },
		ShouldCount:   func(*http.Request, int) bool { return false },
		Store:         store,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			panic("boom")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	func() {
		defer func() { _ = recover() }()
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}()

	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		done <- rec.Code
	}()

	select {
	case code := <-done:
		if code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", code, http.StatusNoContent)
		}
	case <-time.After(time.Second):
		t.Fatal("second request blocked on a lock left held by the panic")
	}
}

func TestFailClosedResponseBufferOverflow(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store func(t *testing.T) (ratelimit.Store, ratelimit.Store)
	}{
		{
			name: "atomic",
			store: func(t *testing.T) (ratelimit.Store, ratelimit.Store) {
				store := newStore(t)
				return store, store
			},
		},
		{
			name: "legacy",
			store: func(t *testing.T) (ratelimit.Store, ratelimit.Store) {
				store := newStore(t)
				return legacyStore{Store: store}, store
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configuredStore, underlyingStore := tc.store(t)
			var observed []error
			var attempts []ratelimit.Decision
			var attemptStatuses []int
			handler := ratelimit.Middleware(ratelimit.Config{
				Window:              time.Minute,
				HardThreshold:       10,
				ResponseBufferLimit: 8,
				KeyFunc:             func(*http.Request) []string { return []string{"key"} },
				ShouldCount:         func(_ *http.Request, status int) bool { return status == http.StatusUnauthorized },
				Store:               configuredStore,
				OnError: func(_ *http.Request, err error) {
					observed = append(observed, err)
				},
				OnAttempt: func(_ *http.Request, decision ratelimit.Decision, status int) {
					attempts = append(attempts, decision)
					attemptStatuses = append(attemptStatuses, status)
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Downstream", "must-not-leak")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("safe"))
				_, _ = w.Write([]byte("overflow!"))
			}))

			rec := send(handler)
			if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), `"error":"response_too_large"`) {
				t.Fatalf("response = %d %q, want 500 response_too_large", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("X-Downstream") != "" || strings.Contains(rec.Body.String(), "safe") || strings.Contains(rec.Body.String(), "overflow") {
				t.Fatalf("overflow leaked downstream response: headers=%v body=%q", rec.Header(), rec.Body.String())
			}
			if len(observed) != 1 || !errors.Is(observed[0], ratelimit.ErrResponseTooLarge) {
				t.Fatalf("OnError = %v, want one ErrResponseTooLarge", observed)
			}
			var overflow *ratelimit.ResponseTooLargeError
			if !errors.As(observed[0], &overflow) || overflow.Limit != 8 || overflow.Buffered != 4 || overflow.Discarded != 9 {
				t.Fatalf("OnError = %#v, want typed overflow limit=8 buffered=4 discarded=9", observed[0])
			}
			if len(attempts) != 1 || attempts[0].Count != 1 || len(attemptStatuses) != 1 || attemptStatuses[0] != http.StatusUnauthorized {
				t.Fatalf("OnAttempt decisions=%+v statuses=%v, want one persisted 401 attempt at count 1", attempts, attemptStatuses)
			}
			bucket, ok, err := underlyingStore.Get(t.Context(), "key")
			if err != nil || !ok || len(bucket.Attempts) != 1 {
				t.Fatalf("overflowing response was not counted: bucket=%+v ok=%v err=%v", bucket, ok, err)
			}
		})
	}
}

func TestFailClosedResponseControllerFlushIsActionableAndObservedOnce(t *testing.T) {
	store := newStore(t)
	var observed []error
	var attempts atomic.Int32
	var flushErrors []error
	handler := ratelimit.Middleware(ratelimit.Config{
		Window:        time.Minute,
		HardThreshold: 10,
		KeyFunc:       func(*http.Request) []string { return []string{"key"} },
		ShouldCount:   func(_ *http.Request, status int) bool { return status == http.StatusUnauthorized },
		Store:         store,
		OnError: func(_ *http.Request, err error) {
			observed = append(observed, err)
		},
		OnAttempt: func(*http.Request, ratelimit.Decision, int) {
			attempts.Add(1)
		},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		controller := http.NewResponseController(w)
		flushErrors = append(flushErrors, controller.Flush(), controller.Flush())
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("downstream"))
	}))

	rec := send(handler)
	if rec.Code != http.StatusUnauthorized || rec.Body.String() != "downstream" {
		t.Fatalf("response = %d %q, want buffered downstream response", rec.Code, rec.Body.String())
	}
	if len(flushErrors) != 2 {
		t.Fatalf("Flush calls = %d, want 2", len(flushErrors))
	}
	for i, err := range flushErrors {
		if !errors.Is(err, ratelimit.ErrStreamingUnsupported) || !strings.Contains(err.Error(), "ErrorPolicyFailOpen") {
			t.Fatalf("Flush error %d = %v, want actionable ErrStreamingUnsupported", i+1, err)
		}
	}
	if len(observed) != 1 || !errors.Is(observed[0], ratelimit.ErrStreamingUnsupported) {
		t.Fatalf("OnError = %v, want one ErrStreamingUnsupported", observed)
	}
	if attempts.Load() != 1 {
		t.Fatalf("OnAttempt calls = %d, want 1", attempts.Load())
	}
}

func TestLegacyCaptureOnErrorCanReenterSameKey(t *testing.T) {
	for _, tc := range []struct {
		name       string
		outerWrite func(http.ResponseWriter)
		wantStatus int
	}{
		{
			name: "overflow",
			outerWrite: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("response exceeds limit"))
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "flush",
			outerWrite: func(w http.ResponseWriter) {
				_ = http.NewResponseController(w).Flush()
				w.WriteHeader(http.StatusUnauthorized)
			},
			wantStatus: http.StatusUnauthorized,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			underlying := newStore(t)
			var handler http.Handler
			var errorsObserved atomic.Int32
			var attemptsObserved atomic.Int32
			handler = ratelimit.Middleware(ratelimit.Config{
				Window:              time.Minute,
				HardThreshold:       10,
				ResponseBufferLimit: 8,
				KeyFunc:             func(*http.Request) []string { return []string{"same-key"} },
				ShouldCount:         func(*http.Request, int) bool { return true },
				Store:               legacyStore{Store: underlying},
				OnError: func(*http.Request, error) {
					errorsObserved.Add(1)
					reentrant := httptest.NewRequest(http.MethodPost, "/login", nil)
					reentrant.Header.Set("X-Reentrant", "true")
					handler.ServeHTTP(httptest.NewRecorder(), reentrant)
				},
				OnAttempt: func(*http.Request, ratelimit.Decision, int) {
					attemptsObserved.Add(1)
				},
			})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Reentrant") == "true" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				tc.outerWrite(w)
			}))

			done := make(chan int, 1)
			go func() { done <- send(handler).Code }()
			select {
			case status := <-done:
				if status != tc.wantStatus {
					t.Fatalf("status = %d, want %d", status, tc.wantStatus)
				}
			case <-time.After(time.Second):
				t.Fatal("OnError re-entry deadlocked on the legacy key lock")
			}
			if got := errorsObserved.Load(); got != 1 {
				t.Fatalf("OnError calls = %d, want 1", got)
			}
			if got := attemptsObserved.Load(); got != 2 {
				t.Fatalf("OnAttempt calls = %d, want 2", got)
			}
		})
	}
}

func TestFailClosedBufferIgnoresInformationalStatus(t *testing.T) {
	store := newStore(t)
	handler := ratelimit.Middleware(ratelimit.Config{
		Window:        time.Minute,
		HardThreshold: 10,
		KeyFunc:       func(*http.Request) []string { return []string{"key"} },
		ShouldCount:   func(_ *http.Request, status int) bool { return status == http.StatusUnauthorized },
		Store:         store,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	bucket, ok, err := store.Get(t.Context(), "key")
	if err != nil || !ok || len(bucket.Attempts) != 1 {
		t.Fatalf("final failure status was not counted: bucket=%+v ok=%v err=%v", bucket, ok, err)
	}
}
