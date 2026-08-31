package ratelimit_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/ratelimit"
	"github.com/rakunlabs/tummy"
)

type failingAtomicStore struct {
	ratelimit.AtomicStore
	failAt   int32
	calls    atomic.Int32
	sentinel error
}

type stallingAtomicStore struct {
	ratelimit.AtomicStore
	stallAt       int32
	calls         atomic.Int32
	sawUncanceled atomic.Bool
	sawDeadline   atomic.Bool
	stalled       chan struct{}
	stallOnce     sync.Once
}

type hookedAtomicStore struct {
	ratelimit.AtomicStore
	calls atomic.Int32
	hook  func(context.Context, int32, []string, func(map[string]*ratelimit.Bucket) error) (bool, error)
}

func (s *hookedAtomicStore) Transaction(ctx context.Context, keys []string, fn func(map[string]*ratelimit.Bucket) error) error {
	call := s.calls.Add(1)
	if s.hook != nil {
		if handled, err := s.hook(ctx, call, keys, fn); handled {
			return err
		}
	}
	return s.AtomicStore.Transaction(ctx, keys, fn)
}

func (s *stallingAtomicStore) Transaction(ctx context.Context, keys []string, fn func(map[string]*ratelimit.Bucket) error) error {
	if s.calls.Add(1) != s.stallAt {
		return s.AtomicStore.Transaction(ctx, keys, fn)
	}
	if ctx.Err() == nil {
		s.sawUncanceled.Store(true)
	}
	if _, ok := ctx.Deadline(); ok {
		s.sawDeadline.Store(true)
	}
	if s.stalled != nil {
		s.stallOnce.Do(func() { close(s.stalled) })
	}
	<-ctx.Done()
	return ctx.Err()
}

func (s *failingAtomicStore) Transaction(ctx context.Context, keys []string, fn func(map[string]*ratelimit.Bucket) error) error {
	if s.calls.Add(1) == s.failAt {
		return s.sentinel
	}
	return s.AtomicStore.Transaction(ctx, keys, fn)
}

func newAtomicStore(t *testing.T, capacity int) (ratelimit.Store, ratelimit.AtomicStore) {
	t.Helper()
	store, err := ratelimit.NewMemoryStore(capacity)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	atomicStore, ok := store.(ratelimit.AtomicStore)
	if !ok {
		t.Fatal("NewMemoryStore does not implement AtomicStore")
	}
	return store, atomicStore
}

func TestAtomicStoreLimitsConcurrentMiddlewareInstances(t *testing.T) {
	useTummy(t)
	store, _ := newAtomicStore(t, 64)
	cfg := defaultConfig(store)
	cfg.SoftThreshold = 0
	cfg.HardThreshold = 5
	cfg.RequireAtomicStore = true

	entered := make(chan struct{}, 16)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseAll)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusUnauthorized)
	})
	handlers := []http.Handler{
		ratelimit.Middleware(cfg)(next),
		ratelimit.Middleware(cfg)(next),
	}

	const requests = 16
	start := make(chan struct{})
	codes := make(chan int, requests)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(handler http.Handler) {
			defer wg.Done()
			<-start
			codes <- send(handler).Code
		}(handlers[i%len(handlers)])
	}
	close(start)

	for i := 0; i < cfg.HardThreshold; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatalf("only %d handlers entered, want %d reservations", i, cfg.HardThreshold)
		}
	}
	reservedBucket, ok, err := store.Get(t.Context(), "static")
	if err != nil || !ok || len(reservedBucket.Attempts)+len(reservedBucket.Reservations) != cfg.HardThreshold {
		t.Fatalf("live records while handlers run: bucket=%+v ok=%v err=%v, want %d", reservedBucket, ok, err, cfg.HardThreshold)
	}
	rejected := 0
	for rejected < requests-cfg.HardThreshold {
		select {
		case <-entered:
			t.Fatal("more than HardThreshold handlers passed while reservations were in flight")
		case code := <-codes:
			if code != http.StatusTooManyRequests {
				t.Fatalf("unblocked status = %d, want 429", code)
			}
			rejected++
		case <-time.After(time.Second):
			t.Fatalf("only %d requests were rejected while handlers were blocked", rejected)
		}
	}

	releaseAll()
	wg.Wait()
	close(codes)

	passed := 0
	for code := range codes {
		switch code {
		case http.StatusUnauthorized:
			passed++
		default:
			t.Fatalf("unexpected status %d", code)
		}
	}
	if passed != cfg.HardThreshold || rejected != requests-cfg.HardThreshold {
		t.Fatalf("passed=%d rejected=%d, want %d and %d", passed, rejected, cfg.HardThreshold, requests-cfg.HardThreshold)
	}
	finalBucket, ok, err := store.Get(t.Context(), "static")
	if err != nil || !ok || len(finalBucket.Attempts) != cfg.HardThreshold || len(finalBucket.Reservations) != 0 {
		t.Fatalf("final hard-threshold state: bucket=%+v ok=%v err=%v", finalBucket, ok, err)
	}
}

func TestAtomicReservationRollsBackNonCountedResponse(t *testing.T) {
	store, _ := newAtomicStore(t, 8)
	cfg := defaultConfig(store)
	cfg.SoftThreshold = 0
	cfg.HardThreshold = 1
	cfg.RequireAtomicStore = true

	handler := ratelimit.Middleware(cfg)(successHandler())
	for i := 0; i < 2; i++ {
		if rec := send(handler); rec.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i+1, rec.Code)
		}
	}
	if bucket, ok, err := store.Get(t.Context(), "static"); err != nil || ok || bucket != nil {
		t.Fatalf("rolled-back reservation remained: bucket=%+v ok=%v err=%v", bucket, ok, err)
	}
}

func TestAtomicReservationRollsBackHandlerPanic(t *testing.T) {
	store, _ := newAtomicStore(t, 8)
	cfg := defaultConfig(store)
	cfg.SoftThreshold = 0
	cfg.HardThreshold = 1
	cfg.RequireAtomicStore = true

	var calls atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			panic("boom")
		}
		w.WriteHeader(http.StatusOK)
	})
	first := ratelimit.Middleware(cfg)(next)
	second := ratelimit.Middleware(cfg)(next)
	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Fatal("handler did not panic")
			}
		}()
		send(first)
	}()

	if rec := send(second); rec.Code != http.StatusOK {
		t.Fatalf("request after panic status = %d, want 200", rec.Code)
	}
	if bucket, ok, err := store.Get(t.Context(), "static"); err != nil || ok || bucket != nil {
		t.Fatalf("panic left a reservation: bucket=%+v ok=%v err=%v", bucket, ok, err)
	}
}

func TestAtomicInitialStoreOperationTimeout(t *testing.T) {
	for _, tc := range []struct {
		name       string
		policy     ratelimit.ErrorPolicy
		wantStatus int
	}{
		{name: "fail closed", policy: ratelimit.ErrorPolicyFailClosed, wantStatus: http.StatusServiceUnavailable},
		{name: "fail open", policy: ratelimit.ErrorPolicyFailOpen, wantStatus: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, atomicStore := newAtomicStore(t, 8)
			stalling := &stallingAtomicStore{AtomicStore: atomicStore, stallAt: 1}
			cfg := defaultConfig(stalling)
			cfg.ErrorPolicy = tc.policy
			cfg.StoreOperationTimeout = 20 * time.Millisecond
			var observed error
			cfg.OnError = func(_ *http.Request, err error) { observed = err }
			var handlerCalls atomic.Int32
			handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				handlerCalls.Add(1)
				w.WriteHeader(http.StatusUnauthorized)
			}))

			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- send(handler) }()
			select {
			case rec := <-done:
				if rec.Code != tc.wantStatus {
					t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
				}
			case <-time.After(time.Second):
				t.Fatal("initial reservation exceeded StoreOperationTimeout")
			}
			if !errors.Is(observed, context.DeadlineExceeded) {
				t.Fatalf("OnError = %v, want context deadline exceeded", observed)
			}
			if !stalling.sawUncanceled.Load() || !stalling.sawDeadline.Load() {
				t.Fatalf("initial context: uncanceled=%v deadline=%v", stalling.sawUncanceled.Load(), stalling.sawDeadline.Load())
			}
			wantCalls := int32(0)
			if tc.policy == ratelimit.ErrorPolicyFailOpen {
				wantCalls = 1
			}
			if got := handlerCalls.Load(); got != wantCalls {
				t.Fatalf("handler calls = %d, want %d", got, wantCalls)
			}
		})
	}
}

func TestAtomicInitialStoreOperationHonorsRequestCancellation(t *testing.T) {
	_, atomicStore := newAtomicStore(t, 8)
	stalling := &stallingAtomicStore{
		AtomicStore: atomicStore,
		stallAt:     1,
		stalled:     make(chan struct{}),
	}
	cfg := defaultConfig(stalling)
	cfg.ErrorPolicy = ratelimit.ErrorPolicyFailOpen
	cfg.StoreOperationTimeout = time.Hour
	var observed error
	cfg.OnError = func(_ *http.Request, err error) { observed = err }
	var handlerCalls atomic.Int32
	handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/login", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()
	select {
	case <-stalling.stalled:
	case <-time.After(time.Second):
		t.Fatal("initial reservation did not reach the store")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("initial reservation ignored request cancellation")
	}
	if !errors.Is(observed, context.Canceled) {
		t.Fatalf("OnError = %v, want context canceled", observed)
	}
	if got := handlerCalls.Load(); got != 0 {
		t.Fatalf("handler ran %d times after request cancellation", got)
	}
}

func TestAtomicStoreOperationTimeoutAfterCanceledRequest(t *testing.T) {
	for _, tc := range []struct {
		name       string
		policy     ratelimit.ErrorPolicy
		wantStatus int
	}{
		{name: "fail closed", policy: ratelimit.ErrorPolicyFailClosed, wantStatus: http.StatusServiceUnavailable},
		{name: "fail open", policy: ratelimit.ErrorPolicyFailOpen, wantStatus: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, atomicStore := newAtomicStore(t, 8)
			stalling := &stallingAtomicStore{AtomicStore: atomicStore, stallAt: 2}
			cfg := defaultConfig(stalling)
			cfg.ErrorPolicy = tc.policy
			cfg.RequireAtomicStore = true
			cfg.StoreOperationTimeout = 20 * time.Millisecond
			var observed error
			cfg.OnError = func(_ *http.Request, err error) { observed = err }

			ctx, cancel := context.WithCancel(context.Background())
			handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				cancel()
				w.WriteHeader(http.StatusUnauthorized)
			}))
			req := httptest.NewRequest(http.MethodPost, "/login", nil).WithContext(ctx)
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				handler.ServeHTTP(rec, req)
				close(done)
			}()

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for bounded finalization")
			}
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if !errors.Is(observed, context.DeadlineExceeded) {
				t.Fatalf("OnError = %v, want context deadline exceeded", observed)
			}
			if !stalling.sawUncanceled.Load() || !stalling.sawDeadline.Load() {
				t.Fatalf("post-handler context: uncanceled=%v deadline=%v", stalling.sawUncanceled.Load(), stalling.sawDeadline.Load())
			}
			if bucket, ok, err := store.Get(t.Context(), "static"); err != nil || ok || bucket != nil {
				t.Fatalf("deferred rollback did not clear reservation: bucket=%+v ok=%v err=%v", bucket, ok, err)
			}
		})
	}
}

func TestAtomicPanicCleanupUsesBoundedContext(t *testing.T) {
	_, atomicStore := newAtomicStore(t, 8)
	stalling := &stallingAtomicStore{AtomicStore: atomicStore, stallAt: 2}
	cfg := defaultConfig(stalling)
	cfg.RequireAtomicStore = true
	cfg.StoreOperationTimeout = 20 * time.Millisecond
	var observed error
	cfg.OnError = func(_ *http.Request, err error) { observed = err }

	ctx, cancel := context.WithCancel(context.Background())
	handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		cancel()
		panic("boom")
	}))
	recovered := make(chan any, 1)
	go func() {
		defer func() { recovered <- recover() }()
		req := httptest.NewRequest(http.MethodPost, "/login", nil).WithContext(ctx)
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}()

	select {
	case got := <-recovered:
		if got != "boom" {
			t.Fatalf("recovered = %v, want boom", got)
		}
	case <-time.After(time.Second):
		t.Fatal("panic cleanup exceeded its store operation timeout")
	}
	if !errors.Is(observed, context.DeadlineExceeded) {
		t.Fatalf("OnError = %v, want context deadline exceeded", observed)
	}
	if !stalling.sawUncanceled.Load() || !stalling.sawDeadline.Load() {
		t.Fatalf("panic cleanup context: uncanceled=%v deadline=%v", stalling.sawUncanceled.Load(), stalling.sawDeadline.Load())
	}
}

func TestAtomicReservationSurvivesWindowAndFinalizesAtAdmission(t *testing.T) {
	useTummy(t)
	store, _ := newAtomicStore(t, 8)
	cfg := defaultConfig(store)
	cfg.SoftThreshold = 0
	cfg.HardThreshold = 1

	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	handler := ratelimit.Middleware(cfg)(next)
	firstDone := make(chan int, 1)
	go func() { firstDone <- send(handler).Code }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first handler did not start")
	}

	tummy.AddDuration(cfg.Window + time.Second)
	blocked := send(handler)
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("status while original handler is active = %d, want 429", blocked.Code)
	}
	if got := blocked.Header().Get("Retry-After"); got != "59" {
		t.Fatalf("Retry-After = %q, want remaining reservation lease 59", got)
	}

	close(release)
	select {
	case code := <-firstDone:
		if code != http.StatusUnauthorized {
			t.Fatalf("first status = %d, want 401", code)
		}
	case <-time.After(time.Second):
		t.Fatal("first handler did not finish")
	}
	if bucket, ok, err := store.Get(t.Context(), "static"); err != nil || ok || bucket != nil {
		t.Fatalf("completed old attempt remained in the current window: bucket=%+v ok=%v err=%v", bucket, ok, err)
	}
	if rec := send(handler); rec.Code != http.StatusUnauthorized {
		t.Fatalf("request after old attempt finalized = %d, want 401", rec.Code)
	}
}

func TestAtomicReservationLeaseRenewsForLongHandler(t *testing.T) {
	useTummy(t)
	store, _ := newAtomicStore(t, 8)
	cfg := defaultConfig(store)
	cfg.Window = 20 * time.Millisecond
	cfg.SoftThreshold = 0
	cfg.HardThreshold = 1
	cfg.StoreOperationTimeout = time.Millisecond

	entered := make(chan struct{})
	release := make(chan struct{})
	handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusUnauthorized)
	}))
	done := make(chan int, 1)
	go func() { done <- send(handler).Code }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}

	initialLease := onlyReservationLease(t, store)
	tummy.AddDuration(30 * time.Millisecond)
	waitForLeaseAfter(t, store, initialLease)
	tummy.AddDuration(30 * time.Millisecond)

	blocked := send(handler)
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("status after multiple windows = %d, want 429", blocked.Code)
	}
	close(release)
	select {
	case code := <-done:
		if code != http.StatusUnauthorized {
			t.Fatalf("handler status = %d, want 401", code)
		}
	case <-time.After(time.Second):
		t.Fatal("handler did not finish")
	}
}

func TestAtomicReservationLeaseRetriesTransientRenewalFailure(t *testing.T) {
	store, atomicStore := newAtomicStore(t, 8)
	sentinel := errors.New("transient renewal failure")
	failed := make(chan struct{})
	renewed := make(chan struct{})
	hooked := &hookedAtomicStore{AtomicStore: atomicStore}
	hooked.hook = func(ctx context.Context, call int32, keys []string, fn func(map[string]*ratelimit.Bucket) error) (bool, error) {
		switch call {
		case 2:
			close(failed)
			return true, sentinel
		case 3:
			err := atomicStore.Transaction(ctx, keys, fn)
			close(renewed)
			return true, err
		default:
			return false, nil
		}
	}

	cfg := defaultConfig(hooked)
	cfg.Window = 20 * time.Millisecond
	cfg.StoreOperationTimeout = time.Millisecond
	observed := make(chan error, 1)
	cfg.OnError = func(_ *http.Request, err error) { observed <- err }
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusUnauthorized)
	}))
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- send(handler) }()

	waitForSignal(t, entered, "handler entry")
	initialLease := onlyReservationLease(t, store)
	waitForSignal(t, failed, "transient renewal failure")
	waitForSignal(t, renewed, "renewal retry")
	if got := onlyReservationLease(t, store); !got.After(initialLease) {
		t.Fatalf("retried lease = %v, want after %v", got, initialLease)
	}
	select {
	case err := <-observed:
		if !errors.Is(err, sentinel) {
			t.Fatalf("OnError = %v, want wrapping %v", err, sentinel)
		}
	default:
		t.Fatal("transient renewal failure was not observed")
	}
	close(release)
	select {
	case rec := <-done:
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("request did not finish after successful renewal retry")
	}
}

func TestAtomicTerminalRenewalFailureHonorsErrorPolicyAndCleansUp(t *testing.T) {
	for _, tc := range []struct {
		name       string
		policy     ratelimit.ErrorPolicy
		wantStatus int
	}{
		{name: "fail closed", policy: ratelimit.ErrorPolicyFailClosed, wantStatus: http.StatusServiceUnavailable},
		{name: "fail open", policy: ratelimit.ErrorPolicyFailOpen, wantStatus: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, atomicStore := newAtomicStore(t, 8)
			hooked := &hookedAtomicStore{AtomicStore: atomicStore}
			hooked.hook = func(_ context.Context, call int32, keys []string, fn func(map[string]*ratelimit.Bucket) error) (bool, error) {
				if call != 2 {
					return false, nil
				}
				buckets := make(map[string]*ratelimit.Bucket, len(keys))
				for _, key := range keys {
					buckets[key] = nil
				}
				return true, fn(buckets)
			}

			cfg := defaultConfig(hooked)
			cfg.Window = 20 * time.Millisecond
			cfg.StoreOperationTimeout = time.Millisecond
			cfg.ErrorPolicy = tc.policy
			observed := make(chan error, 1)
			cfg.OnError = func(_ *http.Request, err error) { observed <- err }
			entered := make(chan struct{})
			release := make(chan struct{})
			handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				close(entered)
				<-release
				w.Header().Set("X-Downstream", "preserve-only-when-open")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("downstream response"))
			}))
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- send(handler) }()

			waitForSignal(t, entered, "handler entry")
			var renewalErr error
			select {
			case renewalErr = <-observed:
			case <-time.After(time.Second):
				t.Fatal("permanent renewal failure was not observed")
			}
			var storeErr *ratelimit.StoreError
			if !errors.As(renewalErr, &storeErr) || !strings.Contains(renewalErr.Error(), "reservation lease expired") {
				t.Fatalf("OnError = %#v, want expired transaction StoreError", renewalErr)
			}
			close(release)
			select {
			case rec := <-done:
				if rec.Code != tc.wantStatus {
					t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
				}
				if tc.policy == ratelimit.ErrorPolicyFailClosed {
					if rec.Header().Get("X-Downstream") != "" || strings.Contains(rec.Body.String(), "downstream response") {
						t.Fatalf("fail-closed response leaked downstream data: headers=%v body=%q", rec.Header(), rec.Body.String())
					}
				} else if rec.Header().Get("X-Downstream") == "" || !strings.Contains(rec.Body.String(), "downstream response") {
					t.Fatalf("fail-open response was not preserved: headers=%v body=%q", rec.Header(), rec.Body.String())
				}
			case <-time.After(time.Second):
				t.Fatal("request did not finish after terminal renewal failure")
			}
			if bucket, ok, err := store.Get(t.Context(), "static"); err != nil || ok || bucket != nil {
				t.Fatalf("terminal renewal left reservation: bucket=%+v ok=%v err=%v", bucket, ok, err)
			}
		})
	}
}

func TestAtomicTerminalRenewalInterruptsLongBackoff(t *testing.T) {
	useTummy(t)
	for _, tc := range []struct {
		name             string
		policy           ratelimit.ErrorPolicy
		wantStatus       int
		wantHandlerCalls int32
	}{
		{name: "fail closed", policy: ratelimit.ErrorPolicyFailClosed, wantStatus: http.StatusServiceUnavailable},
		{name: "fail open", policy: ratelimit.ErrorPolicyFailOpen, wantStatus: http.StatusUnauthorized, wantHandlerCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, atomicStore := newAtomicStore(t, 8)
			if err := store.Set(t.Context(), "static", &ratelimit.Bucket{Attempts: []time.Time{tummy.Now()}}); err != nil {
				t.Fatalf("seed attempt: %v", err)
			}
			hooked := &hookedAtomicStore{AtomicStore: atomicStore}
			hooked.hook = func(_ context.Context, call int32, keys []string, fn func(map[string]*ratelimit.Bucket) error) (bool, error) {
				if call != 2 {
					return false, nil
				}
				buckets := make(map[string]*ratelimit.Bucket, len(keys))
				for _, key := range keys {
					buckets[key] = nil
				}
				return true, fn(buckets)
			}

			cfg := defaultConfig(hooked)
			cfg.Window = 20 * time.Millisecond
			cfg.SoftThreshold = 1
			cfg.BackoffBase = time.Hour
			cfg.BackoffMax = time.Hour
			cfg.StoreOperationTimeout = time.Millisecond
			cfg.ErrorPolicy = tc.policy
			observed := make(chan error, 1)
			cfg.OnError = func(_ *http.Request, err error) { observed <- err }
			var handlerCalls atomic.Int32
			handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				handlerCalls.Add(1)
				if bucket, ok, err := store.Get(t.Context(), "static"); err != nil || ok && len(bucket.Reservations) != 0 {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
			}))

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			req := httptest.NewRequest(http.MethodPost, "/login", nil).WithContext(ctx)
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				done <- rec
			}()

			select {
			case err := <-observed:
				if !strings.Contains(err.Error(), "reservation lease expired") {
					t.Fatalf("OnError = %v, want expired reservation", err)
				}
			case <-time.After(time.Second):
				t.Fatal("lease did not fail during long backoff")
			}
			select {
			case rec := <-done:
				if rec.Code != tc.wantStatus {
					t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
				}
			case <-time.After(time.Second):
				t.Fatal("terminal lease failure did not interrupt long backoff")
			}
			if got := handlerCalls.Load(); got != tc.wantHandlerCalls {
				t.Fatalf("handler calls = %d, want %d", got, tc.wantHandlerCalls)
			}
			bucket, ok, err := store.Get(t.Context(), "static")
			if err != nil || ok && len(bucket.Reservations) != 0 {
				t.Fatalf("long-backoff failure left reservation: bucket=%+v ok=%v err=%v", bucket, ok, err)
			}
		})
	}
}

func TestAtomicRenewalTransactionPanicFailsClosedAndCleansUp(t *testing.T) {
	store, atomicStore := newAtomicStore(t, 8)
	hooked := &hookedAtomicStore{AtomicStore: atomicStore}
	hooked.hook = func(_ context.Context, call int32, _ []string, _ func(map[string]*ratelimit.Bucket) error) (bool, error) {
		if call == 2 {
			panic("renewal transaction panic")
		}
		return false, nil
	}

	cfg := defaultConfig(hooked)
	cfg.Window = 20 * time.Millisecond
	cfg.StoreOperationTimeout = time.Millisecond
	observed := make(chan error, 1)
	cfg.OnError = func(_ *http.Request, err error) { observed <- err }
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.Header().Set("X-Downstream", "must-not-leak")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- send(handler) }()

	waitForSignal(t, entered, "handler entry")
	select {
	case err := <-observed:
		var storeErr *ratelimit.StoreError
		if !errors.As(err, &storeErr) || !strings.Contains(err.Error(), "renewal transaction panic") {
			t.Fatalf("OnError = %#v, want recovered transaction panic", err)
		}
	case <-time.After(time.Second):
		t.Fatal("renewal transaction panic was not observed")
	}
	close(release)
	select {
	case rec := <-done:
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("X-Downstream") != "" {
			t.Fatalf("response after renewal panic: status=%d headers=%v", rec.Code, rec.Header())
		}
	case <-time.After(time.Second):
		t.Fatal("request hung after renewal transaction panic")
	}
	if bucket, ok, err := store.Get(t.Context(), "static"); err != nil || ok || bucket != nil {
		t.Fatalf("renewal panic left reservation: bucket=%+v ok=%v err=%v", bucket, ok, err)
	}
}

func TestAtomicRenewalOnErrorPanicDoesNotEscapeWorker(t *testing.T) {
	store, atomicStore := newAtomicStore(t, 8)
	sentinel := errors.New("renewal failed")
	hooked := &hookedAtomicStore{AtomicStore: atomicStore}
	hooked.hook = func(_ context.Context, call int32, _ []string, _ func(map[string]*ratelimit.Bucket) error) (bool, error) {
		if call == 2 {
			return true, sentinel
		}
		return false, nil
	}

	cfg := defaultConfig(hooked)
	cfg.Window = 20 * time.Millisecond
	cfg.StoreOperationTimeout = time.Millisecond
	observed := make(chan struct{})
	cfg.OnError = func(_ *http.Request, err error) {
		if errors.Is(err, sentinel) {
			close(observed)
		}
		panic("OnError panic")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusUnauthorized)
	}))
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- send(handler) }()

	waitForSignal(t, entered, "handler entry")
	waitForSignal(t, observed, "OnError callback")
	close(release)
	select {
	case rec := <-done:
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("request hung after OnError panic")
	}
	if bucket, ok, err := store.Get(t.Context(), "static"); err != nil || ok || bucket != nil {
		t.Fatalf("OnError panic left reservation: bucket=%+v ok=%v err=%v", bucket, ok, err)
	}
}

func TestAtomicRenewalFailureReachesConfirmedLeaseDeadline(t *testing.T) {
	store, atomicStore := newAtomicStore(t, 8)
	sentinel := errors.New("persistent renewal failure")
	var failRenewals atomic.Bool
	failRenewals.Store(true)
	hooked := &hookedAtomicStore{AtomicStore: atomicStore}
	hooked.hook = func(_ context.Context, call int32, _ []string, _ func(map[string]*ratelimit.Bucket) error) (bool, error) {
		if call >= 2 && failRenewals.Load() {
			return true, sentinel
		}
		return false, nil
	}

	cfg := defaultConfig(hooked)
	cfg.Window = 12 * time.Millisecond
	cfg.StoreOperationTimeout = 2 * time.Millisecond
	terminal := make(chan error, 1)
	cfg.OnError = func(_ *http.Request, err error) {
		if strings.Contains(err.Error(), "renewal could not be confirmed") {
			terminal <- err
		}
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusUnauthorized)
	}))
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- send(handler) }()

	waitForSignal(t, entered, "handler entry")
	select {
	case err := <-terminal:
		if !errors.Is(err, sentinel) {
			t.Fatalf("terminal renewal error = %v, want wrapping %v", err, sentinel)
		}
	case <-time.After(time.Second):
		t.Fatal("renewal retries did not terminate at the confirmed lease deadline")
	}
	failRenewals.Store(false)
	close(release)
	select {
	case rec := <-done:
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("request hung after lease deadline failure")
	}
	if hooked.calls.Load() < 3 {
		t.Fatalf("transaction calls = %d, want at least one bounded renewal retry", hooked.calls.Load())
	}
	if bucket, ok, err := store.Get(t.Context(), "static"); err != nil || ok || bucket != nil {
		t.Fatalf("deadline failure left reservation: bucket=%+v ok=%v err=%v", bucket, ok, err)
	}
}

func TestAtomicLeaseStopCancelsBlockedRenewal(t *testing.T) {
	_, atomicStore := newAtomicStore(t, 8)
	stalled := make(chan struct{})
	canceled := make(chan error, 1)
	hooked := &hookedAtomicStore{AtomicStore: atomicStore}
	hooked.hook = func(ctx context.Context, call int32, _ []string, _ func(map[string]*ratelimit.Bucket) error) (bool, error) {
		if call != 2 {
			return false, nil
		}
		close(stalled)
		<-ctx.Done()
		canceled <- ctx.Err()
		return true, ctx.Err()
	}

	cfg := defaultConfig(hooked)
	cfg.Window = time.Millisecond
	cfg.StoreOperationTimeout = 100 * time.Millisecond
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusUnauthorized)
	}))
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- send(handler) }()

	waitForSignal(t, entered, "handler entry")
	waitForSignal(t, stalled, "blocked renewal")
	close(release)
	select {
	case err := <-canceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("renewal context error = %v, want canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lease stop did not cancel blocked renewal")
	}
	select {
	case rec := <-done:
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("lease stop deadlocked waiting for renewal worker")
	}
}

func TestAtomicReservationSurvivesWindowDuringBackoff(t *testing.T) {
	useTummy(t)
	store, _ := newAtomicStore(t, 8)
	now := tummy.Now()
	if err := store.Set(t.Context(), "static", &ratelimit.Bucket{Attempts: []time.Time{now}}); err != nil {
		t.Fatalf("seed attempt: %v", err)
	}
	cfg := defaultConfig(store)
	cfg.SoftThreshold = 1
	cfg.HardThreshold = 2
	cfg.BackoffBase = time.Hour
	cfg.BackoffMax = time.Hour
	var handlerCalls atomic.Int32
	handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))

	start := func(ctx context.Context) <-chan struct{} {
		done := make(chan struct{})
		go func() {
			req := httptest.NewRequest(http.MethodPost, "/login", nil).WithContext(ctx)
			handler.ServeHTTP(httptest.NewRecorder(), req)
			close(done)
		}()
		return done
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	done1 := start(ctx1)
	waitForReservationCount(t, store, 1)

	tummy.AddDuration(cfg.Window + time.Second)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := start(ctx2)
	waitForReservationCount(t, store, 2)

	blocked := send(handler)
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("status with two delayed reservations = %d, want 429", blocked.Code)
	}
	if got := blocked.Header().Get("Retry-After"); got != "59" {
		t.Fatalf("Retry-After = %q, want earliest lease expiry 59", got)
	}
	if got := handlerCalls.Load(); got != 0 {
		t.Fatalf("handler ran %d times while requests should be in backoff", got)
	}

	cancel1()
	cancel2()
	for i, done := range []<-chan struct{}{done1, done2} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("backoff request %d did not stop after cancellation", i+1)
		}
	}
}

func TestAtomicAbandonedReservationExpiresAtLease(t *testing.T) {
	useTummy(t)
	store, _ := newAtomicStore(t, 8)
	now := tummy.Now()
	leaseUntil := now.Add(2 * time.Minute)
	if err := store.Set(t.Context(), "static", &ratelimit.Bucket{
		Reservations:      map[string]time.Time{"abandoned": now},
		ReservationLeases: map[string]time.Time{"abandoned": leaseUntil},
	}); err != nil {
		t.Fatalf("seed abandoned reservation: %v", err)
	}
	tummy.AddDuration(leaseUntil.Sub(now) + time.Nanosecond)

	cfg := defaultConfig(store)
	cfg.SoftThreshold = 0
	cfg.HardThreshold = 1
	rec := send(ratelimit.Middleware(cfg)(successHandler()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status after abandoned lease expired = %d, want 200", rec.Code)
	}
	if bucket, ok, err := store.Get(t.Context(), "static"); err != nil || ok || bucket != nil {
		t.Fatalf("expired reservation remained: bucket=%+v ok=%v err=%v", bucket, ok, err)
	}
}

func waitForReservationCount(t *testing.T, store ratelimit.Store, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		bucket, ok, err := store.Get(t.Context(), "static")
		if err != nil {
			t.Fatalf("get reservations: %v", err)
		}
		if ok && len(bucket.Reservations) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("reservation count did not reach %d", want)
}

func waitForSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func onlyReservationLease(t *testing.T, store ratelimit.Store) time.Time {
	t.Helper()
	bucket, ok, err := store.Get(t.Context(), "static")
	if err != nil || !ok || len(bucket.ReservationLeases) != 1 {
		t.Fatalf("reservation lease: bucket=%+v ok=%v err=%v", bucket, ok, err)
	}
	for _, leaseUntil := range bucket.ReservationLeases {
		return leaseUntil
	}
	return time.Time{}
}

func waitForLeaseAfter(t *testing.T, store ratelimit.Store, previous time.Time) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if onlyReservationLease(t, store).After(previous) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("reservation lease was not renewed")
}

func TestAtomicRejectUsesMaximumRetryAfterAcrossKeys(t *testing.T) {
	useTummy(t)
	store, _ := newAtomicStore(t, 8)
	now := tummy.Now()
	for _, attempt := range []struct {
		key string
		at  time.Time
	}{
		{key: "short", at: now.Add(-50 * time.Second)},
		{key: "long", at: now.Add(-10 * time.Second)},
	} {
		if err := store.Set(t.Context(), attempt.key, &ratelimit.Bucket{Attempts: []time.Time{attempt.at}}); err != nil {
			t.Fatalf("seed %q: %v", attempt.key, err)
		}
	}
	cfg := defaultConfig(store)
	cfg.SoftThreshold = 0
	cfg.HardThreshold = 1
	cfg.KeyFunc = func(*http.Request) []string { return []string{"short", "long"} }
	var rejectedKey string
	var rejectedFor time.Duration
	cfg.OnReject = func(_ *http.Request, key string, _ ratelimit.RejectReason, retryAfter time.Duration) {
		rejectedKey = key
		rejectedFor = retryAfter
	}
	var handlerCalls atomic.Int32
	handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerCalls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))

	rec := send(handler)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "50" {
		t.Fatalf("Retry-After = %q, want maximum delay 50", got)
	}
	if rejectedKey != "short" || rejectedFor != 50*time.Second {
		t.Fatalf("OnReject key=%q delay=%v, want first rejecting key and maximum delay", rejectedKey, rejectedFor)
	}
	if handlerCalls.Load() != 0 {
		t.Fatal("handler ran despite blocked keys")
	}
}

func TestAtomicTransactionFailuresFailClosed(t *testing.T) {
	sentinel := errors.New("transaction failed")

	t.Run("reserve", func(t *testing.T) {
		store, atomicStore := newAtomicStore(t, 8)
		failing := &failingAtomicStore{AtomicStore: atomicStore, failAt: 1, sentinel: sentinel}
		cfg := defaultConfig(failing)
		cfg.RequireAtomicStore = true
		var handlerCalls atomic.Int32
		var observed error
		cfg.OnError = func(_ *http.Request, err error) { observed = err }
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerCalls.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
		})

		rec := send(ratelimit.Middleware(cfg)(next))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
		if handlerCalls.Load() != 0 {
			t.Fatal("handler ran after reservation transaction failed")
		}
		assertTransactionError(t, observed, sentinel, []string{"static"})
		if bucket, ok, err := store.Get(t.Context(), "static"); err != nil || ok || bucket != nil {
			t.Fatalf("failed reservation changed store: bucket=%+v ok=%v err=%v", bucket, ok, err)
		}
	})

	t.Run("finalize", func(t *testing.T) {
		store, atomicStore := newAtomicStore(t, 8)
		failing := &failingAtomicStore{AtomicStore: atomicStore, failAt: 2, sentinel: sentinel}
		cfg := defaultConfig(failing)
		cfg.RequireAtomicStore = true
		cfg.KeyFunc = func(*http.Request) []string { return []string{"account", "address"} }
		var observed error
		cfg.OnError = func(_ *http.Request, err error) { observed = err }
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Downstream", "must-not-leak")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("downstream response"))
		})

		rec := send(ratelimit.Middleware(cfg)(next))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
		if rec.Header().Get("X-Downstream") != "" {
			t.Fatal("failed-closed transaction exposed downstream headers")
		}
		assertTransactionError(t, observed, sentinel, []string{"account", "address"})
		for _, key := range []string{"account", "address"} {
			if bucket, ok, err := store.Get(t.Context(), key); err != nil || ok || bucket != nil {
				t.Fatalf("failed finalization partially changed %q: bucket=%+v ok=%v err=%v", key, bucket, ok, err)
			}
		}
	})
}

func assertTransactionError(t *testing.T, got, target error, keys []string) {
	t.Helper()
	if !errors.Is(got, target) {
		t.Fatalf("OnError error = %v, want wrapping %v", got, target)
	}
	var storeErr *ratelimit.StoreError
	if !errors.As(got, &storeErr) || storeErr.Operation != ratelimit.StoreOperationTransaction {
		t.Fatalf("OnError error = %#v, want transaction StoreError", got)
	}
	wantKey := fmt.Sprint(keys)
	if storeErr.Key != wantKey {
		t.Fatalf("StoreError.Key = %q, want %q", storeErr.Key, wantKey)
	}
}

func TestMemoryStoreTransactionIsAllOrNothing(t *testing.T) {
	store, atomicStore := newAtomicStore(t, 8)
	now := time.Now()
	for _, key := range []string{"a", "b"} {
		if err := store.Set(t.Context(), key, &ratelimit.Bucket{Attempts: []time.Time{now}}); err != nil {
			t.Fatalf("seed %q: %v", key, err)
		}
	}

	sentinel := errors.New("abort")
	err := atomicStore.Transaction(t.Context(), []string{"a", "b"}, func(buckets map[string]*ratelimit.Bucket) error {
		buckets["a"].Attempts = append(buckets["a"].Attempts, now)
		buckets["b"] = nil
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Transaction error = %v, want %v", err, sentinel)
	}
	for _, key := range []string{"a", "b"} {
		bucket, ok, getErr := store.Get(t.Context(), key)
		if getErr != nil || !ok || len(bucket.Attempts) != 1 {
			t.Fatalf("bucket %q partially changed: bucket=%+v ok=%v err=%v", key, bucket, ok, getErr)
		}
	}
}

func TestMemoryStoreCapacityFailureDoesNotPartiallyCommit(t *testing.T) {
	store, atomicStore := newAtomicStore(t, 1)
	err := atomicStore.Transaction(t.Context(), []string{"a", "b"}, func(buckets map[string]*ratelimit.Bucket) error {
		buckets["a"] = &ratelimit.Bucket{Attempts: []time.Time{time.Now()}}
		buckets["b"] = &ratelimit.Bucket{Attempts: []time.Time{time.Now()}}
		return nil
	})
	if err == nil {
		t.Fatal("Transaction succeeded despite capacity smaller than requested update")
	}
	for _, key := range []string{"a", "b"} {
		if bucket, ok, getErr := store.Get(t.Context(), key); getErr != nil || ok || bucket != nil {
			t.Fatalf("bucket %q partially persisted: bucket=%+v ok=%v err=%v", key, bucket, ok, getErr)
		}
	}
}

func TestMemoryStoreDoesNotEvictActiveReservation(t *testing.T) {
	store, atomicStore := newAtomicStore(t, 1)
	now := time.Now()
	if err := atomicStore.Transaction(t.Context(), []string{"active"}, func(buckets map[string]*ratelimit.Bucket) error {
		buckets["active"] = &ratelimit.Bucket{Reservations: map[string]time.Time{"request": now}}
		return nil
	}); err != nil {
		t.Fatalf("seed reservation: %v", err)
	}

	err := atomicStore.Transaction(t.Context(), []string{"new"}, func(buckets map[string]*ratelimit.Bucket) error {
		buckets["new"] = &ratelimit.Bucket{Attempts: []time.Time{now}}
		return nil
	})
	if err == nil {
		t.Fatal("Transaction evicted an active reservation to make room")
	}
	active, ok, getErr := store.Get(t.Context(), "active")
	if getErr != nil || !ok || len(active.Reservations) != 1 {
		t.Fatalf("active reservation changed: bucket=%+v ok=%v err=%v", active, ok, getErr)
	}
	if bucket, ok, getErr := store.Get(t.Context(), "new"); getErr != nil || ok || bucket != nil {
		t.Fatalf("failed transaction partially persisted new bucket: bucket=%+v ok=%v err=%v", bucket, ok, getErr)
	}
}

func TestMemoryStoreDoesNotEvictLiveAttemptAtCapacity(t *testing.T) {
	useTummy(t)
	now := tummy.Now()

	for _, tc := range []struct {
		name   string
		insert func(context.Context, ratelimit.Store, ratelimit.AtomicStore) error
	}{
		{
			name: "Set",
			insert: func(ctx context.Context, store ratelimit.Store, _ ratelimit.AtomicStore) error {
				return store.Set(ctx, "new", &ratelimit.Bucket{Attempts: []time.Time{now}})
			},
		},
		{
			name: "Transaction",
			insert: func(ctx context.Context, _ ratelimit.Store, atomicStore ratelimit.AtomicStore) error {
				return atomicStore.Transaction(ctx, []string{"new"}, func(buckets map[string]*ratelimit.Bucket) error {
					buckets["new"] = &ratelimit.Bucket{Attempts: []time.Time{now}}
					return nil
				})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, atomicStore := newAtomicStore(t, 1)
			_ = ratelimit.Middleware(defaultConfig(store))
			if err := store.Set(t.Context(), "live", &ratelimit.Bucket{Attempts: []time.Time{now}}); err != nil {
				t.Fatalf("seed live attempt: %v", err)
			}

			if err := tc.insert(t.Context(), store, atomicStore); err == nil || !strings.Contains(err.Error(), "none are reclaimable") {
				t.Fatalf("capacity error = %v, want no reclaimable buckets", err)
			}
			live, ok, err := store.Get(t.Context(), "live")
			if err != nil || !ok || len(live.Attempts) != 1 || !live.Attempts[0].Equal(now) {
				t.Fatalf("live bucket changed: bucket=%+v ok=%v err=%v", live, ok, err)
			}
			if bucket, ok, err := store.Get(t.Context(), "new"); err != nil || ok || bucket != nil {
				t.Fatalf("failed insert partially persisted: bucket=%+v ok=%v err=%v", bucket, ok, err)
			}
		})
	}
}

func TestMemoryStoreCapacityErrorFollowsPolicy(t *testing.T) {
	for _, tc := range []struct {
		name             string
		policy           ratelimit.ErrorPolicy
		wantStatus       int
		wantHandlerCalls int32
	}{
		{name: "default fail closed", wantStatus: http.StatusServiceUnavailable, wantHandlerCalls: 1},
		{name: "fail open", policy: ratelimit.ErrorPolicyFailOpen, wantStatus: http.StatusUnauthorized, wantHandlerCalls: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := newAtomicStore(t, 1)
			cfg := defaultConfig(store)
			cfg.ErrorPolicy = tc.policy
			cfg.KeyFunc = func(r *http.Request) []string { return []string{r.Header.Get("X-Key")} }
			var handlerCalls atomic.Int32
			var observed []error
			cfg.OnError = func(_ *http.Request, err error) { observed = append(observed, err) }
			handler := ratelimit.Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				handlerCalls.Add(1)
				w.WriteHeader(http.StatusUnauthorized)
			}))
			sendKey := func(key string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, "/login", nil)
				req.Header.Set("X-Key", key)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				return rec
			}

			if rec := sendKey("live"); rec.Code != http.StatusUnauthorized {
				t.Fatalf("seed status = %d, want 401", rec.Code)
			}
			if rec := sendKey("new"); rec.Code != tc.wantStatus {
				t.Fatalf("capacity status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if got := handlerCalls.Load(); got != tc.wantHandlerCalls {
				t.Fatalf("handler calls = %d, want %d", got, tc.wantHandlerCalls)
			}
			if len(observed) != 1 {
				t.Fatalf("OnError calls = %d, want 1: %v", len(observed), observed)
			}
			var storeErr *ratelimit.StoreError
			if !errors.As(observed[0], &storeErr) || storeErr.Operation != ratelimit.StoreOperationTransaction || !strings.Contains(observed[0].Error(), "none are reclaimable") {
				t.Fatalf("OnError = %#v, want transaction capacity StoreError", observed[0])
			}
			live, ok, err := store.Get(t.Context(), "live")
			if err != nil || !ok || len(live.Attempts) != 1 {
				t.Fatalf("live enforcing bucket changed: bucket=%+v ok=%v err=%v", live, ok, err)
			}
			if bucket, ok, err := store.Get(t.Context(), "new"); err != nil || ok || bucket != nil {
				t.Fatalf("capacity failure persisted new bucket: bucket=%+v ok=%v err=%v", bucket, ok, err)
			}
		})
	}
}

func TestMemoryStoreReclaimsAttemptsAfterObservedWindow(t *testing.T) {
	useTummy(t)
	store, _ := newAtomicStore(t, 1)
	cfg := defaultConfig(store)
	cfg.Window = time.Minute
	_ = ratelimit.Middleware(cfg)
	now := tummy.Now()
	if err := store.Set(t.Context(), "expired", &ratelimit.Bucket{Attempts: []time.Time{now}}); err != nil {
		t.Fatalf("seed attempt: %v", err)
	}

	tummy.AddDuration(cfg.Window + time.Nanosecond)
	if err := store.Set(t.Context(), "new", &ratelimit.Bucket{Attempts: []time.Time{tummy.Now()}}); err != nil {
		t.Fatalf("reclaim expired attempt: %v", err)
	}
	if bucket, ok, err := store.Get(t.Context(), "expired"); err != nil || ok || bucket != nil {
		t.Fatalf("expired bucket was not reclaimed: bucket=%+v ok=%v err=%v", bucket, ok, err)
	}
}

func TestMemoryStoreUsesLongestObservedWindow(t *testing.T) {
	useTummy(t)
	store, _ := newAtomicStore(t, 1)
	short := defaultConfig(store)
	short.Window = time.Minute
	long := defaultConfig(store)
	long.Window = 2 * time.Minute
	_ = ratelimit.Middleware(short)
	_ = ratelimit.Middleware(long)
	now := tummy.Now()
	if err := store.Set(t.Context(), "shared", &ratelimit.Bucket{Attempts: []time.Time{now}}); err != nil {
		t.Fatalf("seed shared attempt: %v", err)
	}

	tummy.AddDuration(90 * time.Second)
	if err := store.Set(t.Context(), "too-soon", &ratelimit.Bucket{Attempts: []time.Time{tummy.Now()}}); err == nil {
		t.Fatal("store reclaimed bucket before longest observed window elapsed")
	}
	shared, ok, err := store.Get(t.Context(), "shared")
	if err != nil || !ok || len(shared.Attempts) != 1 {
		t.Fatalf("shared bucket changed before longest window: bucket=%+v ok=%v err=%v", shared, ok, err)
	}

	tummy.AddDuration(31 * time.Second)
	if err := store.Set(t.Context(), "new", &ratelimit.Bucket{Attempts: []time.Time{tummy.Now()}}); err != nil {
		t.Fatalf("reclaim after longest window: %v", err)
	}
	if bucket, ok, err := store.Get(t.Context(), "shared"); err != nil || ok || bucket != nil {
		t.Fatalf("shared bucket was not reclaimed: bucket=%+v ok=%v err=%v", bucket, ok, err)
	}
}

func TestMemoryStoreEvictsExpiredLeasedReservationAtCapacity(t *testing.T) {
	useTummy(t)
	now := tummy.Now()

	for _, tc := range []struct {
		name   string
		insert func(context.Context, ratelimit.Store, ratelimit.AtomicStore) error
	}{
		{
			name: "Set",
			insert: func(ctx context.Context, store ratelimit.Store, _ ratelimit.AtomicStore) error {
				return store.Set(ctx, "new", &ratelimit.Bucket{Attempts: []time.Time{now}})
			},
		},
		{
			name: "Transaction",
			insert: func(ctx context.Context, _ ratelimit.Store, atomicStore ratelimit.AtomicStore) error {
				return atomicStore.Transaction(ctx, []string{"new"}, func(buckets map[string]*ratelimit.Bucket) error {
					buckets["new"] = &ratelimit.Bucket{Attempts: []time.Time{now}}
					return nil
				})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, atomicStore := newAtomicStore(t, 1)
			expired := &ratelimit.Bucket{
				Reservations:      map[string]time.Time{"request": now.Add(-time.Minute)},
				ReservationLeases: map[string]time.Time{"request": now},
			}
			if err := store.Set(t.Context(), "expired", expired); err != nil {
				t.Fatalf("seed expired reservation: %v", err)
			}
			if err := tc.insert(t.Context(), store, atomicStore); err != nil {
				t.Fatalf("insert at capacity: %v", err)
			}
			if bucket, ok, err := store.Get(t.Context(), "expired"); err != nil || ok || bucket != nil {
				t.Fatalf("expired reservation was not evicted: bucket=%+v ok=%v err=%v", bucket, ok, err)
			}
			if bucket, ok, err := store.Get(t.Context(), "new"); err != nil || !ok || len(bucket.Attempts) != 1 {
				t.Fatalf("new bucket was not stored: bucket=%+v ok=%v err=%v", bucket, ok, err)
			}
		})
	}
}

func TestMemoryStoreDoesNotEvictActiveLeasedReservation(t *testing.T) {
	useTummy(t)
	store, _ := newAtomicStore(t, 1)
	now := tummy.Now()
	active := &ratelimit.Bucket{
		Reservations:      map[string]time.Time{"request": now},
		ReservationLeases: map[string]time.Time{"request": now.Add(time.Minute)},
	}
	if err := store.Set(t.Context(), "active", active); err != nil {
		t.Fatalf("seed active reservation: %v", err)
	}
	if err := store.Set(t.Context(), "new", &ratelimit.Bucket{Attempts: []time.Time{now}}); err == nil {
		t.Fatal("Set evicted an active leased reservation")
	}
	if bucket, ok, err := store.Get(t.Context(), "active"); err != nil || !ok || len(bucket.Reservations) != 1 {
		t.Fatalf("active leased reservation changed: bucket=%+v ok=%v err=%v", bucket, ok, err)
	}
}

func TestMemoryStoreCopiesReservationLeaseState(t *testing.T) {
	store, _ := newAtomicStore(t, 1)
	now := time.Now()
	bucket := &ratelimit.Bucket{
		Reservations:      map[string]time.Time{"request": now},
		ReservationLeases: map[string]time.Time{"request": now.Add(time.Minute)},
	}
	if err := store.Set(t.Context(), "active", bucket); err != nil {
		t.Fatalf("set bucket: %v", err)
	}
	bucket.ReservationLeases["request"] = now

	got, ok, err := store.Get(t.Context(), "active")
	if err != nil || !ok {
		t.Fatalf("get bucket: ok=%v err=%v", ok, err)
	}
	if want := now.Add(time.Minute); !got.ReservationLeases["request"].Equal(want) {
		t.Fatalf("stored lease = %v, want %v", got.ReservationLeases["request"], want)
	}
	got.ReservationLeases["request"] = now.Add(2 * time.Minute)
	gotAgain, _, err := store.Get(t.Context(), "active")
	if err != nil {
		t.Fatalf("get bucket again: %v", err)
	}
	if want := now.Add(time.Minute); !gotAgain.ReservationLeases["request"].Equal(want) {
		t.Fatalf("mutated read changed stored lease to %v, want %v", gotAgain.ReservationLeases["request"], want)
	}
}

func TestCacheStoreDoesNotClaimAtomicStore(t *testing.T) {
	if _, ok := ratelimit.NewCacheStore(nil).(ratelimit.AtomicStore); ok {
		t.Fatal("NewCacheStore unexpectedly implements AtomicStore")
	}
}

func TestRequireAtomicStoreRejectsLegacyStore(t *testing.T) {
	cfg := defaultConfig(&errorStore{})
	cfg.RequireAtomicStore = true
	defer func() {
		if recover() == nil {
			t.Fatal("Middleware accepted a legacy Store with RequireAtomicStore")
		}
	}()
	_ = ratelimit.Middleware(cfg)
}

func TestRequireAtomicStoreAcceptsMemoryStore(t *testing.T) {
	store, _ := newAtomicStore(t, 8)
	cfg := defaultConfig(store)
	cfg.RequireAtomicStore = true
	_ = ratelimit.Middleware(cfg)
}

func TestInvalidConfigPanics(t *testing.T) {
	store, _ := newAtomicStore(t, 8)
	valid := defaultConfig(store)
	cases := []struct {
		name   string
		mutate func(*ratelimit.Config)
	}{
		{"zero window", func(cfg *ratelimit.Config) { cfg.Window = 0 }},
		{"negative window", func(cfg *ratelimit.Config) { cfg.Window = -time.Second }},
		{"negative soft threshold", func(cfg *ratelimit.Config) { cfg.SoftThreshold = -1 }},
		{"negative hard threshold", func(cfg *ratelimit.Config) { cfg.HardThreshold = -1 }},
		{"both thresholds disabled", func(cfg *ratelimit.Config) { cfg.SoftThreshold, cfg.HardThreshold = 0, 0 }},
		{"equal thresholds", func(cfg *ratelimit.Config) { cfg.SoftThreshold = cfg.HardThreshold }},
		{"soft above hard", func(cfg *ratelimit.Config) { cfg.SoftThreshold = cfg.HardThreshold + 1 }},
		{"negative backoff base", func(cfg *ratelimit.Config) { cfg.BackoffBase = -time.Second }},
		{"negative backoff max", func(cfg *ratelimit.Config) { cfg.BackoffMax = -time.Second }},
		{"negative store operation timeout", func(cfg *ratelimit.Config) { cfg.StoreOperationTimeout = -time.Second }},
		{"invalid error policy", func(cfg *ratelimit.Config) { cfg.ErrorPolicy = ratelimit.ErrorPolicy(255) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			defer func() {
				if recover() == nil {
					t.Fatal("Middleware accepted invalid Config")
				}
			}()
			_ = ratelimit.Middleware(cfg)
		})
	}
}
