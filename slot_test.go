package ada

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// headerMiddleware returns a middleware that sets a response header.
func headerMiddleware(key, value string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(key, value)
			next.ServeHTTP(w, r)
		})
	}
}

// blockingMiddleware returns a middleware that blocks until the context is done
// or the done channel is closed. It sets "X-Cancelled" header to "true" if
// context was cancelled, "false" otherwise.
func blockingMiddleware(done <-chan struct{}) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
				w.Header().Set("X-Cancelled", "true")
				return
			case <-done:
				w.Header().Set("X-Cancelled", "false")
				next.ServeHTTP(w, r)
			}
		})
	}
}

func okHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestNewSlot(t *testing.T) {
	t.Run("with middleware", func(t *testing.T) {
		slot := NewSlot(headerMiddleware("X-Test", "v1"))
		if !slot.Enabled() {
			t.Fatal("new slot should be enabled")
		}
	})

	t.Run("with nil defaults to NoOp", func(t *testing.T) {
		slot := NewSlot(nil)
		if !slot.Enabled() {
			t.Fatal("new slot with nil should be enabled")
		}

		// Should work as pass-through
		mw := slot.Middleware()
		handler := mw(http.HandlerFunc(okHandler))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})
}

func TestSlot_Middleware(t *testing.T) {
	slot := NewSlot(headerMiddleware("X-Auth", "token123"))
	mw := slot.Middleware()
	handler := mw(http.HandlerFunc(okHandler))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rec.Header().Get("X-Auth"); got != "token123" {
		t.Fatalf("expected X-Auth=token123, got %q", got)
	}
}

func TestSlot_Replace(t *testing.T) {
	slot := NewSlot(headerMiddleware("X-Version", "v1"))
	mw := slot.Middleware()
	handler := mw(http.HandlerFunc(okHandler))

	// Before replace
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get("X-Version"); got != "v1" {
		t.Fatalf("before replace: expected v1, got %q", got)
	}

	// Replace
	slot.Replace(headerMiddleware("X-Version", "v2"))

	// After replace — same handler, new middleware
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get("X-Version"); got != "v2" {
		t.Fatalf("after replace: expected v2, got %q", got)
	}
}

func TestSlot_ReplaceNil(t *testing.T) {
	slot := NewSlot(headerMiddleware("X-Test", "v1"))
	slot.Replace(nil) // should not panic, defaults to NoOp

	if !slot.Enabled() {
		t.Fatal("Replace(nil) should keep slot enabled")
	}
}

func TestSlot_Disable(t *testing.T) {
	slot := NewSlot(headerMiddleware("X-Auth", "secret"))
	mw := slot.Middleware()
	handler := mw(http.HandlerFunc(okHandler))

	// Before disable
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get("X-Auth"); got != "secret" {
		t.Fatalf("before disable: expected secret, got %q", got)
	}

	// Disable
	slot.Disable()
	if slot.Enabled() {
		t.Fatal("should be disabled")
	}

	// After disable — middleware is skipped
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get("X-Auth"); got != "" {
		t.Fatalf("after disable: expected empty header, got %q", got)
	}
}

func TestSlot_EnableRestoresPreviousMiddleware(t *testing.T) {
	slot := NewSlot(headerMiddleware("X-Auth", "restored"))
	mw := slot.Middleware()
	handler := mw(http.HandlerFunc(okHandler))

	slot.Disable()
	slot.Enable()

	if !slot.Enabled() {
		t.Fatal("should be enabled after Enable")
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get("X-Auth"); got != "restored" {
		t.Fatalf("expected restored, got %q", got)
	}
}

func TestSlot_EnableWhenAlreadyEnabled(t *testing.T) {
	slot := NewSlot(headerMiddleware("X-Test", "v1"))
	slot.Enable() // no-op

	if !slot.Enabled() {
		t.Fatal("should still be enabled")
	}
}

func TestSlot_DisableNilState(t *testing.T) {
	s := &Slot{}
	s.Disable() // should not panic

	if s.Enabled() {
		t.Fatal("should be disabled")
	}
}

func TestSlot_EnableNilState(t *testing.T) {
	s := &Slot{}
	s.Enable() // should not panic on nil state
}

func TestSlot_SharedAcrossRegistrations(t *testing.T) {
	slot := NewSlot(headerMiddleware("X-Shared", "v1"))

	// Two separate registrations of the same slot
	handler1 := slot.Middleware()(http.HandlerFunc(okHandler))
	handler2 := slot.Middleware()(http.HandlerFunc(okHandler))

	// Both should see v1
	rec1 := httptest.NewRecorder()
	handler1.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/", nil))
	rec2 := httptest.NewRecorder()
	handler2.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec1.Header().Get("X-Shared") != "v1" || rec2.Header().Get("X-Shared") != "v1" {
		t.Fatal("both registrations should see v1")
	}

	// Replace once
	slot.Replace(headerMiddleware("X-Shared", "v2"))

	// Both should see v2
	rec1 = httptest.NewRecorder()
	handler1.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/", nil))
	rec2 = httptest.NewRecorder()
	handler2.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec1.Header().Get("X-Shared") != "v2" || rec2.Header().Get("X-Shared") != "v2" {
		t.Fatalf("both registrations should see v2, got %q and %q",
			rec1.Header().Get("X-Shared"), rec2.Header().Get("X-Shared"))
	}
}

func TestSlot_ReplaceWhileServing(t *testing.T) {
	var served atomic.Int64

	slot := NewSlot(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			served.Add(1)
			next.ServeHTTP(w, r)
		})
	})

	handler := slot.Middleware()(http.HandlerFunc(okHandler))

	const goroutines = 50
	const requestsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines + 1)

	// Readers: fire requests concurrently
	for range goroutines {
		go func() {
			defer wg.Done()
			for range requestsPerGoroutine {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
				if rec.Code != http.StatusOK {
					t.Errorf("expected 200, got %d", rec.Code)
				}
			}
		}()
	}

	// Writer: replace the middleware continuously
	go func() {
		defer wg.Done()
		for range requestsPerGoroutine {
			slot.Replace(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					served.Add(1)
					next.ServeHTTP(w, r)
				})
			})
		}
	}()

	wg.Wait()

	total := served.Load()
	if total != goroutines*requestsPerGoroutine {
		t.Fatalf("expected %d served, got %d", goroutines*requestsPerGoroutine, total)
	}
}

func TestSlot_ReplaceWithTimeout_ImmediateCancel(t *testing.T) {
	done := make(chan struct{})
	// Use ReplaceWithTimeout to set up a cancel-capable generation.
	// NewSlot does not create a cancel context (opt-in), so we need
	// a WithTimeout call to enable cancellation for in-flight requests.
	slot := NewSlot(NoOp())
	handler := slot.Middleware()(http.HandlerFunc(okHandler))
	slot.ReplaceWithTimeout(blockingMiddleware(done), 24*time.Hour)

	var wg sync.WaitGroup
	rec := httptest.NewRecorder()

	wg.Add(1)
	go func() {
		defer wg.Done()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	}()

	// Give the request time to enter the blocking middleware
	time.Sleep(20 * time.Millisecond)

	// Replace with immediate cancel (grace=0)
	slot.ReplaceWithTimeout(headerMiddleware("X-New", "yes"), 0)

	wg.Wait()
	close(done)

	if got := rec.Header().Get("X-Cancelled"); got != "true" {
		t.Fatalf("expected X-Cancelled=true, got %q", got)
	}
}

func TestSlot_ReplaceWithTimeout_GracePeriod(t *testing.T) {
	done := make(chan struct{})
	slot := NewSlot(NoOp())
	handler := slot.Middleware()(http.HandlerFunc(okHandler))
	slot.ReplaceWithTimeout(blockingMiddleware(done), 24*time.Hour)

	var wg sync.WaitGroup
	rec := httptest.NewRecorder()

	wg.Add(1)
	go func() {
		defer wg.Done()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	}()

	// Give the request time to enter the blocking middleware
	time.Sleep(20 * time.Millisecond)

	// Replace with 200ms grace — request should complete before timeout
	slot.ReplaceWithTimeout(headerMiddleware("X-New", "yes"), 200*time.Millisecond)

	// Let the request finish naturally before grace expires
	close(done)
	wg.Wait()

	if got := rec.Header().Get("X-Cancelled"); got != "false" {
		t.Fatalf("expected X-Cancelled=false (finished before grace), got %q", got)
	}
}

func TestSlot_DisableWithTimeout(t *testing.T) {
	done := make(chan struct{})
	slot := NewSlot(NoOp())
	handler := slot.Middleware()(http.HandlerFunc(okHandler))
	slot.ReplaceWithTimeout(blockingMiddleware(done), 24*time.Hour)

	var wg sync.WaitGroup
	rec := httptest.NewRecorder()

	wg.Add(1)
	go func() {
		defer wg.Done()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	}()

	time.Sleep(20 * time.Millisecond)

	// Disable with immediate cancel
	slot.DisableWithTimeout(0)

	wg.Wait()
	close(done)

	if got := rec.Header().Get("X-Cancelled"); got != "true" {
		t.Fatalf("expected X-Cancelled=true, got %q", got)
	}

	if slot.Enabled() {
		t.Fatal("should be disabled")
	}
}

func TestSlot_MergeContexts(t *testing.T) {
	t.Run("cancel context fires", func(t *testing.T) {
		parent := context.Background()
		cancel, stop := context.WithCancel(context.Background())

		merged, cleanup := mergeContexts(parent, cancel)
		defer cleanup()
		stop() // cancel the cancel context

		select {
		case <-merged.Done():
			// expected
		case <-time.After(time.Second):
			t.Fatal("merged context should be cancelled when cancel context fires")
		}
	})

	t.Run("parent context fires", func(t *testing.T) {
		parent, parentStop := context.WithCancel(context.Background())
		cancel, cancelStop := context.WithCancel(context.Background())
		defer cancelStop()

		merged, cleanup := mergeContexts(parent, cancel)
		defer cleanup()
		parentStop()

		select {
		case <-merged.Done():
			// expected
		case <-time.After(time.Second):
			t.Fatal("merged context should be cancelled when parent fires")
		}
	})

	t.Run("nil cancel returns parent", func(t *testing.T) {
		parent := context.Background()
		got, cleanup := mergeContexts(parent, nil)
		defer cleanup()
		if got != parent {
			t.Fatal("nil cancel should return parent directly")
		}
	})
}

func TestNoOp(t *testing.T) {
	noop := NoOp()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Inner", "yes")
	})

	handler := noop(inner)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rec.Header().Get("X-Inner"); got != "yes" {
		t.Fatalf("NoOp should pass through, got X-Inner=%q", got)
	}
}
