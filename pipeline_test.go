package ada

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// appendHeaderMiddleware appends a value to a response header (comma-separated).
// Useful for verifying middleware ordering.
func appendHeaderMiddleware(key, value string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			existing := w.Header().Get(key)
			if existing != "" {
				w.Header().Set(key, existing+","+value)
			} else {
				w.Header().Set(key, value)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func TestNewPipeline(t *testing.T) {
	p := NewPipeline()
	if p.Len() != 0 {
		t.Fatalf("expected empty pipeline, got len=%d", p.Len())
	}

	if keys := p.Keys(); len(keys) != 0 {
		t.Fatalf("expected no keys, got %v", keys)
	}
}

func TestPipeline_EmptyIsPassThrough(t *testing.T) {
	p := NewPipeline()
	handler := p.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Inner", "yes")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rec.Header().Get("X-Inner"); got != "yes" {
		t.Fatalf("empty pipeline should pass through, got X-Inner=%q", got)
	}
}

func TestPipeline_Set(t *testing.T) {
	p := NewPipeline()
	handler := p.Middleware()(http.HandlerFunc(okHandler))

	p.Set("auth", headerMiddleware("X-Auth", "token"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rec.Header().Get("X-Auth"); got != "token" {
		t.Fatalf("expected X-Auth=token, got %q", got)
	}

	if !p.Has("auth") {
		t.Fatal("Has should return true for existing key")
	}

	if p.Has("nonexistent") {
		t.Fatal("Has should return false for nonexistent key")
	}

	if p.Len() != 1 {
		t.Fatalf("expected len=1, got %d", p.Len())
	}
}

func TestPipeline_SetNil(t *testing.T) {
	p := NewPipeline()
	p.Set("test", nil) // should not panic, defaults to NoOp

	if p.Len() != 1 {
		t.Fatalf("expected len=1, got %d", p.Len())
	}
}

func TestPipeline_SetReplacesInPlace(t *testing.T) {
	p := NewPipeline()
	handler := p.Middleware()(http.HandlerFunc(okHandler))

	p.Set("cors", appendHeaderMiddleware("X-Order", "cors"))
	p.Set("auth", appendHeaderMiddleware("X-Order", "auth-v1"))
	p.Set("log", appendHeaderMiddleware("X-Order", "log"))

	// Replace auth in-place
	p.Set("auth", appendHeaderMiddleware("X-Order", "auth-v2"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	got := rec.Header().Get("X-Order")
	expected := "cors,auth-v2,log"
	if got != expected {
		t.Fatalf("expected order %q, got %q", expected, got)
	}

	// Keys order should be preserved
	keys := p.Keys()
	expectedKeys := "cors,auth,log"
	if strings.Join(keys, ",") != expectedKeys {
		t.Fatalf("expected keys %q, got %q", expectedKeys, strings.Join(keys, ","))
	}
}

func TestPipeline_SetAt(t *testing.T) {
	p := NewPipeline()
	handler := p.Middleware()(http.HandlerFunc(okHandler))

	p.Set("a", appendHeaderMiddleware("X-Order", "a"))
	p.Set("c", appendHeaderMiddleware("X-Order", "c"))

	// Insert "b" at position 1 (between a and c)
	p.SetAt(1, "b", appendHeaderMiddleware("X-Order", "b"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	got := rec.Header().Get("X-Order")
	expected := "a,b,c"
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestPipeline_SetAtMovesExisting(t *testing.T) {
	p := NewPipeline()
	handler := p.Middleware()(http.HandlerFunc(okHandler))

	p.Set("a", appendHeaderMiddleware("X-Order", "a"))
	p.Set("b", appendHeaderMiddleware("X-Order", "b"))
	p.Set("c", appendHeaderMiddleware("X-Order", "c"))

	// Move "c" to position 0
	p.SetAt(0, "c", appendHeaderMiddleware("X-Order", "c"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	got := rec.Header().Get("X-Order")
	expected := "c,a,b"
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestPipeline_SetAtOutOfRange(t *testing.T) {
	p := NewPipeline()
	p.Set("a", appendHeaderMiddleware("X-Order", "a"))

	// Index beyond range should append
	p.SetAt(100, "b", appendHeaderMiddleware("X-Order", "b"))

	keys := p.Keys()
	if strings.Join(keys, ",") != "a,b" {
		t.Fatalf("expected a,b, got %s", strings.Join(keys, ","))
	}

	// Negative index should append
	p.SetAt(-1, "c", appendHeaderMiddleware("X-Order", "c"))

	keys = p.Keys()
	if strings.Join(keys, ",") != "a,b,c" {
		t.Fatalf("expected a,b,c, got %s", strings.Join(keys, ","))
	}
}

func TestPipeline_Remove(t *testing.T) {
	p := NewPipeline()
	handler := p.Middleware()(http.HandlerFunc(okHandler))

	p.Set("a", appendHeaderMiddleware("X-Order", "a"))
	p.Set("b", appendHeaderMiddleware("X-Order", "b"))
	p.Set("c", appendHeaderMiddleware("X-Order", "c"))

	// Remove middle element
	removed := p.Remove("b")
	if !removed {
		t.Fatal("Remove should return true for existing key")
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	got := rec.Header().Get("X-Order")
	expected := "a,c"
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}

	if p.Has("b") {
		t.Fatal("Has should return false after remove")
	}

	if p.Len() != 2 {
		t.Fatalf("expected len=2, got %d", p.Len())
	}
}

func TestPipeline_RemoveNonexistent(t *testing.T) {
	p := NewPipeline()
	if p.Remove("nope") {
		t.Fatal("Remove should return false for nonexistent key")
	}
}

func TestPipeline_Reset(t *testing.T) {
	p := NewPipeline()
	handler := p.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Inner", "yes")
	}))

	p.Set("a", headerMiddleware("X-A", "1"))
	p.Set("b", headerMiddleware("X-B", "2"))

	p.Reset()

	if p.Len() != 0 {
		t.Fatalf("expected len=0 after reset, got %d", p.Len())
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	// After reset, only inner handler should run
	if got := rec.Header().Get("X-Inner"); got != "yes" {
		t.Fatalf("expected X-Inner=yes after reset, got %q", got)
	}

	if got := rec.Header().Get("X-A"); got != "" {
		t.Fatalf("expected no X-A after reset, got %q", got)
	}
}

func TestPipeline_Keys(t *testing.T) {
	p := NewPipeline()
	p.Set("c", NoOp())
	p.Set("a", NoOp())
	p.Set("b", NoOp())

	keys := p.Keys()
	expected := "c,a,b"
	if strings.Join(keys, ",") != expected {
		t.Fatalf("expected %q, got %q", expected, strings.Join(keys, ","))
	}

	// Verify it's a copy, not the internal slice
	keys[0] = "modified"
	keysAgain := p.Keys()
	if keysAgain[0] == "modified" {
		t.Fatal("Keys should return a copy, not the internal slice")
	}
}

func TestPipeline_HasOnNilSnapshot(t *testing.T) {
	p := &Pipeline{}
	if p.Has("anything") {
		t.Fatal("Has on nil snapshot should return false")
	}
}

func TestPipeline_LenOnNilSnapshot(t *testing.T) {
	p := &Pipeline{}
	if p.Len() != 0 {
		t.Fatal("Len on nil snapshot should return 0")
	}
}

func TestPipeline_KeysOnNilSnapshot(t *testing.T) {
	p := &Pipeline{}
	if keys := p.Keys(); keys != nil {
		t.Fatalf("Keys on nil snapshot should return nil, got %v", keys)
	}
}

// ── Apply tests ─────────────────────────────────────────────────────────────

func TestPipeline_Apply_BatchSwap(t *testing.T) {
	p := NewPipeline()
	handler := p.Middleware()(http.HandlerFunc(okHandler))

	p.Set("a", appendHeaderMiddleware("X-Order", "a"))
	p.Set("b", appendHeaderMiddleware("X-Order", "b"))

	// Batch replace: clear and rebuild
	p.Apply(func(b *PipelineBuilder) {
		b.Reset()
		b.Set("x", appendHeaderMiddleware("X-Order", "x"))
		b.Set("y", appendHeaderMiddleware("X-Order", "y"))
		b.Set("z", appendHeaderMiddleware("X-Order", "z"))
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	got := rec.Header().Get("X-Order")
	expected := "x,y,z"
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}

	keys := p.Keys()
	if strings.Join(keys, ",") != "x,y,z" {
		t.Fatalf("expected keys x,y,z, got %s", strings.Join(keys, ","))
	}
}

func TestPipeline_Apply_RemoveAndReinsert(t *testing.T) {
	p := NewPipeline()
	handler := p.Middleware()(http.HandlerFunc(okHandler))

	p.Set("cors", appendHeaderMiddleware("X-Order", "cors"))
	p.Set("auth", appendHeaderMiddleware("X-Order", "auth"))
	p.Set("log", appendHeaderMiddleware("X-Order", "log"))

	// Remove auth and re-insert at position 1 with new config
	p.Apply(func(b *PipelineBuilder) {
		b.Remove("auth")
		b.SetAt(1, "auth", appendHeaderMiddleware("X-Order", "auth-new"))
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	got := rec.Header().Get("X-Order")
	expected := "cors,auth-new,log"
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestPipeline_Apply_ConditionalMutation(t *testing.T) {
	p := NewPipeline()
	p.Set("cors", NoOp())

	p.Apply(func(b *PipelineBuilder) {
		if b.Has("cors") {
			b.Remove("cors")
		}

		if !b.Has("auth") {
			b.Set("auth", NoOp())
		}
	})

	if p.Has("cors") {
		t.Fatal("cors should have been removed")
	}

	if !p.Has("auth") {
		t.Fatal("auth should have been added")
	}
}

func TestPipeline_Apply_BuilderKeys(t *testing.T) {
	p := NewPipeline()
	p.Set("a", NoOp())
	p.Set("b", NoOp())

	p.Apply(func(b *PipelineBuilder) {
		keys := b.Keys()
		if strings.Join(keys, ",") != "a,b" {
			t.Fatalf("expected a,b, got %s", strings.Join(keys, ","))
		}

		if b.Len() != 2 {
			t.Fatalf("expected len=2, got %d", b.Len())
		}

		b.Set("c", NoOp())

		if b.Len() != 3 {
			t.Fatalf("expected len=3 after set, got %d", b.Len())
		}
	})
}

// ── Cancel / timeout tests ──────────────────────────────────────────────────

func TestPipeline_ApplyWithTimeout_ImmediateCancel(t *testing.T) {
	p := NewPipeline()

	done := make(chan struct{})
	// Use ApplyWithTimeout to set up a cancel-capable generation.
	// Regular Set does not create a cancel context (opt-in).
	handler := p.Middleware()(http.HandlerFunc(okHandler))
	p.ApplyWithTimeout(func(b *PipelineBuilder) {
		b.Set("blocking", blockingMiddleware(done))
	}, 24*time.Hour)

	var wg sync.WaitGroup
	rec := httptest.NewRecorder()

	wg.Add(1)

	go func() {
		defer wg.Done()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	}()

	// Give the request time to enter the blocking middleware
	time.Sleep(20 * time.Millisecond)

	// Replace with immediate cancel
	p.ApplyWithTimeout(func(b *PipelineBuilder) {
		b.Reset()
		b.Set("new", headerMiddleware("X-New", "yes"))
	}, 0)

	wg.Wait()
	close(done)

	if got := rec.Header().Get("X-Cancelled"); got != "true" {
		t.Fatalf("expected X-Cancelled=true, got %q", got)
	}
}

func TestPipeline_ApplyWithTimeout_GracePeriod(t *testing.T) {
	p := NewPipeline()

	done := make(chan struct{})
	handler := p.Middleware()(http.HandlerFunc(okHandler))
	p.ApplyWithTimeout(func(b *PipelineBuilder) {
		b.Set("blocking", blockingMiddleware(done))
	}, 24*time.Hour)

	var wg sync.WaitGroup
	rec := httptest.NewRecorder()

	wg.Add(1)

	go func() {
		defer wg.Done()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	}()

	time.Sleep(20 * time.Millisecond)

	// Replace with 200ms grace
	p.ApplyWithTimeout(func(b *PipelineBuilder) {
		b.Reset()
	}, 200*time.Millisecond)

	// Let request finish naturally before grace
	close(done)
	wg.Wait()

	if got := rec.Header().Get("X-Cancelled"); got != "false" {
		t.Fatalf("expected X-Cancelled=false (finished before grace), got %q", got)
	}
}

// ── Shared registration tests ───────────────────────────────────────────────

func TestPipeline_SharedAcrossRegistrations(t *testing.T) {
	p := NewPipeline()
	p.Set("auth", headerMiddleware("X-Auth", "v1"))

	// Two independent registration points
	handler1 := p.Middleware()(http.HandlerFunc(okHandler))
	handler2 := p.Middleware()(http.HandlerFunc(okHandler))

	// Both see v1
	rec1 := httptest.NewRecorder()
	handler1.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/", nil))
	rec2 := httptest.NewRecorder()
	handler2.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec1.Header().Get("X-Auth") != "v1" || rec2.Header().Get("X-Auth") != "v1" {
		t.Fatal("both should see v1")
	}

	// Replace
	p.Set("auth", headerMiddleware("X-Auth", "v2"))

	// Both see v2
	rec1 = httptest.NewRecorder()
	handler1.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/", nil))
	rec2 = httptest.NewRecorder()
	handler2.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec1.Header().Get("X-Auth") != "v2" || rec2.Header().Get("X-Auth") != "v2" {
		t.Fatalf("both should see v2, got %q and %q",
			rec1.Header().Get("X-Auth"), rec2.Header().Get("X-Auth"))
	}
}

// ── Inspection tests ────────────────────────────────────────────────────────

func TestPipeline_Index(t *testing.T) {
	p := NewPipeline()
	p.Set("cors", NoOp())
	p.Set("auth", NoOp())
	p.Set("log", NoOp())

	if got := p.Index("cors"); got != 0 {
		t.Fatalf("expected index 0 for cors, got %d", got)
	}

	if got := p.Index("auth"); got != 1 {
		t.Fatalf("expected index 1 for auth, got %d", got)
	}

	if got := p.Index("log"); got != 2 {
		t.Fatalf("expected index 2 for log, got %d", got)
	}

	if got := p.Index("nonexistent"); got != -1 {
		t.Fatalf("expected -1 for nonexistent key, got %d", got)
	}
}

func TestPipeline_IndexOnNilSnapshot(t *testing.T) {
	p := &Pipeline{}
	if got := p.Index("anything"); got != -1 {
		t.Fatalf("expected -1 on nil snapshot, got %d", got)
	}
}

func TestPipeline_String(t *testing.T) {
	t.Run("empty pipeline", func(t *testing.T) {
		p := NewPipeline()
		got := p.String()
		if got != "Pipeline(empty)" {
			t.Fatalf("expected 'Pipeline(empty)', got %q", got)
		}
	})

	t.Run("nil snapshot", func(t *testing.T) {
		p := &Pipeline{}
		got := p.String()
		if got != "Pipeline(empty)" {
			t.Fatalf("expected 'Pipeline(empty)', got %q", got)
		}
	})

	t.Run("with entries", func(t *testing.T) {
		p := NewPipeline()
		p.Set("cors", NoOp())
		p.Set("auth", NoOp())
		p.Set("ratelimit", NoOp())

		got := p.String()
		expected := "Pipeline(3 middlewares):\n  [0] cors\n  [1] auth\n  [2] ratelimit"
		if got != expected {
			t.Fatalf("expected:\n%s\ngot:\n%s", expected, got)
		}
	})

	t.Run("single entry", func(t *testing.T) {
		p := NewPipeline()
		p.Set("auth", NoOp())

		got := p.String()
		expected := "Pipeline(1 middlewares):\n  [0] auth"
		if got != expected {
			t.Fatalf("expected:\n%s\ngot:\n%s", expected, got)
		}
	})
}

func TestPipeline_IndexAfterReorder(t *testing.T) {
	p := NewPipeline()
	p.Set("a", NoOp())
	p.Set("b", NoOp())
	p.Set("c", NoOp())

	// Move c to position 0
	p.SetAt(0, "c", NoOp())

	if got := p.Index("c"); got != 0 {
		t.Fatalf("expected c at index 0 after reorder, got %d", got)
	}

	if got := p.Index("a"); got != 1 {
		t.Fatalf("expected a at index 1 after reorder, got %d", got)
	}

	if got := p.Index("b"); got != 2 {
		t.Fatalf("expected b at index 2 after reorder, got %d", got)
	}
}

// ── Race tests ──────────────────────────────────────────────────────────────

func TestPipeline_SetRemoveWhileServing(t *testing.T) {
	p := NewPipeline()
	p.Set("counter", func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	})

	handler := p.Middleware()(http.HandlerFunc(okHandler))

	const goroutines = 50
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines + 1)

	// Readers
	for range goroutines {
		go func() {
			defer wg.Done()
			for range iterations {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
				if rec.Code != http.StatusOK {
					t.Errorf("expected 200, got %d", rec.Code)
				}
			}
		}()
	}

	// Writer: churn set/remove
	go func() {
		defer wg.Done()
		for i := range iterations {
			key := fmt.Sprintf("mw-%d", i%5)
			p.Set(key, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(w, r)
				})
			})
			p.Remove(key)
		}
	}()

	wg.Wait()
}

func TestPipeline_ApplyWhileServing(t *testing.T) {
	p := NewPipeline()
	var served atomic.Int64

	p.Set("counter", func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			served.Add(1)
			next.ServeHTTP(w, r)
		})
	})

	handler := p.Middleware()(http.HandlerFunc(okHandler))

	const goroutines = 30
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines + 1)

	// Readers
	for range goroutines {
		go func() {
			defer wg.Done()
			for range iterations {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			}
		}()
	}

	// Writer: Apply batch mutations
	go func() {
		defer wg.Done()
		for range iterations {
			p.Apply(func(b *PipelineBuilder) {
				b.Reset()
				b.Set("counter", func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						served.Add(1)
						next.ServeHTTP(w, r)
					})
				})
			})
		}
	}()

	wg.Wait()

	total := served.Load()
	expected := int64(goroutines * iterations)
	if total != expected {
		t.Fatalf("expected %d served, got %d", expected, total)
	}
}

// ── Order stability tests ───────────────────────────────────────────────────

func TestPipeline_OrderPreservedOnReplace(t *testing.T) {
	p := NewPipeline()
	handler := p.Middleware()(http.HandlerFunc(okHandler))

	p.Set("a", appendHeaderMiddleware("X-Order", "a"))
	p.Set("b", appendHeaderMiddleware("X-Order", "b"))
	p.Set("c", appendHeaderMiddleware("X-Order", "c"))

	// Replace b — order should be preserved
	p.Set("b", appendHeaderMiddleware("X-Order", "B"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	got := rec.Header().Get("X-Order")
	if got != "a,B,c" {
		t.Fatalf("expected a,B,c, got %q", got)
	}
}

func TestPipeline_RemovePreservesOtherOrder(t *testing.T) {
	p := NewPipeline()
	handler := p.Middleware()(http.HandlerFunc(okHandler))

	p.Set("a", appendHeaderMiddleware("X-Order", "a"))
	p.Set("b", appendHeaderMiddleware("X-Order", "b"))
	p.Set("c", appendHeaderMiddleware("X-Order", "c"))
	p.Set("d", appendHeaderMiddleware("X-Order", "d"))

	p.Remove("b")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	got := rec.Header().Get("X-Order")
	if got != "a,c,d" {
		t.Fatalf("expected a,c,d, got %q", got)
	}
}

func TestPipeline_AddAfterRemoveLosesPosition(t *testing.T) {
	p := NewPipeline()
	handler := p.Middleware()(http.HandlerFunc(okHandler))

	p.Set("a", appendHeaderMiddleware("X-Order", "a"))
	p.Set("b", appendHeaderMiddleware("X-Order", "b"))
	p.Set("c", appendHeaderMiddleware("X-Order", "c"))

	p.Remove("b")

	// Re-add b — it goes to the end
	p.Set("b", appendHeaderMiddleware("X-Order", "b"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	got := rec.Header().Get("X-Order")
	if got != "a,c,b" {
		t.Fatalf("expected a,c,b, got %q", got)
	}
}

func TestPipeline_ReAddAtOriginalPosition(t *testing.T) {
	p := NewPipeline()
	handler := p.Middleware()(http.HandlerFunc(okHandler))

	p.Set("a", appendHeaderMiddleware("X-Order", "a"))
	p.Set("b", appendHeaderMiddleware("X-Order", "b"))
	p.Set("c", appendHeaderMiddleware("X-Order", "c"))

	// Remove and re-add at position 1 via Apply
	p.Apply(func(b *PipelineBuilder) {
		b.Remove("b")
		b.SetAt(1, "b", appendHeaderMiddleware("X-Order", "b-new"))
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	got := rec.Header().Get("X-Order")
	if got != "a,b-new,c" {
		t.Fatalf("expected a,b-new,c, got %q", got)
	}
}

// ── Builder tests ───────────────────────────────────────────────────────────

func TestPipelineBuilder_SetAt(t *testing.T) {
	p := NewPipeline()

	p.Apply(func(b *PipelineBuilder) {
		b.Set("a", NoOp())
		b.Set("c", NoOp())
		b.SetAt(1, "b", NoOp())

		keys := b.Keys()
		if strings.Join(keys, ",") != "a,b,c" {
			t.Fatalf("expected a,b,c, got %s", strings.Join(keys, ","))
		}
	})
}

func TestPipelineBuilder_SetAtNil(t *testing.T) {
	p := NewPipeline()

	p.Apply(func(b *PipelineBuilder) {
		b.SetAt(0, "test", nil) // should not panic

		if b.Len() != 1 {
			t.Fatalf("expected len=1, got %d", b.Len())
		}
	})
}

func TestPipelineBuilder_Reset(t *testing.T) {
	p := NewPipeline()
	p.Set("a", NoOp())
	p.Set("b", NoOp())

	p.Apply(func(b *PipelineBuilder) {
		if b.Len() != 2 {
			t.Fatalf("expected len=2 before reset, got %d", b.Len())
		}

		b.Reset()

		if b.Len() != 0 {
			t.Fatalf("expected len=0 after reset, got %d", b.Len())
		}
	})

	if p.Len() != 0 {
		t.Fatalf("pipeline should be empty after Apply with reset, got len=%d", p.Len())
	}
}

func TestPipelineBuilder_RemoveNonexistent(t *testing.T) {
	p := NewPipeline()

	p.Apply(func(b *PipelineBuilder) {
		if b.Remove("nope") {
			t.Fatal("Remove should return false for nonexistent key")
		}
	})
}

func TestPipelineBuilder_SetMovesExisting(t *testing.T) {
	p := NewPipeline()

	p.Apply(func(b *PipelineBuilder) {
		b.Set("a", NoOp())
		b.Set("b", NoOp())
		b.Set("c", NoOp())

		// Move c to position 0
		b.SetAt(0, "c", NoOp())

		keys := b.Keys()
		if strings.Join(keys, ",") != "c,a,b" {
			t.Fatalf("expected c,a,b, got %s", strings.Join(keys, ","))
		}
	})
}
