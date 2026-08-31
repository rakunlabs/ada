package ada

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"
)

type reloadGCProbe [1024]byte

type reloadNextHandler struct {
	body string
}

func (h *reloadNextHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte(h.body))
}

func waitForReloadGC(t *testing.T, ref weak.Pointer[reloadGCProbe]) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if ref.Value() == nil {
			return
		}

		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("object remained reachable after repeated garbage collections")
}

func abandonedReloadRegistration(mw MiddlewareFunc) weak.Pointer[reloadGCProbe] {
	probe := new(reloadGCProbe)
	ref := weak.Make(probe)
	handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		runtime.KeepAlive(probe)
	}))

	runtime.KeepAlive(handler)
	runtime.KeepAlive(probe)

	return ref
}

func probeMiddleware() (MiddlewareFunc, weak.Pointer[reloadGCProbe]) {
	probe := new(reloadGCProbe)
	ref := weak.Make(probe)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			runtime.KeepAlive(probe)
			next.ServeHTTP(w, r)
		})
	}, ref
}

func requireReloadPanic(t *testing.T, fn func()) {
	t.Helper()

	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()

		fn()
	}()

	if !panicked {
		t.Fatal("expected panic")
	}
}

func requireReloadCompletion(t *testing.T, fn func()) {
	t.Helper()

	result := make(chan any, 1)
	go func() {
		defer func() {
			result <- recover()
		}()
		fn()
	}()

	select {
	case recovered := <-result:
		if recovered != nil {
			t.Fatalf("operation panicked: %v", recovered)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("operation deadlocked")
	}
}

func waitForReloadCondition(t *testing.T, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("reload condition was not reached")
		}
		runtime.Gosched()
	}
}

func TestSlotRegistrationTargetCanBeCollected(t *testing.T) {
	slot := NewSlot(NoOp())
	ref := abandonedReloadRegistration(slot.Middleware())

	waitForReloadGC(t, ref)

	// A later mutation also compacts the dead weak registry entry.
	slot.Replace(NoOp())
	if len(slot.targets) != 0 {
		t.Fatalf("expected dead target to be compacted, got %d entries", len(slot.targets))
	}
}

func TestPipelineRegistrationTargetCanBeCollected(t *testing.T) {
	pipeline := NewPipeline()
	ref := abandonedReloadRegistration(pipeline.Middleware())

	waitForReloadGC(t, ref)

	pipeline.Set("live", NoOp())
	if len(pipeline.targets) != 0 {
		t.Fatalf("expected dead target to be compacted, got %d entries", len(pipeline.targets))
	}
}

func TestSlotReplaceReleasesObsoleteMiddleware(t *testing.T) {
	mw, ref := probeMiddleware()
	slot := NewSlot(mw)
	handler := slot.Middleware()(http.HandlerFunc(okHandler))

	slot.Replace(NoOp())
	waitForReloadGC(t, ref)

	runtime.KeepAlive(slot)
	runtime.KeepAlive(handler)
}

func TestPipelineRemoveReleasesObsoleteMiddleware(t *testing.T) {
	mw, ref := probeMiddleware()
	pipeline := NewPipeline()
	pipeline.Set("probe", mw)
	handler := pipeline.Middleware()(http.HandlerFunc(okHandler))

	if !pipeline.Remove("probe") {
		t.Fatal("expected probe middleware to be removed")
	}
	waitForReloadGC(t, ref)

	runtime.KeepAlive(pipeline)
	runtime.KeepAlive(handler)
}

func TestSlotReentrantConstructors(t *testing.T) {
	t.Run("registration", func(t *testing.T) {
		slot := NewSlot(nil)
		slot.Replace(func(next http.Handler) http.Handler {
			slot.Disable()
			return tagMiddleware("stale")(next)
		})

		var handler http.Handler
		requireReloadCompletion(t, func() {
			handler = slot.Middleware()(http.HandlerFunc(okHandler))
		})

		if slot.Enabled() {
			t.Fatal("reentrant Disable should remain active")
		}
		if got := hit(func(http.Handler) http.Handler { return handler }); got != "" {
			t.Fatalf("disabled handler produced %q", got)
		}
	})

	t.Run("mutation", func(t *testing.T) {
		slot := NewSlot(NoOp())
		handler := slot.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("next"))
		}))
		var outerCalls atomic.Int32
		var innerCalls atomic.Int32
		inner := func(next http.Handler) http.Handler {
			innerCalls.Add(1)

			return tagMiddleware("inner")(next)
		}

		requireReloadCompletion(t, func() {
			slot.Replace(func(next http.Handler) http.Handler {
				outerCalls.Add(1)
				slot.Replace(inner)

				return tagMiddleware("outer")(next)
			})
		})

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if got := rec.Body.String(); got != "innernext" {
			t.Fatalf("body = %q, want %q", got, "innernext")
		}
		if outerCalls.Load() != 1 || innerCalls.Load() != 1 {
			t.Fatalf("constructor calls = outer %d, inner %d; want 1 each", outerCalls.Load(), innerCalls.Load())
		}
	})
}

func TestPipelineReentrantConstructors(t *testing.T) {
	t.Run("registration", func(t *testing.T) {
		pipeline := NewPipeline()
		pipeline.Set("remove-self", func(next http.Handler) http.Handler {
			pipeline.Remove("remove-self")
			return tagMiddleware("stale")(next)
		})

		var handler http.Handler
		requireReloadCompletion(t, func() {
			handler = pipeline.Middleware()(http.HandlerFunc(okHandler))
		})

		if pipeline.Len() != 0 {
			t.Fatalf("pipeline len = %d, want 0", pipeline.Len())
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("mutation", func(t *testing.T) {
		pipeline := NewPipeline()
		handler := pipeline.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("next"))
		}))
		var outerCalls atomic.Int32
		var innerCalls atomic.Int32
		inner := func(next http.Handler) http.Handler {
			innerCalls.Add(1)

			return tagMiddleware("inner")(next)
		}

		requireReloadCompletion(t, func() {
			pipeline.Set("current", func(next http.Handler) http.Handler {
				outerCalls.Add(1)
				pipeline.Set("current", inner)

				return tagMiddleware("outer")(next)
			})
		})

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if got := rec.Body.String(); got != "innernext" {
			t.Fatalf("body = %q, want %q", got, "innernext")
		}
		if outerCalls.Load() != 1 || innerCalls.Load() != 1 {
			t.Fatalf("constructor calls = outer %d, inner %d; want 1 each", outerCalls.Load(), innerCalls.Load())
		}
	})
}

func TestSlotConstructorPanicIsTransactional(t *testing.T) {
	slot := NewSlot(tagMiddleware("old"))
	handler1 := slot.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("next"))
	}))
	handler2 := slot.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("next"))
	}))

	requireReloadPanic(t, func() {
		slot.Replace(func(http.Handler) http.Handler {
			panic("slot constructor")
		})
	})

	for i, handler := range []http.Handler{handler1, handler2} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if got := rec.Body.String(); got != "oldnext" {
			t.Fatalf("handler %d body = %q, want %q", i, got, "oldnext")
		}
	}

	slot.Replace(tagMiddleware("new"))
	rec := httptest.NewRecorder()
	handler1.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Body.String(); got != "newnext" {
		t.Fatalf("body after recovery = %q, want %q", got, "newnext")
	}
}

func TestRegistrationConstructorPanicLeavesLocksUsable(t *testing.T) {
	t.Run("slot", func(t *testing.T) {
		slot := NewSlot(func(http.Handler) http.Handler {
			panic("slot registration")
		})
		requireReloadPanic(t, func() {
			slot.Middleware()(http.HandlerFunc(okHandler))
		})

		slot.Replace(NoOp())
		handler := slot.Middleware()(http.HandlerFunc(okHandler))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("pipeline", func(t *testing.T) {
		pipeline := NewPipeline()
		pipeline.Set("panic", func(http.Handler) http.Handler {
			panic("pipeline registration")
		})
		requireReloadPanic(t, func() {
			pipeline.Middleware()(http.HandlerFunc(okHandler))
		})

		pipeline.Remove("panic")
		pipeline.Set("live", NoOp())
		handler := pipeline.Middleware()(http.HandlerFunc(okHandler))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})
}

func TestPipelineConstructorPanicIsTransactional(t *testing.T) {
	pipeline := NewPipeline()
	pipeline.Set("old", tagMiddleware("old"))
	handler1 := pipeline.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("next"))
	}))
	handler2 := pipeline.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("next"))
	}))

	requireReloadPanic(t, func() {
		pipeline.Set("panic", func(http.Handler) http.Handler {
			panic("pipeline constructor")
		})
	})

	if pipeline.Has("panic") {
		t.Fatal("panicking middleware was published")
	}
	for i, handler := range []http.Handler{handler1, handler2} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if got := rec.Body.String(); got != "oldnext" {
			t.Fatalf("handler %d body = %q, want %q", i, got, "oldnext")
		}
	}

	pipeline.Set("new", tagMiddleware("new"))
	rec := httptest.NewRecorder()
	handler1.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Body.String(); got != "oldnewnext" {
		t.Fatalf("body after recovery = %q, want %q", got, "oldnewnext")
	}
}

func TestPipelineApplyCallbackPanicIsTransactional(t *testing.T) {
	tests := []struct {
		name  string
		apply func(*Pipeline, func(*PipelineBuilder))
	}{
		{name: "Apply", apply: func(p *Pipeline, fn func(*PipelineBuilder)) { p.Apply(fn) }},
		{name: "ApplyWithTimeout", apply: func(p *Pipeline, fn func(*PipelineBuilder)) {
			p.ApplyWithTimeout(fn, 0)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := NewPipeline()
			pipeline.Set("old", tagMiddleware("old"))
			handler := pipeline.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("next"))
			}))
			before := pipeline.snapshot.Load()

			requireReloadPanic(t, func() {
				tt.apply(pipeline, func(b *PipelineBuilder) {
					b.Reset()
					b.Set("new", tagMiddleware("new"))
					panic("apply callback")
				})
			})

			if after := pipeline.snapshot.Load(); after != before {
				t.Fatal("callback panic changed the active snapshot")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if got := rec.Body.String(); got != "oldnext" {
				t.Fatalf("body = %q, want %q", got, "oldnext")
			}

			pipeline.Set("after", NoOp())
			if !pipeline.Has("after") {
				t.Fatal("pipeline lock was unusable after callback panic")
			}
		})
	}
}

func TestPipelineApplyCallbackRunsOnceWhenReentrant(t *testing.T) {
	tests := []struct {
		name  string
		apply func(*Pipeline, func(*PipelineBuilder))
	}{
		{name: "Apply", apply: func(p *Pipeline, fn func(*PipelineBuilder)) { p.Apply(fn) }},
		{name: "ApplyWithTimeout", apply: func(p *Pipeline, fn func(*PipelineBuilder)) {
			p.ApplyWithTimeout(fn, 0)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipeline := NewPipeline()
			handler := pipeline.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("next"))
			}))
			calls := 0

			requireReloadCompletion(t, func() {
				tt.apply(pipeline, func(b *PipelineBuilder) {
					calls++
					pipeline.Set("inner", tagMiddleware("inner"))
					b.Set("outer", tagMiddleware("outer"))
				})
			})

			if calls != 1 {
				t.Fatalf("callback calls = %d, want 1", calls)
			}
			if got := strings.Join(pipeline.Keys(), ","); got != "outer,inner" {
				t.Fatalf("keys = %q, want %q", got, "outer,inner")
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if got := rec.Body.String(); got != "outerinnernext" {
				t.Fatalf("body = %q, want %q", got, "outerinnernext")
			}
		})
	}
}

func TestTimeoutConstructorPanicKeepsPriorGeneration(t *testing.T) {
	t.Run("slot", func(t *testing.T) {
		slot := NewSlot(NoOp())
		handler := slot.Middleware()(http.HandlerFunc(okHandler))
		slot.ReplaceWithTimeout(NoOp(), 0)
		before := slot.state.Load()

		requireReloadPanic(t, func() {
			slot.ReplaceWithTimeout(func(http.Handler) http.Handler {
				panic("slot timeout constructor")
			}, 0)
		})

		if after := slot.state.Load(); after != before {
			t.Fatal("constructor panic changed the active Slot generation")
		}
		select {
		case <-before.ctx.Done():
			t.Fatal("constructor panic cancelled the prior Slot generation")
		default:
		}

		slot.ReplaceWithTimeout(NoOp(), 0)
		runtime.KeepAlive(handler)
	})

	t.Run("pipeline", func(t *testing.T) {
		pipeline := NewPipeline()
		handler := pipeline.Middleware()(http.HandlerFunc(okHandler))
		pipeline.ApplyWithTimeout(func(b *PipelineBuilder) {
			b.Set("old", NoOp())
		}, 0)
		before := pipeline.snapshot.Load()

		requireReloadPanic(t, func() {
			pipeline.ApplyWithTimeout(func(b *PipelineBuilder) {
				b.Set("panic", func(http.Handler) http.Handler {
					panic("pipeline timeout constructor")
				})
			}, 0)
		})

		if after := pipeline.snapshot.Load(); after != before {
			t.Fatal("constructor panic changed the active Pipeline generation")
		}
		select {
		case <-before.ctx.Done():
			t.Fatal("constructor panic cancelled the prior Pipeline generation")
		default:
		}

		pipeline.ApplyWithTimeout(func(b *PipelineBuilder) { b.Reset() }, 0)
		runtime.KeepAlive(handler)
	})
}

func TestPipelineConcurrentDistinctMutationsArePreserved(t *testing.T) {
	pipeline := NewPipeline()
	handler := pipeline.Middleware()(http.HandlerFunc(okHandler))

	const mutations = 24
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(mutations)

	for i := range mutations {
		go func() {
			defer wg.Done()
			<-start

			key := "X-Mutation-" + strconv.Itoa(i)
			pipeline.Set(key, headerMiddleware(key, "present"))
		}()
	}

	close(start)
	wg.Wait()

	if got := pipeline.Len(); got != mutations {
		t.Fatalf("pipeline len = %d, want %d", got, mutations)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	for i := range mutations {
		key := "X-Mutation-" + strconv.Itoa(i)
		if got := rec.Header().Get(key); got != "present" {
			t.Fatalf("header %s = %q, want %q", key, got, "present")
		}
	}
}

func TestRegistrationEnrollsAtItsFIFOPosition(t *testing.T) {
	t.Run("Slot", func(t *testing.T) {
		slot := NewSlot(NoOp())
		oldNext := &reloadNextHandler{body: "old"}
		newNext := &reloadNextHandler{body: "new"}
		oldHandler := slot.Middleware()(oldNext)
		entered := make(chan struct{})
		release := make(chan struct{})
		ownerDone := make(chan any, 1)
		go func() {
			defer func() { ownerDone <- recover() }()
			slot.Replace(func(next http.Handler) http.Handler {
				close(entered)
				<-release

				return next
			})
		}()
		<-entered

		var oldCalls atomic.Int32
		var newCalls atomic.Int32
		slot.Replace(func(next http.Handler) http.Handler {
			if next == newNext {
				newCalls.Add(1)
			} else {
				oldCalls.Add(1)
			}

			return tagMiddleware("B")(next)
		})
		newHandler := slot.Middleware()(newNext)
		if newCalls.Load() != 0 {
			t.Fatal("deferred registration was constructed before its FIFO task")
		}

		close(release)
		if recovered := <-ownerDone; recovered != nil {
			t.Fatalf("queue owner panicked: %v", recovered)
		}
		if oldCalls.Load() != 1 || newCalls.Load() != 1 {
			t.Fatalf("B constructor calls = old target %d, new target %d; want 1 each", oldCalls.Load(), newCalls.Load())
		}
		if got := hit(func(http.Handler) http.Handler { return newHandler }); got != "Bnew" {
			t.Fatalf("new registration body = %q, want %q", got, "Bnew")
		}
		runtime.KeepAlive(oldHandler)
	})

	t.Run("Pipeline", func(t *testing.T) {
		pipeline := NewPipeline()
		oldNext := &reloadNextHandler{body: "old"}
		newNext := &reloadNextHandler{body: "new"}
		oldHandler := pipeline.Middleware()(oldNext)
		entered := make(chan struct{})
		release := make(chan struct{})
		ownerDone := make(chan any, 1)
		go func() {
			defer func() { ownerDone <- recover() }()
			pipeline.Set("current", func(next http.Handler) http.Handler {
				close(entered)
				<-release

				return next
			})
		}()
		<-entered

		var oldCalls atomic.Int32
		var newCalls atomic.Int32
		pipeline.Set("current", func(next http.Handler) http.Handler {
			if next == newNext {
				newCalls.Add(1)
			} else {
				oldCalls.Add(1)
			}

			return tagMiddleware("B")(next)
		})
		newHandler := pipeline.Middleware()(newNext)
		if newCalls.Load() != 0 {
			t.Fatal("deferred registration was constructed before its FIFO task")
		}

		close(release)
		if recovered := <-ownerDone; recovered != nil {
			t.Fatalf("queue owner panicked: %v", recovered)
		}
		if oldCalls.Load() != 1 || newCalls.Load() != 1 {
			t.Fatalf("B constructor calls = old target %d, new target %d; want 1 each", oldCalls.Load(), newCalls.Load())
		}
		if got := hit(func(http.Handler) http.Handler { return newHandler }); got != "Bnew" {
			t.Fatalf("new registration body = %q, want %q", got, "Bnew")
		}
		runtime.KeepAlive(oldHandler)
	})
}

func TestReloadQueueAppliesBackpressure(t *testing.T) {
	t.Run("Slot", func(t *testing.T) {
		slot := NewSlot(NoOp())
		handler := slot.Middleware()(http.HandlerFunc(okHandler))
		entered := make(chan struct{})
		release := make(chan struct{})
		ownerDone := make(chan any, 1)
		go func() {
			defer func() { ownerDone <- recover() }()
			slot.Replace(func(next http.Handler) http.Handler {
				close(entered)
				<-release

				return next
			})
		}()
		<-entered
		for range reloadTaskQueueLimit {
			slot.Replace(NoOp())
		}

		extraDone := make(chan struct{})
		go func() {
			defer close(extraDone)
			slot.Replace(NoOp())
		}()
		waitForReloadCondition(t, func() bool {
			slot.mu.Lock()
			defer slot.mu.Unlock()

			return len(slot.tasks) == reloadTaskQueueLimit && slot.taskWaiters == 1
		})
		select {
		case <-extraDone:
			t.Fatal("submission above the queue bound did not block")
		default:
		}

		close(release)
		if recovered := <-ownerDone; recovered != nil {
			t.Fatalf("queue owner panicked: %v", recovered)
		}
		<-extraDone
		slot.mu.Lock()
		queued, processing := len(slot.tasks), slot.processing
		slot.mu.Unlock()
		if queued != 0 || processing {
			t.Fatalf("queue did not drain: queued=%d processing=%v", queued, processing)
		}
		runtime.KeepAlive(handler)
	})

	t.Run("Pipeline", func(t *testing.T) {
		pipeline := NewPipeline()
		handler := pipeline.Middleware()(http.HandlerFunc(okHandler))
		entered := make(chan struct{})
		release := make(chan struct{})
		ownerDone := make(chan any, 1)
		go func() {
			defer func() { ownerDone <- recover() }()
			pipeline.Set("current", func(next http.Handler) http.Handler {
				close(entered)
				<-release

				return next
			})
		}()
		<-entered
		for range reloadTaskQueueLimit {
			pipeline.Set("current", NoOp())
		}

		extraDone := make(chan struct{})
		go func() {
			defer close(extraDone)
			pipeline.Set("current", NoOp())
		}()
		waitForReloadCondition(t, func() bool {
			pipeline.mu.Lock()
			defer pipeline.mu.Unlock()

			return len(pipeline.tasks) == reloadTaskQueueLimit && pipeline.taskWaiters == 1
		})
		select {
		case <-extraDone:
			t.Fatal("submission above the queue bound did not block")
		default:
		}

		close(release)
		if recovered := <-ownerDone; recovered != nil {
			t.Fatalf("queue owner panicked: %v", recovered)
		}
		<-extraDone
		pipeline.mu.Lock()
		queued, processing := len(pipeline.tasks), pipeline.processing
		pipeline.mu.Unlock()
		if queued != 0 || processing {
			t.Fatalf("queue did not drain: queued=%d processing=%v", queued, processing)
		}
		runtime.KeepAlive(handler)
	})
}

func TestReloadQueueRecoversAfterGoexit(t *testing.T) {
	t.Run("Slot", func(t *testing.T) {
		slot := NewSlot(tagMiddleware("old"))
		handler := slot.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("next"))
		}))
		var goexitCalls atomic.Int32
		var bCalls atomic.Int32
		var cCalls atomic.Int32
		ownerDone := make(chan struct{})
		go func() {
			defer close(ownerDone)
			slot.Replace(func(http.Handler) http.Handler {
				goexitCalls.Add(1)
				slot.Replace(func(next http.Handler) http.Handler {
					bCalls.Add(1)

					return tagMiddleware("B")(next)
				})
				runtime.Goexit()

				return nil
			})
		}()
		<-ownerDone

		slot.Replace(func(next http.Handler) http.Handler {
			cCalls.Add(1)

			return tagMiddleware("C")(next)
		})
		if got := hit(func(http.Handler) http.Handler { return handler }); got != "Cnext" {
			t.Fatalf("active body = %q, want %q", got, "Cnext")
		}
		if goexitCalls.Load() != 1 || bCalls.Load() != 1 || cCalls.Load() != 1 {
			t.Fatalf("constructor calls = Goexit %d, B %d, C %d; want 1 each", goexitCalls.Load(), bCalls.Load(), cCalls.Load())
		}
	})

	t.Run("Pipeline", func(t *testing.T) {
		pipeline := NewPipeline()
		pipeline.Set("current", tagMiddleware("old"))
		handler := pipeline.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("next"))
		}))
		var goexitCalls atomic.Int32
		var bCalls atomic.Int32
		var cCalls atomic.Int32
		ownerDone := make(chan struct{})
		go func() {
			defer close(ownerDone)
			pipeline.Set("current", func(http.Handler) http.Handler {
				goexitCalls.Add(1)
				pipeline.Set("current", func(next http.Handler) http.Handler {
					bCalls.Add(1)

					return tagMiddleware("B")(next)
				})
				runtime.Goexit()

				return nil
			})
		}()
		<-ownerDone

		pipeline.Set("current", func(next http.Handler) http.Handler {
			cCalls.Add(1)

			return tagMiddleware("C")(next)
		})
		if got := hit(func(http.Handler) http.Handler { return handler }); got != "Cnext" {
			t.Fatalf("active body = %q, want %q", got, "Cnext")
		}
		if goexitCalls.Load() != 1 || bCalls.Load() != 1 || cCalls.Load() != 1 {
			t.Fatalf("constructor calls = Goexit %d, B %d, C %d; want 1 each", goexitCalls.Load(), bCalls.Load(), cCalls.Load())
		}
	})
}

func TestSlotFailedReplaceDoesNotTaintDependentMutation(t *testing.T) {
	for _, dependent := range []string{"Disable", "Enable"} {
		t.Run(dependent, func(t *testing.T) {
			slot := NewSlot(tagMiddleware("old"))
			handler := slot.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("next"))
			}))
			if dependent == "Enable" {
				slot.Disable()
			}

			var calls atomic.Int32
			requireReloadPanic(t, func() {
				slot.Replace(func(http.Handler) http.Handler {
					calls.Add(1)
					if dependent == "Disable" {
						slot.Disable()
					} else {
						slot.Enable()
					}

					panic("failed replacement")
				})
			})

			if dependent == "Disable" {
				if slot.Enabled() {
					t.Fatal("queued Disable was not applied")
				}
				slot.Enable()
			} else if !slot.Enabled() {
				t.Fatal("queued Enable was not applied")
			}
			if got := hit(func(http.Handler) http.Handler { return handler }); got != "oldnext" {
				t.Fatalf("active body = %q, want %q", got, "oldnext")
			}
			if calls.Load() != 1 {
				t.Fatalf("failed constructor calls = %d, want 1", calls.Load())
			}
		})
	}
}

func TestPipelineDistinctKeyReentrantMutationIsQueued(t *testing.T) {
	pipeline := NewPipeline()
	handler := pipeline.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("next"))
	}))

	var once sync.Once
	var outerCalls atomic.Int32
	var innerCalls atomic.Int32
	var active atomic.Int32
	var overlap atomic.Bool
	outer := func(next http.Handler) http.Handler {
		outerCalls.Add(1)
		if active.Add(1) != 1 {
			overlap.Store(true)
		}
		defer active.Add(-1)
		once.Do(func() {
			pipeline.Set("inner", func(next http.Handler) http.Handler {
				innerCalls.Add(1)

				return tagMiddleware("inner")(next)
			})
		})

		return tagMiddleware("outer")(next)
	}

	requireReloadCompletion(t, func() { pipeline.Set("outer", outer) })
	if got := strings.Join(pipeline.Keys(), ","); got != "outer,inner" {
		t.Fatalf("keys = %q, want %q", got, "outer,inner")
	}
	if got := hit(func(http.Handler) http.Handler { return handler }); got != "outerinnernext" {
		t.Fatalf("active body = %q, want %q", got, "outerinnernext")
	}
	if overlap.Load() {
		t.Fatal("outer constructor was invoked concurrently")
	}
	if outerCalls.Load() != 2 || innerCalls.Load() != 1 {
		t.Fatalf("constructor calls = outer %d, inner %d; want 2 and 1", outerCalls.Load(), innerCalls.Load())
	}
}

func TestMiddlewareRegistrationFromConstructorIsDeferred(t *testing.T) {
	t.Run("Slot", func(t *testing.T) {
		slot := NewSlot(NoOp())
		handler := slot.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("next"))
		}))
		var once sync.Once
		var calls atomic.Int32
		var nested http.Handler
		var during string
		outer := func(next http.Handler) http.Handler {
			calls.Add(1)
			once.Do(func() {
				nested = slot.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte("next"))
				}))
				during = hit(func(http.Handler) http.Handler { return nested })
			})

			return tagMiddleware("slot")(next)
		}

		requireReloadCompletion(t, func() { slot.Replace(outer) })
		if during != "next" {
			t.Fatalf("deferred registration body = %q, want pass-through %q", during, "next")
		}
		for _, current := range []http.Handler{handler, nested} {
			if got := hit(func(http.Handler) http.Handler { return current }); got != "slotnext" {
				t.Fatalf("active body = %q, want %q", got, "slotnext")
			}
		}
		if calls.Load() != 2 {
			t.Fatalf("constructor calls = %d, want 2 registrations", calls.Load())
		}
	})

	t.Run("Pipeline", func(t *testing.T) {
		pipeline := NewPipeline()
		handler := pipeline.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("next"))
		}))
		var once sync.Once
		var calls atomic.Int32
		var nested http.Handler
		var during string
		outer := func(next http.Handler) http.Handler {
			calls.Add(1)
			once.Do(func() {
				nested = pipeline.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte("next"))
				}))
				during = hit(func(http.Handler) http.Handler { return nested })
			})

			return tagMiddleware("pipeline")(next)
		}

		requireReloadCompletion(t, func() { pipeline.Set("current", outer) })
		if during != "next" {
			t.Fatalf("deferred registration body = %q, want pass-through %q", during, "next")
		}
		for _, current := range []http.Handler{handler, nested} {
			if got := hit(func(http.Handler) http.Handler { return current }); got != "pipelinenext" {
				t.Fatalf("active body = %q, want %q", got, "pipelinenext")
			}
		}
		if calls.Load() != 2 {
			t.Fatalf("constructor calls = %d, want 2 registrations", calls.Load())
		}
	})
}

func TestPipelineQueuedPanicSkipsFailedSnapshotAndContinues(t *testing.T) {
	pipeline := NewPipeline()
	handler := pipeline.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("next"))
	}))

	var once sync.Once
	var aCalls atomic.Int32
	var bCalls atomic.Int32
	var cCalls atomic.Int32
	a := func(next http.Handler) http.Handler {
		aCalls.Add(1)
		once.Do(func() {
			pipeline.Set("B", func(http.Handler) http.Handler {
				bCalls.Add(1)

				panic("B constructor")
			})
			pipeline.Set("C", func(next http.Handler) http.Handler {
				cCalls.Add(1)

				return tagMiddleware("C")(next)
			})
		})

		return tagMiddleware("A")(next)
	}

	requireReloadPanic(t, func() { pipeline.Set("A", a) })
	if got := strings.Join(pipeline.Keys(), ","); got != "A,C" {
		t.Fatalf("keys = %q, want %q", got, "A,C")
	}
	if got := hit(func(http.Handler) http.Handler { return handler }); got != "ACnext" {
		t.Fatalf("active body = %q, want %q", got, "ACnext")
	}
	if aCalls.Load() != 2 || bCalls.Load() != 1 || cCalls.Load() != 1 {
		t.Fatalf("constructor calls = A %d, B %d, C %d; want 2, 1, 1", aCalls.Load(), bCalls.Load(), cCalls.Load())
	}
}

func TestQueuedApplyWithTimeoutKeepsCancellationObligation(t *testing.T) {
	pipeline := NewPipeline()
	handler := pipeline.Middleware()(http.HandlerFunc(okHandler))
	entered := make(chan struct{})
	pipeline.ApplyWithTimeout(func(b *PipelineBuilder) {
		b.Set("old", func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-r.Context().Done()
				w.Header().Set("X-Cancelled", "true")
			})
		})
	}, 24*time.Hour)
	oldSnapshot := pipeline.snapshot.Load()

	rec := httptest.NewRecorder()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not enter old generation")
	}

	var once sync.Once
	var calls atomic.Int32
	timeoutMiddleware := func(next http.Handler) http.Handler {
		calls.Add(1)
		once.Do(func() { pipeline.Set("regular", NoOp()) })

		return next
	}
	pipeline.ApplyWithTimeout(func(b *PipelineBuilder) {
		b.Reset()
		b.Set("timeout", timeoutMiddleware)
	}, 0)

	select {
	case <-requestDone:
	case <-time.After(2 * time.Second):
		t.Fatal("old generation was not cancelled")
	}
	if rec.Header().Get("X-Cancelled") != "true" {
		t.Fatal("old request did not observe timeout cancellation")
	}
	select {
	case <-oldSnapshot.ctx.Done():
	default:
		t.Fatal("old generation context remains live")
	}
	if got := strings.Join(pipeline.Keys(), ","); got != "timeout,regular" {
		t.Fatalf("keys = %q, want %q", got, "timeout,regular")
	}
	if pipeline.snapshot.Load().ctx != nil {
		t.Fatal("regular successor unexpectedly retained timeout context")
	}
	if calls.Load() != 2 {
		t.Fatalf("timeout constructor calls = %d, want 2 serial generations", calls.Load())
	}
}

func TestConditionalApplyIsSerializedInQueueOrder(t *testing.T) {
	pipeline := NewPipeline()
	handler := pipeline.Middleware()(http.HandlerFunc(okHandler))
	var once sync.Once
	var callbackCalls atomic.Int32
	var outerCalls atomic.Int32
	outer := func(next http.Handler) http.Handler {
		outerCalls.Add(1)
		once.Do(func() {
			pipeline.Set("x", NoOp())
			pipeline.Apply(func(b *PipelineBuilder) {
				callbackCalls.Add(1)
				if b.Has("x") {
					b.Remove("x")
					b.Set("seen", NoOp())
				} else {
					b.Set("wrong", NoOp())
				}
			})
		})

		return next
	}

	pipeline.Set("outer", outer)
	if got := strings.Join(pipeline.Keys(), ","); got != "outer,seen" {
		t.Fatalf("keys = %q, want %q", got, "outer,seen")
	}
	if pipeline.Has("x") || pipeline.Has("wrong") {
		t.Fatal("conditional Apply did not observe its immediate predecessor")
	}
	if callbackCalls.Load() != 1 {
		t.Fatalf("Apply callback calls = %d, want 1", callbackCalls.Load())
	}
	if outerCalls.Load() != 3 {
		t.Fatalf("outer constructor calls = %d, want one per serial generation", outerCalls.Load())
	}
	runtime.KeepAlive(handler)
}

func TestSlowConcurrentConstructorsAreQueued(t *testing.T) {
	t.Run("Slot", func(t *testing.T) {
		slot := NewSlot(NoOp())
		handler := slot.Middleware()(http.HandlerFunc(okHandler))

		testSlowDistinctConstructors(t, func(mw MiddlewareFunc) {
			slot.Replace(mw)
		})
		runtime.KeepAlive(handler)
	})

	t.Run("Pipeline", func(t *testing.T) {
		pipeline := NewPipeline()
		handler := pipeline.Middleware()(http.HandlerFunc(okHandler))

		testSlowDistinctConstructors(t, func(mw MiddlewareFunc) {
			pipeline.Set("current", mw)
		})
		runtime.KeepAlive(handler)
	})
}

func testSlowDistinctConstructors(t *testing.T, replace func(MiddlewareFunc)) {
	t.Helper()

	var calls [2]atomic.Int32
	var active atomic.Int32
	var overlap atomic.Bool

	factory := func(index int) MiddlewareFunc {
		return func(next http.Handler) http.Handler {
			calls[index].Add(1)
			if active.Add(1) != 1 {
				overlap.Store(true)
			}
			time.Sleep(150 * time.Millisecond)
			active.Add(-1)

			return next
		}
	}

	runConcurrentReloads(t, 2, func(i int) { replace(factory(i)) })
	if overlap.Load() {
		t.Fatal("constructors overlapped instead of being queued")
	}
	for i := range calls {
		if got := calls[i].Load(); got != 1 {
			t.Fatalf("constructor %d calls = %d, want 1", i, got)
		}
	}
}

func TestConcurrentReplacementConstructorsRunOnce(t *testing.T) {
	const replacements = 24

	t.Run("Slot", func(t *testing.T) {
		slot := NewSlot(NoOp())
		handler := slot.Middleware()(http.HandlerFunc(okHandler))
		calls := make([]atomic.Int32, replacements)

		runConcurrentReloads(t, replacements, func(i int) {
			slot.Replace(func(next http.Handler) http.Handler {
				calls[i].Add(1)
				runtime.Gosched()

				return next
			})
		})
		for i := range calls {
			if got := calls[i].Load(); got != 1 {
				t.Fatalf("constructor %d calls = %d, want 1", i, got)
			}
		}
		runtime.KeepAlive(handler)
	})

	t.Run("Pipeline", func(t *testing.T) {
		pipeline := NewPipeline()
		handler := pipeline.Middleware()(http.HandlerFunc(okHandler))
		calls := make([]atomic.Int32, replacements)

		runConcurrentReloads(t, replacements, func(i int) {
			pipeline.Set("current", func(next http.Handler) http.Handler {
				calls[i].Add(1)
				runtime.Gosched()

				return next
			})
		})
		for i := range calls {
			if got := calls[i].Load(); got != 1 {
				t.Fatalf("constructor %d calls = %d, want 1", i, got)
			}
		}
		runtime.KeepAlive(handler)
	})
}

func runConcurrentReloads(t *testing.T, count int, fn func(int)) {
	t.Helper()

	start := make(chan struct{})
	panics := make(chan any, count)
	var wg sync.WaitGroup
	wg.Add(count)
	for i := range count {
		go func() {
			defer wg.Done()
			defer func() { panics <- recover() }()
			<-start
			fn(i)
		}()
	}
	close(start)
	wg.Wait()
	close(panics)

	for recovered := range panics {
		if recovered != nil {
			t.Fatalf("concurrent reload panicked: %v", recovered)
		}
	}
}

func TestRegistrationCompactionUsesGeometricThresholds(t *testing.T) {
	t.Run("Slot", func(t *testing.T) {
		slot := NewSlot(NoOp())
		handlers := make([]http.Handler, 0, 32)
		for range 16 {
			handlers = append(handlers, slot.Middleware()(http.HandlerFunc(okHandler)))
		}
		if slot.compactAt != 32 {
			t.Fatalf("compactAt after 16 registrations = %d, want 32", slot.compactAt)
		}
		for range 16 {
			handlers = append(handlers, slot.Middleware()(http.HandlerFunc(okHandler)))
		}
		if slot.compactAt != 64 {
			t.Fatalf("compactAt after 32 registrations = %d, want 64", slot.compactAt)
		}
		runtime.KeepAlive(handlers)
	})

	t.Run("Pipeline", func(t *testing.T) {
		pipeline := NewPipeline()
		handlers := make([]http.Handler, 0, 32)
		for range 16 {
			handlers = append(handlers, pipeline.Middleware()(http.HandlerFunc(okHandler)))
		}
		if pipeline.compactAt != 32 {
			t.Fatalf("compactAt after 16 registrations = %d, want 32", pipeline.compactAt)
		}
		for range 16 {
			handlers = append(handlers, pipeline.Middleware()(http.HandlerFunc(okHandler)))
		}
		if pipeline.compactAt != 64 {
			t.Fatalf("compactAt after 32 registrations = %d, want 64", pipeline.compactAt)
		}
		runtime.KeepAlive(handlers)
	})
}
