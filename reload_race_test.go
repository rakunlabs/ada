package ada

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// hit drives one request through mw and reports the body it produced.
func hit(mw MiddlewareFunc) string {
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("next"))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	return rec.Body.String()
}

func tagMiddleware(tag string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(tag))
			next.ServeHTTP(w, r)
		})
	}
}

// TestSlot_RegisterDuringMutation guards the registration TOCTOU: the initial
// chain used to be built outside the lock that appends the target, so a
// concurrent Enable could rebuild every already-registered target and then miss
// the new one — leaving it with a nil chain that the request path dereferenced.
func TestSlot_RegisterDuringMutation(t *testing.T) {
	for range 200 {
		slot := NewSlot(tagMiddleware("A"))
		slot.Disable()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			slot.Enable()
		}()

		go func() {
			defer wg.Done()
			// Must not panic, and must produce a usable handler.
			if got := hit(slot.Middleware()); got != "next" && got != "Anext" {
				t.Errorf("unexpected body %q", got)
			}
		}()

		wg.Wait()
	}
}

// TestSlot_ConcurrentReplaceAndDisable guards the lost update: Disable did a
// read-modify-write on the state outside the mutex, so it could clobber a
// concurrent Replace and a later Enable would silently restore the OLD
// middleware. After the fix, Enable must always restore whatever Replace last
// published.
func TestSlot_ConcurrentReplaceAndDisable(t *testing.T) {
	for range 500 {
		slot := NewSlot(tagMiddleware("old"))
		mw := slot.Middleware()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			slot.Replace(tagMiddleware("new"))
		}()

		go func() {
			defer wg.Done()
			slot.Disable()
		}()

		wg.Wait()

		slot.Enable()

		// Whatever interleaving happened, the executed chain must match the
		// state the Slot reports — never the pre-Replace middleware.
		if got := hit(mw); got != "newnext" {
			t.Fatalf("after Replace+Disable+Enable: body = %q, want %q", got, "newnext")
		}
	}
}

// TestPipeline_RegisterDuringMutation asserts the same invariant for Pipeline,
// which had the identical TOCTOU with a silent symptom: the newly registered
// target kept a stale chain, so a middleware that Has() reported as present
// never ran.
//
// Unlike the two Slot tests above, this one does NOT reliably reproduce the
// old bug — the window between the snapshot read and the append is only a few
// instructions wide, and it did not trigger in 2000 iterations against the
// unfixed code. It is kept as an invariant check: reported contents and
// executed chain must agree.
func TestPipeline_RegisterDuringMutation(t *testing.T) {
	for range 500 {
		pipeline := NewPipeline()

		var (
			wg sync.WaitGroup
			mw MiddlewareFunc
		)

		wg.Add(2)

		go func() {
			defer wg.Done()
			pipeline.Set("mark", tagMiddleware("mark"))
		}()

		go func() {
			defer wg.Done()
			mw = pipeline.Middleware()
		}()

		wg.Wait()

		// Registration order is racy, so re-read a fresh handler: what must
		// hold is that the pipeline's reported contents and the executed
		// chain agree.
		if !pipeline.Has("mark") {
			t.Fatal("Set completed but Has reports the entry missing")
		}
		if got := hit(mw); got != "marknext" {
			t.Fatalf("pipeline reports %q registered but chain produced %q", "mark", got)
		}
	}
}
