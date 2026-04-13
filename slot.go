package ada

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// MiddlewareFunc is the canonical middleware signature used by ada.
type MiddlewareFunc = func(next http.Handler) http.Handler

// NoOp returns a middleware that does nothing and passes through to the next handler.
// Useful as a placeholder for disabled Slots or empty Pipelines.
func NoOp() MiddlewareFunc {
	return func(next http.Handler) http.Handler { return next }
}

// slotState holds the immutable state of a Slot at a point in time.
// Swapped atomically; never mutated after creation.
type slotState struct {
	mw      MiddlewareFunc     // never nil; NoOp when disabled-and-cleared
	enabled bool               // when false, the slot is a pass-through
	cancel  context.CancelFunc // cancels the generation context; nil when cancel tracking is off
	ctx     context.Context    // generation context; nil when cancel tracking is off
}

// slotTarget tracks a single registration point where the Slot's
// pre-built handler chain needs to be maintained.
type slotTarget struct {
	next  http.Handler
	chain atomic.Pointer[http.Handler]
}

// Slot wraps a middleware in an atomic pointer, allowing it to be replaced,
// disabled, or re-enabled at runtime without re-registering routes.
//
// A Slot may be registered with server.Use, Group, or as a per-route middleware
// argument. All registration points share the same underlying state; a single
// Replace/Disable/Enable call affects every location where the Slot was used.
//
// Cost: two atomic pointer loads per request (~2 ns). When a WithTimeout
// variant is active, one context derivation is added per request.
//
// Example:
//
//	auth := ada.NewSlot(forwardauth.Middleware(
//	    forwardauth.WithAddress("http://auth:8080/verify"),
//	))
//	server.Use(auth.Middleware())
//	server.GET("/api/me", meHandler)
//
//	// later, at runtime:
//	auth.Replace(forwardauth.Middleware(
//	    forwardauth.WithAddress("http://auth-v2:8080/verify"),
//	))
//	auth.Disable()   // bypass
//	auth.Enable()    // restore
type Slot struct {
	state   atomic.Pointer[slotState]
	mu      sync.Mutex    // serializes writes to targets
	targets []*slotTarget // registration points for pre-built chain rebuild
}

// NewSlot creates a new enabled Slot initialized with the given middleware.
// If mw is nil, the slot starts with NoOp (pass-through).
//
// No cancel context is created by default. Cancel contexts are only created
// by WithTimeout variants (ReplaceWithTimeout, DisableWithTimeout), keeping
// the per-request overhead at zero for the common case.
func NewSlot(mw MiddlewareFunc) *Slot {
	if mw == nil {
		mw = NoOp()
	}

	s := &Slot{}
	s.state.Store(&slotState{mw: mw, enabled: true})

	return s
}

// Middleware returns a stable middleware closure suitable for registration
// with server.Use, Group, or route-level middleware arguments.
//
// The returned closure uses a pre-built handler chain that is rebuilt only
// on mutation. Per-request cost is two atomic pointer loads (~2 ns) with
// zero allocations.
//
// Every call returns a new closure, but all closures read from the same
// underlying atomic pointer. Registering the same Slot in multiple places
// is safe; Replace/Disable/Enable propagates to all of them.
//
// Note: if the same Slot is registered in stacked locations (e.g. root Use
// AND a child Group), the middleware runs once per registration point per
// request in that group. This matches how non-slotted middlewares behave.
func (s *Slot) Middleware() MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		target := &slotTarget{next: next}

		// Build initial chain.
		st := s.state.Load()
		if st != nil && st.enabled {
			chain := st.mw(next)
			target.chain.Store(&chain)
		}

		// Register this target so future mutations rebuild its chain.
		s.mu.Lock()
		s.targets = append(s.targets, target)
		s.mu.Unlock()

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			st := s.state.Load()
			if st == nil || !st.enabled {
				next.ServeHTTP(w, r)
				return
			}

			// If this generation has a cancel context (from a WithTimeout variant),
			// merge it with the request context so cancellation propagates.
			if st.ctx != nil {
				merged, cleanup := mergeContexts(r.Context(), st.ctx)
				defer cleanup()
				r = r.WithContext(merged)
			}

			h := target.chain.Load()
			(*h).ServeHTTP(w, r)
		})
	}
}

// Replace atomically swaps the underlying middleware.
// The slot remains enabled after the swap.
// In-flight requests using the old middleware finish normally.
func (s *Slot) Replace(mw MiddlewareFunc) {
	if mw == nil {
		mw = NoOp()
	}

	s.state.Store(&slotState{mw: mw, enabled: true})
	s.rebuildTargets(mw)
}

// ReplaceWithTimeout atomically swaps the underlying middleware and cancels
// in-flight requests through the old middleware after the grace period.
//
// Requests that complete before the grace period expires are unaffected.
// After the grace period, the old generation's context is cancelled; handlers
// that respect ctx.Done() will abort, others finish normally (best-effort).
//
// A grace of 0 cancels immediately.
//
// Note: only in-flight requests from a previous WithTimeout generation can be
// cancelled. Requests from a generation created by NewSlot, Replace, or Enable
// do not have a cancel context and are unaffected.
func (s *Slot) ReplaceWithTimeout(mw MiddlewareFunc, grace time.Duration) {
	if mw == nil {
		mw = NoOp()
	}

	old := s.state.Load()

	newCtx, newCancel := context.WithCancel(context.Background())
	s.state.Store(&slotState{
		mw:      mw,
		enabled: true,
		cancel:  newCancel,
		ctx:     newCtx,
	})
	s.rebuildTargets(mw)

	cancelOldGeneration(old, grace)
}

// Disable makes the slot a pass-through without discarding the underlying
// middleware. The previously-set middleware is preserved and can be restored
// with Enable.
// In-flight requests using the old middleware finish normally.
func (s *Slot) Disable() {
	old := s.state.Load()

	mw := NoOp()
	if old != nil {
		mw = old.mw
	}

	s.state.Store(&slotState{mw: mw, enabled: false})
	// No rebuildTargets needed — the hot path checks st.enabled first
	// and short-circuits to next.ServeHTTP.
}

// DisableWithTimeout makes the slot a pass-through and cancels in-flight
// requests through the old middleware after the grace period.
//
// A grace of 0 cancels immediately.
func (s *Slot) DisableWithTimeout(grace time.Duration) {
	old := s.state.Load()

	mw := NoOp()
	if old != nil {
		mw = old.mw
	}

	s.state.Store(&slotState{mw: mw, enabled: false})
	cancelOldGeneration(old, grace)
}

// Enable restores the slot to its previously-set middleware.
// If the slot is already enabled, this is a no-op.
func (s *Slot) Enable() {
	old := s.state.Load()
	if old == nil || old.enabled {
		return
	}

	s.state.Store(&slotState{mw: old.mw, enabled: true})
	s.rebuildTargets(old.mw)
}

// Enabled reports whether the slot is currently enabled.
func (s *Slot) Enabled() bool {
	st := s.state.Load()
	return st != nil && st.enabled
}

// rebuildTargets pre-builds the handler chain for all registration points.
// Called on Replace, ReplaceWithTimeout, and Enable.
func (s *Slot) rebuildTargets(mw MiddlewareFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range s.targets {
		chain := mw(t.next)
		t.chain.Store(&chain)
	}
}

// cancelOldGeneration cancels the old generation's context after the grace period.
// If the old state has no cancel func (non-timeout path), this is a no-op.
func cancelOldGeneration(old *slotState, grace time.Duration) {
	if old == nil || old.cancel == nil {
		return
	}

	if grace <= 0 {
		old.cancel()
		return
	}

	go func() {
		timer := time.NewTimer(grace)
		defer timer.Stop()
		<-timer.C
		old.cancel()
	}()
}

// mergeContexts returns a context that is cancelled when either parent or
// cancel is done, whichever comes first. Values are inherited from parent.
//
// The returned cleanup function deregisters watchers from the cancel context's
// children map, preventing unbounded memory growth across requests. Callers
// must call cleanup after the request completes (typically via defer).
func mergeContexts(parent, cancel context.Context) (context.Context, func()) {
	if cancel == nil {
		return parent, func() {}
	}

	ctx, stop := context.WithCancel(parent)

	// When the cancel context (generation) is done, cancel the merged context.
	s1 := context.AfterFunc(cancel, func() {
		stop()
	})

	// When the parent (request) is done, stop watching the cancel context.
	s2 := context.AfterFunc(parent, func() {
		stop()
	})

	cleanup := func() {
		s1()   // deregister from cancel context's children map
		s2()   // deregister from parent context's children map
		stop() // cancel the merged context (idempotent)
	}

	return ctx, cleanup
}
