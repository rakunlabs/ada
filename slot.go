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

// slotBinding is everything the request path needs, published as one value.
//
// Keeping the chain and the generation context together matters: when they
// lived in two independent atomic pointers a request could load the new
// generation's context and the old generation's chain (or vice versa), so
// requests running through the old middleware were not cancellable — the exact
// inverse of the ReplaceWithTimeout contract.
type slotBinding struct {
	// ctx is the generation context; nil when cancel tracking is off.
	ctx context.Context
	// chain is the pre-built handler chain, or the bare next handler when
	// the slot is disabled. Never nil.
	chain http.Handler
}

// slotTarget tracks a single registration point where the Slot's
// pre-built handler chain needs to be maintained.
type slotTarget struct {
	next    http.Handler
	binding atomic.Pointer[slotBinding]
}

// bind pre-builds this target's binding for the given state.
//   - A chain is ALWAYS stored — the bare next handler when the slot is
//     disabled — so the request path never has to test for nil.
func (t *slotTarget) bind(st *slotState) {
	binding := &slotBinding{chain: t.next}

	if st != nil {
		binding.ctx = st.ctx

		if st.enabled {
			binding.chain = st.mw(t.next)
		}
	}

	t.binding.Store(binding)
}

// Slot wraps a middleware in an atomic pointer, allowing it to be replaced,
// disabled, or re-enabled at runtime without re-registering routes.
//
// A Slot may be registered with server.Use, Group, or as a per-route middleware
// argument. All registration points share the same underlying state; a single
// Replace/Disable/Enable call affects every location where the Slot was used.
//
// Cost: one atomic pointer load per request. When a WithTimeout variant is
// active, one context derivation is added per request.
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

		// Register and build in ONE critical section. Splitting them let a
		// concurrent mutation rebuild every *already registered* target and
		// then miss this one, leaving it bound to a stale chain — or, before
		// a chain was stored at all, to nil.
		s.mu.Lock()
		target.bind(s.state.Load())
		s.targets = append(s.targets, target)
		s.mu.Unlock()

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			binding := target.binding.Load()

			// If this generation has a cancel context (from a WithTimeout
			// variant), merge it with the request context so cancellation
			// propagates to the chain published alongside it.
			if binding.ctx != nil {
				merged, cleanup := mergeContexts(r.Context(), binding.ctx)
				defer cleanup()
				r = r.WithContext(merged)
			}

			binding.chain.ServeHTTP(w, r)
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

	s.storeAndRebuild(&slotState{mw: mw, enabled: true})
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

	newCtx, newCancel := context.WithCancel(context.Background())

	old := s.storeAndRebuild(&slotState{
		mw:      mw,
		enabled: true,
		cancel:  newCancel,
		ctx:     newCtx,
	})

	cancelOldGeneration(old, grace)
}

// Disable makes the slot a pass-through without discarding the underlying
// middleware. The previously-set middleware is preserved and can be restored
// with Enable.
// In-flight requests using the old middleware finish normally.
func (s *Slot) Disable() {
	s.mutate(disabledFrom)
}

// DisableWithTimeout makes the slot a pass-through and cancels in-flight
// requests through the old middleware after the grace period.
//
// A grace of 0 cancels immediately.
func (s *Slot) DisableWithTimeout(grace time.Duration) {
	cancelOldGeneration(s.mutate(disabledFrom), grace)
}

// Enable restores the slot to its previously-set middleware.
// If the slot is already enabled, this is a no-op.
func (s *Slot) Enable() {
	s.mutate(func(old *slotState) *slotState {
		if old == nil || old.enabled {
			return nil // already enabled, or nothing to restore
		}

		return &slotState{mw: old.mw, enabled: true}
	})
}

// Enabled reports whether the slot is currently enabled.
func (s *Slot) Enabled() bool {
	st := s.state.Load()
	return st != nil && st.enabled
}

// disabledFrom derives the disabled state that preserves old's middleware, so
// Enable can restore it.
func disabledFrom(old *slotState) *slotState {
	mw := NoOp()
	if old != nil {
		mw = old.mw
	}

	return &slotState{mw: mw, enabled: false}
}

// storeAndRebuild publishes a new state and rebinds every registration point
// in one critical section, returning the state it replaced.
//
// Publishing outside the lock — as this used to — let two concurrent mutations
// interleave so that the stored state and the built chains disagreed
// permanently: Enabled() reported one middleware while requests ran another,
// with no way to resync.
func (s *Slot) storeAndRebuild(state *slotState) *slotState {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.storeAndRebuildLocked(state)
}

func (s *Slot) storeAndRebuildLocked(state *slotState) *slotState {
	old := s.state.Load()
	s.state.Store(state)

	for _, t := range s.targets {
		t.bind(state)
	}

	return old
}

// mutate applies fn to the current state and publishes the result atomically,
// so a read-modify-write mutator (Disable, Enable) cannot clobber a concurrent
// Replace. Returning nil from fn makes the call a no-op.
func (s *Slot) mutate(fn func(old *slotState) *slotState) *slotState {
	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.state.Load()

	state := fn(old)
	if state == nil {
		return old
	}

	return s.storeAndRebuildLocked(state)
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
