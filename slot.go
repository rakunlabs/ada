package ada

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
	"weak"
)

// MiddlewareFunc is the canonical middleware signature used by ada.
type MiddlewareFunc = func(next http.Handler) http.Handler

const (
	reloadTargetCompactMin = 16
	// reloadTaskQueueLimit bounds the queued-mutation backlog for both Slot
	// and Pipeline. It is unexported, so the exported Slot/Pipeline godoc
	// spells the number out instead of naming it — keep those in sync.
	reloadTaskQueueLimit = 64
)

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

// reloadBinding is everything a reloadable middleware request path needs,
// published as one value. Slot and Pipeline both use it so neither can pair a
// chain from one generation with the cancellation context from another.
//
// Keeping the chain and the generation context together matters: when they
// lived in two independent atomic pointers a request could load the new
// generation's context and the old generation's chain (or vice versa), so
// requests running through the old middleware were not cancellable — the exact
// inverse of the ReplaceWithTimeout contract.
type reloadBinding struct {
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
	binding atomic.Pointer[reloadBinding]
}

// prepare pre-builds this target's binding for the given state.
//   - A chain is ALWAYS stored — the bare next handler when the slot is
//     disabled — so the request path never has to test for nil.
func (t *slotTarget) prepare(st *slotState) *reloadBinding {
	binding := &reloadBinding{chain: t.next}

	if st != nil {
		binding.ctx = st.ctx

		if st.enabled {
			binding.chain = st.mw(t.next)
		}
	}

	return binding
}

// Slot wraps a middleware in an atomic pointer, allowing it to be replaced,
// disabled, or re-enabled at runtime without re-registering routes.
//
// A Slot may be registered with server.Use, Group, or as a per-route middleware
// argument. All registration points share the same underlying state; a single
// Replace/Disable/Enable call affects every location where the Slot was used.
//
// Slot serializes middleware construction. A mutation requested reentrantly or
// concurrently while construction is active is queued and returns immediately;
// the active caller drains queued work in FIFO order before returning. Each task
// derives only from the latest successfully published state. If queued work
// panics, later tasks still run and the first panic is rethrown by the active
// caller after the queue is drained.
//
// At most 64 tasks wait internally. Further concurrent submissions block until
// a dequeue signals space, bounding retained task state. The normally empty
// queue keeps one-time reentrant mutations deferred.
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
	state atomic.Pointer[slotState]
	mu    sync.Mutex

	// targets are weak so replacing or removing a route releases its handler
	// chain without requiring explicit unregistration. Protected by mu.
	targets     []weak.Pointer[slotTarget]
	compactAt   int
	processing  bool
	tasks       []func()
	taskCond    *sync.Cond
	taskWaiters int
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

	s := &Slot{compactAt: reloadTargetCompactMin}
	state := &slotState{mw: mw, enabled: true}
	s.state.Store(state)

	return s
}

// Middleware returns a stable middleware closure suitable for registration
// with server.Use, Group, or route-level middleware arguments.
//
// The returned closure uses a pre-built handler chain that is rebuilt only
// on mutation. Per-request cost is one atomic pointer load (~1 ns) with
// zero allocations.
//
// Every call returns a new closure, but all closures read from the same
// underlying atomic pointer. Registering the same Slot in multiple places
// is safe; Replace/Disable/Enable propagates to all of them.
//
// Note: if the same Slot is registered in stacked locations (e.g. root Use
// AND a child Group), the middleware runs once per registration point per
// request in that group. This matches how non-slotted middlewares behave.
//
// Middleware constructors run outside Slot locks. A registration requested
// during construction returns with a complete pass-through binding and is
// rebound by its queued task before the active caller returns.
func (s *Slot) Middleware() MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		target := &slotTarget{next: next}
		target.binding.Store(&reloadBinding{chain: next})

		s.submit(func() {
			s.mu.Lock()
			s.targets = append(s.targets, weak.Make(target))
			s.maybeCompactTargetsLocked()
			state := s.state.Load()
			s.mu.Unlock()

			target.binding.Store(target.prepare(state))
		})

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

	s.submit(func() {
		s.mutate(func(*slotState) *slotState {
			return &slotState{mw: mw, enabled: true}
		})
	})
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

	s.submit(func() {
		newCtx, newCancel := context.WithCancel(context.Background())
		published := false
		defer func() {
			if !published {
				newCancel()
			}
		}()

		old := s.mutate(func(*slotState) *slotState {
			return &slotState{
				mw:      mw,
				enabled: true,
				cancel:  newCancel,
				ctx:     newCtx,
			}
		})
		published = true
		cancelOldGeneration(old, grace)
	})
}

// Disable makes the slot a pass-through without discarding the underlying
// middleware. The previously-set middleware is preserved and can be restored
// with Enable.
// In-flight requests using the old middleware finish normally.
func (s *Slot) Disable() {
	s.submit(func() {
		s.mutate(disabledFrom)
	})
}

// DisableWithTimeout makes the slot a pass-through and cancels in-flight
// requests through the old middleware after the grace period.
//
// A grace of 0 cancels immediately.
func (s *Slot) DisableWithTimeout(grace time.Duration) {
	s.submit(func() {
		old := s.mutate(disabledFrom)
		cancelOldGeneration(old, grace)
	})
}

// Enable restores the slot to its previously-set middleware.
// If the slot is already enabled, this is a no-op.
func (s *Slot) Enable() {
	s.submit(func() {
		s.mutate(func(old *slotState) *slotState {
			if old == nil || old.enabled {
				return nil // already enabled, or nothing to restore
			}

			return &slotState{mw: old.mw, enabled: true}
		})
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

// mutate constructs and publishes one queued operation transactionally.
func (s *Slot) mutate(fn func(old *slotState) *slotState) *slotState {
	s.mu.Lock()
	old := s.state.Load()
	state := fn(old)
	if state == nil {
		s.mu.Unlock()

		return old
	}
	targets := s.liveTargetsLocked()
	s.mu.Unlock()

	bindings := make([]*reloadBinding, len(targets))
	for i, target := range targets {
		bindings[i] = target.prepare(state)
	}

	s.mu.Lock()
	for i, target := range targets {
		target.binding.Store(bindings[i])
	}
	s.state.Store(state)
	s.mu.Unlock()

	return old
}

func (s *Slot) submit(task func()) {
	s.mu.Lock()
	s.initTaskCondLocked()
	for len(s.tasks) >= reloadTaskQueueLimit && s.processing {
		s.taskWaiters++
		s.taskCond.Wait()
		s.taskWaiters--
	}
	if len(s.tasks) >= reloadTaskQueueLimit {
		initial := s.tasks[0]
		s.tasks[0] = nil
		s.tasks = s.tasks[1:]
		s.tasks = append(s.tasks, task)
		s.processing = true
		s.taskCond.Signal()
		s.mu.Unlock()

		s.processTasks(initial)

		return
	}
	s.tasks = append(s.tasks, task)
	if s.processing {
		s.mu.Unlock()

		return
	}
	s.processing = true
	s.mu.Unlock()

	s.processTasks(nil)
}

func (s *Slot) processTasks(initial func()) {
	released := false
	defer func() {
		if released {
			return
		}
		s.mu.Lock()
		s.processing = false
		s.initTaskCondLocked()
		s.taskCond.Broadcast()
		s.mu.Unlock()
	}()

	var firstPanic any
	task := initial
	for {
		if task == nil {
			s.mu.Lock()
			if len(s.tasks) == 0 {
				s.tasks = nil
				s.processing = false
				s.initTaskCondLocked()
				s.taskCond.Broadcast()
				released = true
				s.mu.Unlock()
				if firstPanic != nil {
					panic(firstPanic)
				}

				return
			}
			task = s.tasks[0]
			s.tasks[0] = nil
			s.tasks = s.tasks[1:]
			s.initTaskCondLocked()
			s.taskCond.Signal()
			s.mu.Unlock()
		}

		if recovered := runReloadTask(task); recovered != nil && firstPanic == nil {
			firstPanic = recovered
		}
		task = nil
	}
}

func (s *Slot) initTaskCondLocked() {
	if s.taskCond == nil {
		s.taskCond = sync.NewCond(&s.mu)
	}
}

func runReloadTask(task func()) (recovered any) {
	defer func() {
		recovered = recover()
	}()
	task()

	return nil
}

// liveTargetsLocked returns strong references for one rebuild and drops dead
// weak entries from the registry. Caller must hold s.mu.
func (s *Slot) liveTargetsLocked() []*slotTarget {
	registered := s.targets
	targets := make([]*slotTarget, 0, len(s.targets))
	live := registered[:0]

	for _, ref := range registered {
		if target := ref.Value(); target != nil {
			targets = append(targets, target)
			live = append(live, ref)
		}
	}

	s.targets = compactWeakSlotTargets(registered, live)
	s.compactAt = nextReloadTargetCompaction(len(s.targets))

	return targets
}

// maybeCompactTargetsLocked performs geometric registration-time cleanup.
// Scans happen at exponentially increasing thresholds when targets stay live,
// making registration amortized O(1); every mutation still compacts eagerly.
func (s *Slot) maybeCompactTargetsLocked() {
	if s.compactAt == 0 {
		s.compactAt = reloadTargetCompactMin
	}
	if len(s.targets) < s.compactAt {
		return
	}

	registered := s.targets
	live := registered[:0]
	for _, ref := range registered {
		if ref.Value() != nil {
			live = append(live, ref)
		}
	}

	s.targets = compactWeakSlotTargets(registered, live)
	s.compactAt = nextReloadTargetCompaction(len(s.targets))
}

func nextReloadTargetCompaction(live int) int {
	next := live * 2
	if next < reloadTargetCompactMin {
		return reloadTargetCompactMin
	}

	return next
}

func compactWeakSlotTargets(registered, live []weak.Pointer[slotTarget]) []weak.Pointer[slotTarget] {
	clear(registered[len(live):])
	if len(live)*2 < len(registered) {
		return append([]weak.Pointer[slotTarget](nil), live...)
	}

	return live
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

	cleanup := func() {
		s1()   // deregister from cancel context's children map
		stop() // cancel the merged context (idempotent)
	}

	return ctx, cleanup
}
