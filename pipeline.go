package ada

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"weak"
)

// pipelineEntry is a single named middleware in the pipeline.
type pipelineEntry struct {
	key string
	mw  MiddlewareFunc
}

// pipelineSnapshot is the immutable state of a Pipeline at a point in time.
// Never mutated after creation; swapped atomically via copy-on-write.
type pipelineSnapshot struct {
	entries []pipelineEntry
	cancel  context.CancelFunc // cancels the generation context; nil when cancel tracking is off
	ctx     context.Context    // generation context; nil when cancel tracking is off
}

// rebuildTarget tracks a single registration point where the pipeline's
// pre-built chain needs to be maintained.
type rebuildTarget struct {
	next    http.Handler
	binding atomic.Pointer[reloadBinding]
}

// prepare builds the chain and its generation context as one unpublished value.
// They must never be loaded independently: doing so can run an old chain with
// a new generation context (or vice versa), defeating ApplyWithTimeout.
func (t *rebuildTarget) prepare(snap *pipelineSnapshot) *reloadBinding {
	if snap == nil {
		return &reloadBinding{chain: t.next}
	}

	return &reloadBinding{
		chain: buildChain(snap.entries, t.next),
		ctx:   snap.ctx,
	}
}

// Pipeline is a dynamically-managed ordered set of middlewares keyed by string.
// Middlewares can be added, replaced, removed, and reordered at runtime without
// re-registering routes.
//
// The Pipeline is registered once via Pipeline.Middleware(); subsequent Set/Remove/Apply
// calls take effect on the next request. Each registration point publishes its
// chain and cancellation context atomically. If the same Pipeline is stacked at
// multiple points (for example root and route), a mutation may land between
// those points during one request; this is the same boundary as independently
// registered ordinary middleware.
//
// Pipeline serializes middleware construction and Apply callbacks. A mutation
// requested reentrantly or concurrently while construction is active is queued
// and returns immediately; the active caller drains queued work in FIFO order
// before returning. Each task derives only from the latest successfully
// published snapshot. If queued work panics, later tasks still run and the first
// panic is rethrown by the active caller after the queue is drained.
//
// At most 64 tasks wait internally. Further concurrent submissions block until
// a dequeue signals space, bounding retained task state. The normally empty
// queue keeps one-time reentrant mutations deferred.
//
// Cost: one atomic pointer load per request (chain is pre-built on mutation).
//
// Example:
//
//	stack := ada.NewPipeline()
//	stack.Set("cors", cors.Middleware(...))
//	stack.Set("auth", forwardauth.Middleware(...))
//	server.Use(stack.Middleware())
//
//	// later:
//	stack.Set("ratelimit", ratelimit.Middleware(...))  // add new
//	stack.Remove("auth")                                 // remove
//	stack.Apply(func(b *ada.PipelineBuilder) {           // batch
//	    b.Reset()
//	    b.Set("cors", newCorsMw)
//	    b.Set("auth", newAuthMw)
//	})
type Pipeline struct {
	mu       sync.Mutex
	snapshot atomic.Pointer[pipelineSnapshot]

	// targets are weak so replacing or removing a route releases its handler
	// chain without requiring explicit unregistration. Protected by mu.
	targets     []weak.Pointer[rebuildTarget]
	compactAt   int
	processing  bool
	tasks       []func()
	taskCond    *sync.Cond
	taskWaiters int
}

// NewPipeline creates an empty Pipeline.
func NewPipeline() *Pipeline {
	p := &Pipeline{compactAt: reloadTargetCompactMin}
	snapshot := &pipelineSnapshot{}
	p.snapshot.Store(snapshot)

	return p
}

// Middleware returns a stable middleware closure suitable for registration
// with server.Use, Group, or route-level middleware arguments.
//
// The returned closure captures `next` at registration time and uses a
// pre-built chain that is rebuilt only on mutation. Per-request cost is
// one atomic pointer load (~1 ns).
//
// Calling Middleware multiple times returns independent closures that all
// observe the same pipeline state.
//
// Middleware constructors run outside Pipeline locks. A registration requested
// during construction returns with a complete pass-through binding and is
// rebound by its queued task before the active caller returns.
func (p *Pipeline) Middleware() MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		target := &rebuildTarget{next: next}
		target.binding.Store(&reloadBinding{chain: next})

		p.submit(func() {
			p.mu.Lock()
			p.targets = append(p.targets, weak.Make(target))
			p.maybeCompactTargetsLocked()
			snap := p.snapshot.Load()
			p.mu.Unlock()

			target.binding.Store(target.prepare(snap))
		})

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			binding := target.binding.Load()
			// If this generation has a cancel context (from ApplyWithTimeout),
			// merge it with the request context so cancellation propagates to
			// the chain published in the same binding.
			if binding.ctx != nil {
				merged, cleanup := mergeContexts(r.Context(), binding.ctx)
				defer cleanup()
				r = r.WithContext(merged)
			}

			binding.chain.ServeHTTP(w, r)
		})
	}
}

// Set installs or replaces the middleware under the given key.
// If the key is new, it is appended to the end of the pipeline.
// If the key already exists, its middleware is replaced in-place (order preserved).
func (p *Pipeline) Set(key string, mw MiddlewareFunc) {
	if mw == nil {
		mw = NoOp()
	}

	p.submit(func() {
		p.update(func(b *PipelineBuilder) bool {
			b.set(key, mw)
			return true
		})
	})
}

// SetAt installs or replaces a middleware at a specific position.
// If index is out of range, the entry is appended at the end.
// If the key already exists at a different position, it is moved to the new position.
func (p *Pipeline) SetAt(index int, key string, mw MiddlewareFunc) {
	if mw == nil {
		mw = NoOp()
	}

	p.submit(func() {
		p.update(func(b *PipelineBuilder) bool {
			b.setAt(index, key, mw)
			return true
		})
	})
}

// Remove removes the middleware under the given key.
// Returns true if a middleware was removed synchronously. A call deferred behind
// active construction returns false; its queued removal still runs in order.
func (p *Pipeline) Remove(key string) bool {
	removed := false
	completed := p.submit(func() {
		p.update(func(b *PipelineBuilder) bool {
			removed = b.Remove(key)
			return removed
		})
	})

	return completed && removed
}

// Has reports whether a middleware is installed under the given key.
func (p *Pipeline) Has(key string) bool {
	snap := p.snapshot.Load()
	if snap == nil {
		return false
	}

	for _, e := range snap.entries {
		if e.key == key {
			return true
		}
	}

	return false
}

// Len reports the number of middlewares currently in the pipeline.
func (p *Pipeline) Len() int {
	snap := p.snapshot.Load()
	if snap == nil {
		return 0
	}

	return len(snap.entries)
}

// Keys returns a copy of the current key order.
func (p *Pipeline) Keys() []string {
	snap := p.snapshot.Load()
	if snap == nil {
		return nil
	}

	keys := make([]string, len(snap.entries))
	for i, e := range snap.entries {
		keys[i] = e.key
	}

	return keys
}

// Index returns the position of the middleware with the given key, or -1 if not found.
func (p *Pipeline) Index(key string) int {
	snap := p.snapshot.Load()
	if snap == nil {
		return -1
	}

	for i, e := range snap.entries {
		if e.key == key {
			return i
		}
	}

	return -1
}

// String returns a human-readable representation of the pipeline's current state.
// Useful for logging and debugging.
//
// Example output:
//
//	Pipeline(3 middlewares):
//	  [0] cors
//	  [1] auth
//	  [2] ratelimit
func (p *Pipeline) String() string {
	snap := p.snapshot.Load()
	if snap == nil || len(snap.entries) == 0 {
		return "Pipeline(empty)"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Pipeline(%d middlewares):", len(snap.entries))
	for i, e := range snap.entries {
		fmt.Fprintf(&b, "\n  [%d] %s", i, e.key)
	}

	return b.String()
}

// Apply runs fn with a PipelineBuilder that buffers mutations.
// For an idle Pipeline, fn's changes publish as one atomic swap before Apply
// returns. During construction, Apply itself returns immediately and fn runs
// exactly once later against the state immediately preceding it in queue order.
// fn always runs without an internal Pipeline mutex held.
func (p *Pipeline) Apply(fn func(b *PipelineBuilder)) {
	p.apply(fn, false, 0)
}

// ApplyWithTimeout runs fn as a batch and cancels in-flight requests through
// the old pipeline after the grace period.
//
// A grace of 0 cancels immediately.
func (p *Pipeline) ApplyWithTimeout(fn func(b *PipelineBuilder), grace time.Duration) {
	p.apply(fn, true, grace)
}

// Reset removes all middlewares atomically.
func (p *Pipeline) Reset() {
	p.submit(func() {
		p.update(func(b *PipelineBuilder) bool {
			b.Reset()
			return true
		})
	})
}

// copyEntries returns a deep copy of the snapshot's entries.
func (p *Pipeline) copyEntries(snap *pipelineSnapshot) []pipelineEntry {
	if snap == nil || len(snap.entries) == 0 {
		return nil
	}

	entries := make([]pipelineEntry, len(snap.entries))
	copy(entries, snap.entries)

	return entries
}

// apply executes a callback as one serial queue entry. Conditional reads and
// writes therefore observe and commit one exact snapshot.
func (p *Pipeline) apply(fn func(b *PipelineBuilder), withTimeout bool, grace time.Duration) {
	p.submit(func() {
		snap := p.snapshot.Load()
		b := &PipelineBuilder{entries: p.copyEntries(snap)}
		fn(b)

		newSnap := &pipelineSnapshot{entries: b.entries}
		if withTimeout {
			newSnap.ctx, newSnap.cancel = context.WithCancel(context.Background())
		}
		published := false
		defer func() {
			if !published && newSnap.cancel != nil {
				newSnap.cancel()
			}
		}()

		oldSnap := p.publish(newSnap)
		published = true
		if withTimeout {
			cancelOldPipelineGeneration(oldSnap, grace)
		}
	})
}

// update derives and publishes one internal mutation from the latest successful
// snapshot. Returning false from fn makes the task a no-op.
func (p *Pipeline) update(fn func(b *PipelineBuilder) bool) (*pipelineSnapshot, bool) {
	p.mu.Lock()
	oldSnap := p.snapshot.Load()
	b := &PipelineBuilder{entries: p.copyEntries(oldSnap)}
	if !fn(b) {
		p.mu.Unlock()

		return oldSnap, false
	}
	p.mu.Unlock()

	return p.publish(&pipelineSnapshot{entries: b.entries}), true
}

func (p *Pipeline) publish(snap *pipelineSnapshot) *pipelineSnapshot {
	p.mu.Lock()
	oldSnap := p.snapshot.Load()
	targets := p.liveTargetsLocked()
	p.mu.Unlock()

	bindings := make([]*reloadBinding, len(targets))
	for i, target := range targets {
		bindings[i] = target.prepare(snap)
	}

	p.mu.Lock()
	for i, target := range targets {
		target.binding.Store(bindings[i])
	}
	p.snapshot.Store(snap)
	p.mu.Unlock()

	return oldSnap
}

// submit queues reentrant and concurrent work. Only the caller that transitions
// the Pipeline from idle to processing drains the queue synchronously.
func (p *Pipeline) submit(task func()) bool {
	p.mu.Lock()
	p.initTaskCondLocked()
	for len(p.tasks) >= reloadTaskQueueLimit && p.processing {
		p.taskWaiters++
		p.taskCond.Wait()
		p.taskWaiters--
	}
	if len(p.tasks) >= reloadTaskQueueLimit {
		initial := p.tasks[0]
		p.tasks[0] = nil
		p.tasks = p.tasks[1:]
		p.tasks = append(p.tasks, task)
		p.processing = true
		p.taskCond.Signal()
		p.mu.Unlock()

		p.processTasks(initial)

		return true
	}
	p.tasks = append(p.tasks, task)
	if p.processing {
		p.mu.Unlock()

		return false
	}
	p.processing = true
	p.mu.Unlock()

	p.processTasks(nil)

	return true
}

func (p *Pipeline) processTasks(initial func()) {
	released := false
	defer func() {
		if released {
			return
		}
		p.mu.Lock()
		p.processing = false
		p.initTaskCondLocked()
		p.taskCond.Broadcast()
		p.mu.Unlock()
	}()

	var firstPanic any
	task := initial
	for {
		if task == nil {
			p.mu.Lock()
			if len(p.tasks) == 0 {
				p.tasks = nil
				p.processing = false
				p.initTaskCondLocked()
				p.taskCond.Broadcast()
				released = true
				p.mu.Unlock()
				if firstPanic != nil {
					panic(firstPanic)
				}

				return
			}
			task = p.tasks[0]
			p.tasks[0] = nil
			p.tasks = p.tasks[1:]
			p.initTaskCondLocked()
			p.taskCond.Signal()
			p.mu.Unlock()
		}

		if recovered := runReloadTask(task); recovered != nil && firstPanic == nil {
			firstPanic = recovered
		}
		task = nil
	}
}

func (p *Pipeline) initTaskCondLocked() {
	if p.taskCond == nil {
		p.taskCond = sync.NewCond(&p.mu)
	}
}

// liveTargetsLocked returns strong references for one rebuild and drops dead
// weak entries from the registry. Caller must hold p.mu.
func (p *Pipeline) liveTargetsLocked() []*rebuildTarget {
	registered := p.targets
	targets := make([]*rebuildTarget, 0, len(p.targets))
	live := registered[:0]

	for _, ref := range registered {
		if target := ref.Value(); target != nil {
			targets = append(targets, target)
			live = append(live, ref)
		}
	}

	p.targets = compactWeakPipelineTargets(registered, live)
	p.compactAt = nextReloadTargetCompaction(len(p.targets))

	return targets
}

// maybeCompactTargetsLocked performs geometric registration-time cleanup.
// Mutations continue to compact eagerly in liveTargetsLocked.
func (p *Pipeline) maybeCompactTargetsLocked() {
	if p.compactAt == 0 {
		p.compactAt = reloadTargetCompactMin
	}
	if len(p.targets) < p.compactAt {
		return
	}

	registered := p.targets
	live := registered[:0]
	for _, ref := range registered {
		if ref.Value() != nil {
			live = append(live, ref)
		}
	}

	p.targets = compactWeakPipelineTargets(registered, live)
	p.compactAt = nextReloadTargetCompaction(len(p.targets))
}

func compactWeakPipelineTargets(registered, live []weak.Pointer[rebuildTarget]) []weak.Pointer[rebuildTarget] {
	clear(registered[len(live):])
	if len(live)*2 < len(registered) {
		return append([]weak.Pointer[rebuildTarget](nil), live...)
	}

	return live
}

// buildChain composes the given middleware entries around next, producing a
// single http.Handler. If entries is empty, returns next unchanged.
func buildChain(entries []pipelineEntry, next http.Handler) http.Handler {
	h := next
	for i := len(entries) - 1; i >= 0; i-- {
		h = entries[i].mw(h)
	}

	return h
}

// cancelOldPipelineGeneration cancels the old generation's context after the grace period.
func cancelOldPipelineGeneration(old *pipelineSnapshot, grace time.Duration) {
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

// /////////////////////////////////////////////////////////////////////////////

// PipelineBuilder buffers mutations for atomic application via Pipeline.Apply.
// All methods operate on the exact serial snapshot supplied to the callback.
type PipelineBuilder struct {
	entries []pipelineEntry
}

// Set installs or replaces a middleware under the given key.
// New keys are appended; existing keys are replaced in-place.
func (b *PipelineBuilder) Set(key string, mw MiddlewareFunc) {
	if mw == nil {
		mw = NoOp()
	}
	b.set(key, mw)
}

func (b *PipelineBuilder) set(key string, mw MiddlewareFunc) {
	for i, e := range b.entries {
		if e.key == key {
			b.entries[i].mw = mw
			return
		}
	}

	b.entries = append(b.entries, pipelineEntry{key: key, mw: mw})
}

// SetAt installs or replaces a middleware at a specific position.
// If the key already exists at a different position, it is moved.
// If index is out of range, the entry is appended.
func (b *PipelineBuilder) SetAt(index int, key string, mw MiddlewareFunc) {
	if mw == nil {
		mw = NoOp()
	}
	b.setAt(index, key, mw)
}

func (b *PipelineBuilder) setAt(index int, key string, mw MiddlewareFunc) {
	// Remove existing entry with same key.
	for i, e := range b.entries {
		if e.key == key {
			b.entries = slices.Delete(b.entries, i, i+1)

			break
		}
	}

	entry := pipelineEntry{key: key, mw: mw}

	if index < 0 || index >= len(b.entries) {
		b.entries = append(b.entries, entry)
	} else {
		b.entries = slices.Insert(b.entries, index, entry)
	}
}

// Remove removes the middleware under the given key.
// Returns true if a middleware was removed.
func (b *PipelineBuilder) Remove(key string) bool {
	for i, e := range b.entries {
		if e.key == key {
			b.entries = slices.Delete(b.entries, i, i+1)

			return true
		}
	}

	return false
}

// Reset removes all middlewares from the builder.
func (b *PipelineBuilder) Reset() {
	b.entries = nil
}

// Has reports whether a middleware is installed under the given key.
func (b *PipelineBuilder) Has(key string) bool {
	for _, e := range b.entries {
		if e.key == key {
			return true
		}
	}

	return false
}

// Keys returns the current key order.
func (b *PipelineBuilder) Keys() []string {
	keys := make([]string, len(b.entries))
	for i, e := range b.entries {
		keys[i] = e.key
	}

	return keys
}

// Len reports the number of middlewares in the builder.
func (b *PipelineBuilder) Len() int {
	return len(b.entries)
}
