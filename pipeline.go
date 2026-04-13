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
	next  http.Handler
	chain atomic.Pointer[http.Handler]
}

// Pipeline is a dynamically-managed ordered set of middlewares keyed by string.
// Middlewares can be added, replaced, removed, and reordered at runtime without
// re-registering routes.
//
// The Pipeline is registered once via Pipeline.Middleware(); subsequent Set/Remove/Apply
// calls take effect on the next request. In-flight requests always observe a consistent
// snapshot.
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

	// targets is the list of registration points whose pre-built chains
	// need rebuilding on mutation. Protected by mu.
	targets []*rebuildTarget
}

// NewPipeline creates an empty Pipeline.
func NewPipeline() *Pipeline {
	p := &Pipeline{}
	p.snapshot.Store(&pipelineSnapshot{})

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
func (p *Pipeline) Middleware() MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		target := &rebuildTarget{next: next}

		// Build the initial chain.
		snap := p.snapshot.Load()
		chain := buildChain(snap.entries, next)
		target.chain.Store(&chain)

		// Register this target so future mutations rebuild its chain.
		p.mu.Lock()
		p.targets = append(p.targets, target)
		p.mu.Unlock()

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := target.chain.Load()

			snap := p.snapshot.Load()
			// If this generation has a cancel context (from ApplyWithTimeout),
			// merge it with the request context so cancellation propagates.
			if snap != nil && snap.ctx != nil {
				merged, cleanup := mergeContexts(r.Context(), snap.ctx)
				defer cleanup()
				r = r.WithContext(merged)
			}

			(*h).ServeHTTP(w, r)
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

	p.mu.Lock()
	defer p.mu.Unlock()

	snap := p.snapshot.Load()
	entries := p.copyEntries(snap)

	found := false
	for i, e := range entries {
		if e.key == key {
			entries[i].mw = mw
			found = true

			break
		}
	}

	if !found {
		entries = append(entries, pipelineEntry{key: key, mw: mw})
	}

	p.storeAndRebuild(&pipelineSnapshot{entries: entries})
}

// SetAt installs or replaces a middleware at a specific position.
// If index is out of range, the entry is appended at the end.
// If the key already exists at a different position, it is moved to the new position.
func (p *Pipeline) SetAt(index int, key string, mw MiddlewareFunc) {
	if mw == nil {
		mw = NoOp()
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	snap := p.snapshot.Load()
	entries := p.copyEntries(snap)

	// Remove existing entry with same key if present.
	for i, e := range entries {
		if e.key == key {
			entries = append(entries[:i], entries[i+1:]...)

			break
		}
	}

	entry := pipelineEntry{key: key, mw: mw}

	if index < 0 || index >= len(entries) {
		entries = append(entries, entry)
	} else {
		entries = slices.Insert(entries, index, entry)
	}

	p.storeAndRebuild(&pipelineSnapshot{entries: entries})
}

// Remove removes the middleware under the given key.
// Returns true if a middleware was removed.
func (p *Pipeline) Remove(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	snap := p.snapshot.Load()
	entries := p.copyEntries(snap)

	for i, e := range entries {
		if e.key == key {
			entries = append(entries[:i], entries[i+1:]...)
			p.storeAndRebuild(&pipelineSnapshot{entries: entries})

			return true
		}
	}

	return false
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
// When fn returns, all changes are published as a single atomic swap.
// In-flight requests continue with the old snapshot; new requests see the new one.
func (p *Pipeline) Apply(fn func(b *PipelineBuilder)) {
	p.mu.Lock()
	defer p.mu.Unlock()

	snap := p.snapshot.Load()
	b := &PipelineBuilder{
		entries: p.copyEntries(snap),
	}

	fn(b)

	p.storeAndRebuild(&pipelineSnapshot{entries: b.entries})
}

// ApplyWithTimeout runs fn as a batch and cancels in-flight requests through
// the old pipeline after the grace period.
//
// A grace of 0 cancels immediately.
func (p *Pipeline) ApplyWithTimeout(fn func(b *PipelineBuilder), grace time.Duration) {
	p.mu.Lock()

	oldSnap := p.snapshot.Load()

	b := &PipelineBuilder{
		entries: p.copyEntries(oldSnap),
	}

	fn(b)

	newCtx, newCancel := context.WithCancel(context.Background())
	newSnap := &pipelineSnapshot{
		entries: b.entries,
		cancel:  newCancel,
		ctx:     newCtx,
	}
	p.storeAndRebuild(newSnap)
	p.mu.Unlock()

	// Cancel old generation after grace period.
	if oldSnap != nil && oldSnap.cancel != nil {
		cancelOldPipelineGeneration(oldSnap, grace)
	}
}

// Reset removes all middlewares atomically.
func (p *Pipeline) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.storeAndRebuild(&pipelineSnapshot{})
}

// copyEntries returns a deep copy of the snapshot's entries.
// Caller must hold p.mu.
func (p *Pipeline) copyEntries(snap *pipelineSnapshot) []pipelineEntry {
	if snap == nil || len(snap.entries) == 0 {
		return nil
	}

	entries := make([]pipelineEntry, len(snap.entries))
	copy(entries, snap.entries)

	return entries
}

// storeAndRebuild stores a new snapshot and rebuilds all registered chains.
// Cancel contexts are NOT created by default — only ApplyWithTimeout creates them.
// This keeps per-request overhead at zero for the common (non-timeout) case.
// Caller must hold p.mu.
func (p *Pipeline) storeAndRebuild(snap *pipelineSnapshot) {
	p.snapshot.Store(snap)

	for _, t := range p.targets {
		chain := buildChain(snap.entries, t.next)
		t.chain.Store(&chain)
	}
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
// All methods operate on an in-memory copy; no changes are visible until
// Apply returns.
type PipelineBuilder struct {
	entries []pipelineEntry
}

// Set installs or replaces a middleware under the given key.
// New keys are appended; existing keys are replaced in-place.
func (b *PipelineBuilder) Set(key string, mw MiddlewareFunc) {
	if mw == nil {
		mw = NoOp()
	}

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

	// Remove existing entry with same key.
	for i, e := range b.entries {
		if e.key == key {
			b.entries = append(b.entries[:i], b.entries[i+1:]...)

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
			b.entries = append(b.entries[:i], b.entries[i+1:]...)

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
