package ada

import (
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// routePath resolves a route argument against this Mux's group prefix,
// producing the pattern the route is registered — and removed — under.
func (m *Mux) routePath(path string) string {
	return resolveRoutePath(m.prefix, path)
}

func resolveRoutePath(prefix, routePath string) string {
	if routePath == "" {
		if prefix == "" {
			return "/"
		}

		return prefix
	}

	return prefix + "/" + strings.TrimPrefix(routePath, "/")
}

// Remove deletes the route registered for method at path on this Mux,
// reporting whether one was found. Pass "" as the method to remove a
// catch-all registered with Handle or HandleFunc.
//
// The path is interpreted exactly as the routing methods interpret it, so a
// Group removes from its own prefix:
//
//	api := server.Group("/api")
//	api.GET("/users", listUsers)
//	api.Remove(http.MethodGet, "/users") // removes /api/users
//
// Safe to call while the server is serving. Requests already in flight
// complete against the routing table they started with.
func (m *Mux) Remove(method, path string) bool {
	return m.routes.remove(method, m.routePath(path))
}

// RemoveWildcard deletes a catch-all registered with HandleWildcard or
// HandleFuncWildcard. It applies the same path normalization as registration,
// so callers do not need to know whether a trailing "*" was added internally.
func (m *Mux) RemoveWildcard(path string) bool {
	return m.Remove("", normalizeWildcardPath(path))
}

// Routes lists every route registered on this Mux and any Group sharing its
// routing table, ordered by pattern then method.
//
// Safe to call while the server is serving.
func (m *Mux) Routes() []RouteInfo {
	return m.routes.routes()
}

// ApplyRoutes applies a group of route additions, replacements and removals as
// one publication. Requests observe either the complete old table or the
// complete new table, never a partially applied batch.
//
// RouteBuilder accepts the non-generic HandleWithMethod primitive. Context
// handlers can be passed as m.Wrap(handler).
//
// The callback runs under the route-table writer lock. Use only the supplied
// builder inside it; calling Mux route mutation or introspection methods from
// the callback is not supported.
func (m *Mux) ApplyRoutes(fn func(*RouteBuilder)) {
	m.routes.apply(func(root *node) {
		fn(&RouteBuilder{
			root:        root,
			prefix:      m.prefix,
			middlewares: m.middlewares,
		})
	})
}

func normalizeWildcardPath(path string) string {
	if path == "" || strings.HasSuffix(path, "/") {
		return path + "*"
	}

	return path
}

// routeTable owns the radix trie and is shared, by pointer, between a Mux and
// every Group derived from it — Group copies the Mux by value, so the table
// must be reachable through one indirection for a group's registrations to
// land in the same tree as its parent's.
//
// It keeps two trees:
//
//   - live is the writer's tree. It is mutated in place under mu and is never
//     handed to a request, so a registration can never be observed half-applied.
//   - root is the published snapshot. Requests route against it and only ever
//     read it.
//
// Publication is lazy until the first request. Once a snapshot exists, runtime
// mutations publish their replacement eagerly so the clone cost stays on the
// control-plane caller instead of creating a latency spike on the next request.
// This keeps the cost sane at both ends:
//
//   - Registering n routes at startup performs n in-place mutations and exactly
//     one clone, at the first request. Cloning per registration would have made
//     startup O(n²).
//   - Apply coalesces a burst of runtime changes into one publication.
//
// The request path pays one atomic pointer load plus a nil check, which is the
// same load it needed to read the root anyway.
type routeTable struct {
	mu   sync.Mutex
	live *node

	root atomic.Pointer[node]
}

func newRouteTable() *routeTable {
	return &routeTable{live: &node{}}
}

// load returns the tree to route against, publishing the initial snapshot on
// the first request.
func (t *routeTable) load() *node {
	if root := t.root.Load(); root != nil {
		return root
	}

	return t.republish()
}

// republish clones the writer's tree and publishes it. Concurrent callers
// collapse onto the first one's clone.
func (t *routeTable) republish() *node {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Another goroutine may have published while we waited for the lock.
	if root := t.root.Load(); root != nil {
		return root
	}

	root := t.live.clone()
	t.root.Store(root)

	return root
}

// mutate applies fn to the writer's tree. Before serving begins it leaves
// publication lazy; after a snapshot exists it eagerly publishes a clone so no
// request pays the rebuild cost.
func (t *routeTable) mutate(fn func(root *node)) {
	t.mu.Lock()
	defer t.mu.Unlock()

	published := t.root.Load() != nil
	fn(t.live)

	if published {
		t.root.Store(t.live.clone())
	}
}

// insert registers a handler.
func (t *routeTable) insert(method, path string, handler http.HandlerFunc) {
	t.mutate(func(root *node) {
		root.Insert(method, path, handler)
	})
}

// remove deletes the handler registered for method at pattern, reporting
// whether anything was removed.
func (t *routeTable) remove(method, pattern string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	removed := t.live.removeRoute(method, pattern)
	if removed && t.root.Load() != nil {
		t.root.Store(t.live.clone())
	}

	return removed
}

// apply runs a batch against a private working tree. If fn panics, the live
// tree remains untouched; otherwise every change becomes visible in one
// publication.
func (t *routeTable) apply(fn func(root *node)) {
	t.mu.Lock()
	defer t.mu.Unlock()

	working := t.live.clone()
	fn(working)
	t.live = working

	if t.root.Load() != nil {
		t.root.Store(working.clone())
	}
}

// routes lists every registered route, taken from the writer's tree so the
// result reflects mutations that have not been published yet.
func (t *routeTable) routes() []RouteInfo {
	t.mu.Lock()
	defer t.mu.Unlock()

	var out []RouteInfo

	t.live.walkRoutes(&out)

	sort.Slice(out, func(i, j int) bool {
		if out[i].Pattern != out[j].Pattern {
			return out[i].Pattern < out[j].Pattern
		}

		return out[i].Method < out[j].Method
	})

	return out
}

// //////////////////////////////////////////////////////////

// RouteInfo describes one registered route.
type RouteInfo struct {
	// Method is the HTTP method, or "" for a catch-all registered with
	// Handle/HandleFunc.
	Method string
	// Pattern is the route as registered, group prefix included.
	Pattern string
}

// RouteBuilder batches route-table changes for Mux.ApplyRoutes. It is valid
// only for the duration of the callback.
type RouteBuilder struct {
	root        *node
	prefix      string
	middlewares []MiddlewareFunc
}

// HandleWithMethod adds or replaces a route in the batch.
func (b *RouteBuilder) HandleWithMethod(method, routePath string, handler http.HandlerFunc, middlewares ...MiddlewareFunc) {
	combined := make([]MiddlewareFunc, 0, len(b.middlewares)+len(middlewares))
	combined = append(combined, b.middlewares...)
	combined = append(combined, middlewares...)
	handler = Chain(combined...)(handler).ServeHTTP
	b.root.Insert(method, resolveRoutePath(b.prefix, routePath), handler)
}

// Remove deletes a route from the batch.
func (b *RouteBuilder) Remove(method, routePath string) bool {
	return b.root.removeRoute(method, resolveRoutePath(b.prefix, routePath))
}

// RemoveWildcard deletes a wildcard catch-all from the batch.
func (b *RouteBuilder) RemoveWildcard(routePath string) bool {
	return b.Remove("", normalizeWildcardPath(routePath))
}

// clone deep-copies the routing structure of the subtree.
//
// Handlers, param descriptors and the errorScope Mux pointers are shared with
// the original: they are immutable once registered — SetHandler replaces whole
// methodEntry values rather than editing them — so sharing cannot let a reader
// observe a mutation.
func (n *node) clone() *node {
	if n == nil {
		return nil
	}

	c := *n

	if n.StaticChildren != nil {
		c.StaticChildren = make([]staticChild, len(n.StaticChildren))
		for i, child := range n.StaticChildren {
			c.StaticChildren[i] = staticChild{char: child.char, node: child.node.clone()}
		}
	}

	if n.entries != nil {
		c.entries = make([]methodEntry, len(n.entries))
		copy(c.entries, n.entries)
	}

	if n.catchAll != nil {
		entry := *n.catchAll
		c.catchAll = &entry
	}

	if n.TypeParam != nil {
		c.TypeParam = &nodeParam{Name: n.TypeParam.Name, Children: n.TypeParam.Children.clone()}
	}

	if n.TypeWildcard != nil {
		c.TypeWildcard = &nodeWildcard{Children: n.TypeWildcard.Children.clone()}
	}

	return &c
}

// removeRoute deletes the handler for method at pattern anywhere in the
// subtree, reporting whether it found one.
//
// The lookup matches on the pattern recorded by SetHandler rather than
// re-walking the trie with the pattern's own syntax. That costs a full subtree
// scan, but removal is rare and this cannot disagree with what was registered —
// re-deriving the path through the radix splitting rules would be a second
// implementation of insertPath, and a second chance to get it wrong.
//
// Emptied nodes are left in place. They carry no handler, so IsHandlerExists
// reports false and the matcher walks past them exactly as it does for any
// intermediate node; pruning them would mean re-merging radix keys for no
// behavioural gain.
func (n *node) removeRoute(method, pattern string) bool {
	if n == nil {
		return false
	}

	removed := false

	if n.catchAll != nil && n.catchAll.method == method && n.catchAll.pattern == pattern {
		n.catchAll = nil
		removed = true
	}

	for i := range n.entries {
		if n.entries[i].method == method && n.entries[i].pattern == pattern {
			n.entries = append(n.entries[:i], n.entries[i+1:]...)
			removed = true

			break
		}
	}

	if removed {
		n.allow = buildAllowHeader(n)
	}

	for _, child := range n.StaticChildren {
		if child.node.removeRoute(method, pattern) {
			removed = true
		}
	}

	if n.TypeParam != nil && n.TypeParam.Children.removeRoute(method, pattern) {
		removed = true
	}

	if n.TypeWildcard != nil && n.TypeWildcard.Children.removeRoute(method, pattern) {
		removed = true
	}

	return removed
}

// walkRoutes appends every route in the subtree to out.
func (n *node) walkRoutes(out *[]RouteInfo) {
	if n == nil {
		return
	}

	if n.catchAll != nil {
		*out = append(*out, RouteInfo{Method: n.catchAll.method, Pattern: n.catchAll.pattern})
	}

	for i := range n.entries {
		*out = append(*out, RouteInfo{Method: n.entries[i].method, Pattern: n.entries[i].pattern})
	}

	for _, child := range n.StaticChildren {
		child.node.walkRoutes(out)
	}

	if n.TypeParam != nil {
		n.TypeParam.Children.walkRoutes(out)
	}

	if n.TypeWildcard != nil {
		n.TypeWildcard.Children.walkRoutes(out)
	}
}
