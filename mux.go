package ada

import (
	"fmt"
	"net/http"
	"path"
	"sort"
	"strings"
)

type typeNode int

const (
	typeNodeSelf          typeNode = iota // Self node, e.g., /
	typeNodeStatic                        // Static node, e.g., /users
	typeNodeWildcard                      // Bare wildcard, single segment when middle, greedy when trailing: /users/*
	typeNodeParam                         // Single-segment named param, e.g., /users/{id}
	typeNodeWildcardParam                 // Greedy NAMED wildcard, trailing only, e.g., /files/{path...}
)

type paramInfo struct {
	Index int    // segment index in the URL path
	Name  string // parameter name, e.g. "id"
}

// staticChild is a single entry in the sorted children slice.
// Sorted by char for fast linear scan (most nodes have 1-4 children).
type staticChild struct {
	char byte
	node *node
}

// methodEntry bundles everything needed to dispatch one method on a node:
// the handler, the route pattern (set on r.Pattern before the call), and the
// pre-computed param names. Nodes hold these in a small slice instead of
// maps — a linear scan over 1-4 entries beats map hashing on the hot path.
type methodEntry struct {
	method  string
	pattern string
	params  []paramInfo
	handler http.HandlerFunc
}

type node struct {
	// Possible marks a trailing (greedy) wildcard child: the node can
	// consume the entire remaining path.
	Possible bool

	// Inlined static trie fields. StaticKey is the compressed radix
	// label for this node; keys span segment boundaries, so '/' bytes
	// appear inside keys and one comparison can match several path
	// segments. StaticChildren is a sorted slice keyed by first byte.
	StaticKey      string
	StaticChildren []staticChild

	// Pre-computed '/' metadata for StaticKey, maintained by setKey so
	// the hot path avoids strings.LastIndexByte/strings.Count per key
	// hop. keySlashPos is lastIndexByte(key,'/')+1 — 0 means "no slash"
	// so the zero value is correct for empty keys. keySlashCount is the
	// number of '/' bytes in the key.
	keySlashPos   int
	keySlashCount int

	TypeWildcard *nodeWildcard
	TypeParam    *nodeParam

	// entries holds the per-method handlers; catchAll is the
	// method-agnostic handler registered via HandleFunc/Handle.
	entries  []methodEntry
	catchAll *methodEntry

	// errorScope is the Mux whose 404/405/auto-OPTIONS chains apply to
	// requests that reach this subtree without matching a route.
	//
	// It is attached at `prefix + "/*"` by Use/NotFound/MethodNotAllowed
	// and by Group, so a group's middlewares still run on its unmatched
	// paths. Crucially it is NOT a route: registering one (as this
	// package used to) makes the node answer every method, which shadows
	// 405, auto-OPTIONS and any user-registered catch-all.
	errorScope *Mux

	// allow is the pre-computed Allow header value for 405/auto-OPTIONS
	// responses. Maintained by SetHandler; "" when a catch-all handler
	// exists (any method is accepted) or no methods are registered.
	allow string
}

// lookupMethod returns the entry for the given method, or nil.
// Linear scan: nodes typically register 1-4 methods, and a string
// comparison (length check + memequal) is cheaper than map hashing.
func (n *node) lookupMethod(method string) *methodEntry {
	for i := range n.entries {
		if n.entries[i].method == method {
			return &n.entries[i]
		}
	}

	return nil
}

// lookupEntry resolves the entry for a request method including the
// auto-HEAD fallback (HEAD falls back to GET) and the catch-all handler.
func (n *node) lookupEntry(method string) *methodEntry {
	entry := n.lookupMethod(method)
	if entry == nil && method == http.MethodHead {
		entry = n.lookupMethod(http.MethodGet)
	}
	if entry == nil {
		entry = n.catchAll
	}

	return entry
}

// setKey assigns the radix key and refreshes the pre-computed '/'
// metadata used by ServeHTTP's segment bookkeeping.
func (n *node) setKey(key string) {
	n.StaticKey = key
	n.keySlashPos = strings.LastIndexByte(key, '/') + 1
	n.keySlashCount = strings.Count(key, "/")
}

// getStaticChild returns the child node for the given first byte.
// Uses linear scan on a sorted slice — optimal for 1-8 children.
func (n *node) getStaticChild(char byte) (*node, bool) {
	for _, c := range n.StaticChildren {
		if c.char == char {
			return c.node, true
		}

		if c.char > char {
			return nil, false // sorted, stop early
		}
	}

	return nil, false
}

// setStaticChild inserts or replaces a child node, maintaining sorted order.
func (n *node) setStaticChild(char byte, child *node) {
	for i, c := range n.StaticChildren {
		if c.char == char {
			n.StaticChildren[i].node = child

			return
		}

		if c.char > char {
			// Insert at position i.
			n.StaticChildren = append(n.StaticChildren, staticChild{})
			copy(n.StaticChildren[i+1:], n.StaticChildren[i:])
			n.StaticChildren[i] = staticChild{char: char, node: child}

			return
		}
	}

	// Append at end.
	n.StaticChildren = append(n.StaticChildren, staticChild{char: char, node: child})
}

type nodeParam struct {
	// Name of the parameter, ex "id"
	Name     string
	Children *node
}

type nodeWildcard struct {
	// Children nodes for wildcard
	Children *node
}

func (n *node) IsHandlerExists() bool {
	return n.catchAll != nil || len(n.entries) > 0
}

func (n *node) SetHandler(method, path string, handler http.HandlerFunc, params []paramInfo) {
	// The pattern is stored on the entry and assigned to r.Pattern in
	// ServeHTTP right before the handler runs — no wrapper closure, so
	// dispatch stays a single indirect call.
	entry := methodEntry{
		method:  method,
		pattern: path,
		params:  params,
		handler: handler,
	}

	if method == "" {
		n.catchAll = &entry
		n.allow = buildAllowHeader(n)

		return
	}

	for i := range n.entries {
		if n.entries[i].method == method {
			n.entries[i] = entry

			return
		}
	}

	n.entries = append(n.entries, entry)
	n.allow = buildAllowHeader(n)
}

func (n *node) Insert(method, path string, handler http.HandlerFunc) {
	current, params, lastType := n.insertPath(path)

	current.SetHandler(method, path, handler, params)
	// Possible marks "trailing wildcard reached" so ServeHTTP can apply
	// the greedy/joined value reconstruction. This applies to both
	// trailing `*` and trailing `{name...}` — they share the same
	// greedy semantics. Middle `*` (the only other wildcard case left
	// after validation) intentionally does NOT set Possible; its value
	// is captured per-segment via the params slice instead.
	if lastType == typeNodeWildcard || lastType == typeNodeWildcardParam {
		current.Possible = true
	}
}

// insertPath walks the trie for `path`, creating nodes as needed, and returns
// the terminal node, the captured parameter descriptors, and the type of the
// last emitted segment.
//   - No handler is installed, so callers can also attach non-routing metadata
//     to a subtree (see Mux.scopeErrors).
func (n *node) insertPath(path string) (*node, []paramInfo, typeNode) {
	pathSegments := strings.Split(strings.TrimPrefix(path, "/"), "/")

	// ── Validation phase ─────────────────────────────────────────────
	// Reject ambiguous patterns at register time, with a clear message
	// telling the operator how to express their intent unambiguously.
	// The check is O(segments), done once, never on the request path.
	//
	// Rules:
	//   1. At most ONE `*` segment in a route. If you need multiple
	//      captures, use `{name}` for the middle ones; if you need
	//      multiple greedy captures, you've structurally misunderstood
	//      greedy semantics (it consumes the rest of the path).
	//   2. At most ONE `{name...}` segment, and it must be the trailing
	//      segment. A greedy in the middle would have nothing to
	//      backtrack against — there'd be no way for the matcher to
	//      know where to stop.
	//
	// We panic rather than return an error because Insert's signature
	// is `void` and routes are registered at startup: a bad pattern
	// here means the program is misconfigured. Failing loud at boot is
	// strictly better than silent runtime surprises (which is exactly
	// the failure mode that prompted this whole refactor in the first
	// place — see history of middle-`*` returning empty strings).
	var (
		starCount       int
		greedyCount     int
		greedyIndex     = -1
		lastNonEmptyIdx = -1
	)
	for i, seg := range pathSegments {
		if seg == "" {
			continue
		}
		lastNonEmptyIdx = i
		switch {
		case seg == "*":
			starCount++
		case isGreedyParam(seg):
			greedyCount++
			greedyIndex = i
		}
	}
	if starCount > 1 {
		panic("ada: pattern has more than one '*' segment; use '{name}' for middle captures: " + path)
	}
	if greedyCount > 1 {
		panic("ada: pattern has more than one greedy '{name...}' segment: " + path)
	}
	if greedyIndex >= 0 && greedyIndex != lastNonEmptyIdx {
		panic("ada: greedy '{name...}' must be the trailing segment: " + path)
	}

	// ── Insert phase ─────────────────────────────────────────────────
	// The trie stores full-path radix keys: consecutive static segments
	// (and their '/' separators) are compressed into a single key, so
	// request matching consumes multiple segments with one comparison.
	//
	// Anchoring rules:
	//   - Param/wildcard nodes attach at segment-start nodes; the static
	//     run before them therefore ends with the '/' separator.
	//   - A param/wildcard's Children node resumes matching AT the '/'
	//     that follows the captured segment, so static keys after a
	//     param/wildcard begin with '/'.
	//   - Interior empty segments are collapsed ("/a//b" ≡ "/a/b"), but
	//     a trailing empty segment keeps its '/' in the key: "/users/"
	//     only matches "/users/", never "/users".
	var typeNodeSegment typeNode = typeNodeSelf
	var params []paramInfo
	current := n
	var run []byte
	emitted := false // at least one non-empty segment consumed so far

	// segIdx counts EMITTED segments, i.e. it advances in lockstep with
	// ServeHTTP's segIndex, which walks the compressed trie and therefore
	// never sees the interior empty segments collapsed just below. Using
	// the raw `range` index here instead would desynchronise the two
	// numberings for any pattern containing "//" (e.g. from a
	// string-concatenated base path), and every param at or after the
	// empty segment would silently bind to nothing.
	segIdx := 0

	flush := func() {
		if len(run) > 0 {
			current = current.insertNodeTypeStatic(string(run))
			run = run[:0]
		}
	}

	for i, segment := range pathSegments {
		if segment == "" {
			if i == len(pathSegments)-1 && emitted {
				// Trailing slash is significant.
				run = append(run, '/')
				typeNodeSegment = typeNodeStatic
			}

			continue // collapse interior empty segments
		}

		if emitted {
			run = append(run, '/')
		}
		emitted = true

		typeNodeSegment = findTypeNode(segment)
		switch typeNodeSegment {
		case typeNodeStatic:
			run = append(run, segment...)
		case typeNodeWildcard:
			// Bare `*`: exposed under PathValue("*") regardless of
			// whether it's middle or trailing. Middle `*` captures one
			// segment via the params slice; trailing `*` is greedy and
			// is reconstructed from the original URL string in
			// ServeHTTP — but both share this one paramInfo entry.
			flush()
			params = append(params, paramInfo{Index: segIdx, Name: "*"})
			current = current.insertNodeTypeWildcard()
		case typeNodeWildcardParam:
			// `{name...}`: greedy NAMED trailing wildcard. Validation
			// above guarantees this only appears at the trailing
			// position. Tree shape is identical to a bare trailing
			// `*` — we reuse `insertNodeTypeWildcard` — only the
			// PathValue key differs.
			flush()
			name := segment[1 : len(segment)-4] // strip '{' and '...}'
			params = append(params, paramInfo{Index: segIdx, Name: name})
			current = current.insertNodeTypeWildcard()
		case typeNodeParam:
			flush()
			params = append(params, paramInfo{
				Index: segIdx,
				Name:  strings.Trim(segment, "{}"),
			})
			current = current.insertNodeTypeParam(segment)
		default:
			panic("unknown node type") // should never happen
		}

		segIdx++
	}

	flush()

	return current, params, typeNodeSegment
}

func (n *node) insertNodeTypeStatic(path string) *node {
	current := n
	// place every segment in a node or sub-node
	for byteIndex := 0; byteIndex < len(path); {
		char := path[byteIndex]

		if child, exists := current.getStaticChild(char); exists {
			commonLen := 0
			// find remaining on path
			remaining := path[byteIndex:]
			for commonLen < len(child.StaticKey) && commonLen < len(remaining) {
				if child.StaticKey[commonLen] == remaining[commonLen] {
					commonLen += 1
				} else {
					break
				}
			}

			// if it is inside of this node than switch to it and try to continue to find
			if commonLen == len(child.StaticKey) {
				// continue to look inside the child node
				current = child
				byteIndex += commonLen
			} else {
				// Need to split the node
				splitNode := &node{}
				splitNode.setKey(child.StaticKey[:commonLen])

				// Update existing child
				child.setKey(child.StaticKey[commonLen:])
				splitNode.setStaticChild(child.StaticKey[0], child)

				// Add new path if needed
				if commonLen < len(remaining) {
					newSuffix := remaining[commonLen:]
					newNode := &node{}
					newNode.setKey(newSuffix)

					splitNode.setStaticChild(newSuffix[0], newNode)
					current.setStaticChild(char, splitNode)

					return newNode
				}
				current.setStaticChild(char, splitNode)

				return splitNode
			}
		} else {
			// Create new node with remaining characters
			newNode := &node{}
			newNode.setKey(path[byteIndex:])
			current.setStaticChild(char, newNode)

			return newNode
		}
	}

	return current
}

func (n *node) insertNodeTypeWildcard() *node {
	// For wildcard nodes, we create a single node that can match any segment
	if n.TypeWildcard == nil {
		n.TypeWildcard = &nodeWildcard{}
	}

	// If there are no children yet, create a new child node
	if n.TypeWildcard.Children == nil {
		n.TypeWildcard.Children = &node{}
	}

	return n.TypeWildcard.Children
}

func (n *node) insertNodeTypeParam(path string) *node {
	// Extract parameter name from {paramName} format
	paramName := strings.Trim(path, "{}")

	// Create parameter node if it doesn't exist
	if n.TypeParam == nil {
		n.TypeParam = &nodeParam{
			Name: paramName,
		}
	}

	// If there are no children yet, create a new child node
	if n.TypeParam.Children == nil {
		n.TypeParam.Children = &node{}
	}

	return n.TypeParam.Children
}

func findTypeNode(part string) typeNode {
	switch {
	case part == "*":
		return typeNodeWildcard
	case isGreedyParam(part):
		// Must precede the generic '{' check below — every greedy
		// param is also a `{...}` token, but it has its own semantics
		// (match the remaining path, including slashes).
		return typeNodeWildcardParam
	case strings.Contains(part, "{"):
		return typeNodeParam
	default:
		return typeNodeStatic
	}
}

// isGreedyParam reports whether `seg` is a `{name...}` token. The
// inner name must be non-empty so we don't accidentally accept the
// degenerate `{...}` form, which would be ambiguous with a regular
// `{}` param missing its name. Greedy params are also the named
// counterpart of the trailing `*` wildcard: they always match the
// remaining path, including embedded slashes, and they can only
// appear as the last segment of a route (enforced in Insert).
func isGreedyParam(seg string) bool {
	if len(seg) < 6 { // "{x...}" is the shortest valid form
		return false
	}
	if seg[0] != '{' || !strings.HasSuffix(seg, "...}") {
		return false
	}
	// Name between '{' and '...}' must be non-empty.
	return len(seg) > 5
}

// //////////////////////////////////////////////////////////

// MethodQuery is the QUERY HTTP method, a safe and idempotent method that
// carries the query semantics in the request body. Defined in RFC 10008
// "The HTTP QUERY Method"; not yet available as a constant in net/http.
const MethodQuery = "QUERY"

type Mux struct {
	root *node

	errHandler       func(c *Context, err error)
	notFound         http.HandlerFunc
	methodNotAllowed http.HandlerFunc
	middlewares      []func(next http.Handler) http.Handler
	prefix           string

	// Pre-chained 404/405 handlers. Rebuilt whenever middlewares or the
	// custom handlers change (registration time), so the request path
	// never rebuilds the middleware chain — previously every 404/405
	// allocated len(middlewares) closures via Chain.
	notFoundChain         http.Handler
	methodNotAllowedChain http.Handler
	autoOptionsChain      http.Handler
}

func NewMux() *Mux {
	m := &Mux{
		root: &node{},
	}
	m.rebuildErrorChains()

	return m
}

// rebuildErrorChains re-composes the middleware chain around the 404, 405 and
// auto-OPTIONS handlers. Called at every mutation point (NewMux, Use, Group,
// NotFound, MethodNotAllowed) so ServeHTTP only reads the cached chains.
//
// Routing these three through the middleware chain is what makes headers set
// by middleware (CORS being the obvious one) present on the responses that
// most need them.
func (m *Mux) rebuildErrorChains() {
	notFound := m.notFound
	if notFound == nil {
		notFound = http.NotFound
	}
	m.notFoundChain = Chain(m.middlewares...)(notFound)

	methodNotAllowed := m.methodNotAllowed
	if methodNotAllowed == nil {
		methodNotAllowed = func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
	m.methodNotAllowedChain = Chain(m.middlewares...)(methodNotAllowed)

	// The Allow header varies per node, so it is written by the caller
	// before the chain runs; this terminal handler only emits the status.
	m.autoOptionsChain = Chain(m.middlewares...)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
}

// scopeErrors marks the subtree under this Mux's prefix as belonging to this
// Mux for error dispatch, so 404/405/auto-OPTIONS responses below a Group run
// that Group's middleware chain and its NotFound/MethodNotAllowed handlers.
//
// The marker is metadata on the wildcard node, not a route: it never answers a
// request, so it cannot shadow a real handler.
func (m *Mux) scopeErrors() {
	scope, _, _ := m.root.insertPath(m.prefix + "/*")
	scope.errorScope = m
}

// errorMux resolves which Mux handles an error response: the deepest scope the
// request walked through, falling back to the Mux that is serving.
func (m *Mux) errorMux(scope *Mux) *Mux {
	if scope != nil {
		return scope
	}

	return m
}

// RouteHandler lists the handler shapes the routing methods accept.
//
// Both plain net/http handlers and ada's Context-style handlers are allowed.
// Context-style handlers are bound to the Mux they are registered on, so that
// Mux's ErrorHandler receives their returned errors:
//
//	mux.GET("/a", func(w http.ResponseWriter, r *http.Request) { ... })
//	mux.GET("/b", func(c *ada.Context) error { ... })
type RouteHandler interface {
	func(http.ResponseWriter, *http.Request) |
		http.HandlerFunc |
		func(*Context) error |
		HandlerFunc
}

// resolveHandler converts any RouteHandler shape into an http.HandlerFunc.
//   - Context-style handlers are wrapped against this Mux, so ErrorHandler applies.
//   - Runs at registration time only; the request path is unaffected.
func (m *Mux) resolveHandler(handler any) http.HandlerFunc {
	switch h := handler.(type) {
	case func(http.ResponseWriter, *http.Request):
		return h
	case http.HandlerFunc:
		return h
	case func(*Context) error:
		return m.Wrap(h)
	case HandlerFunc:
		return m.Wrap(h)
	default:
		panic(fmt.Sprintf("ada: unsupported handler type %T", handler))
	}
}

// HandleWithMethod registers an http.HandlerFunc for the given method.
//   - This is the non-generic primitive: it is the method to embed in an
//     interface when abstracting over *Mux, because Go interfaces cannot
//     declare (nor be satisfied by) generic methods.
func (m *Mux) HandleWithMethod(method, path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	handlerFunc := Chain(append(m.middlewares, middlewares...)...)(handler)

	if path == "" {
		path = m.prefix
		if path == "" {
			path = "/"
		}
	} else {
		path = m.prefix + "/" + strings.TrimPrefix(path, "/")
	}

	m.root.Insert(method, path, handlerFunc.ServeHTTP)
}

func (m *Mux) GET[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodGet, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) POST[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodPost, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) PUT[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodPut, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) PATCH[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodPatch, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) DELETE[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodDelete, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) HEAD[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodHead, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) OPTIONS[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodOptions, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) TRACE[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodTrace, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) CONNECT[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodConnect, path, m.resolveHandler(any(handler)), middlewares...)
}

// QUERY registers a handler for the QUERY HTTP method, a safe and idempotent
// method with a request body carrying the query (RFC 10008).
func (m *Mux) QUERY[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(MethodQuery, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) HandleFunc[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod("", path, m.resolveHandler(any(handler)), middlewares...)
}

// HandleFuncWildcard is registering all paths under the given path.
func (m *Mux) HandleFuncWildcard[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	if path[len(path)-1] == '/' {
		path += "*"
	}

	m.HandleFunc(path, handler, middlewares...)
}

func (m *Mux) Handle(path string, handler http.Handler, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleFunc(path, handler.ServeHTTP, middlewares...)
}

// HandleWildcard is registering all paths under the given path.
func (m *Mux) HandleWildcard(path string, handler http.Handler, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleFuncWildcard(path, handler.ServeHTTP, middlewares...)
}

func (m *Mux) Use(middlewares ...func(next http.Handler) http.Handler) {
	if len(middlewares) == 0 {
		return
	}

	m.middlewares = append(m.middlewares, middlewares...)
	m.rebuildErrorChains()

	// Claim this prefix for error dispatch so the middlewares just added
	// also run on unmatched paths below it.
	m.scopeErrors()
}

func (m Mux) Group(pathGroup string, middlewares ...func(next http.Handler) http.Handler) *Mux {
	m.prefix = path.Join("/", m.prefix, pathGroup)
	if m.prefix == "/" {
		m.prefix = ""
	}

	// Defensive copy: Mux is taken by value, so m.middlewares' slice
	// header was duplicated, but it still points at the parent's backing
	// array. Without copying here, sibling groups created from the same
	// parent (`a := s.Group(); b := s.Group()`) would share that backing
	// array — and a later `b.Use(...)` could append-in-place into a slot
	// that `a` already considers part of its chain (or vice versa),
	// silently corrupting the middleware order on whichever group ran
	// `Use` first. Allocating a fresh slice with len == cap pins this
	// child group to its own storage and makes append always grow.
	parent := m.middlewares
	m.middlewares = make([]func(next http.Handler) http.Handler, len(parent), len(parent)+len(middlewares))
	copy(m.middlewares, parent)
	m.middlewares = append(m.middlewares, middlewares...)
	m.rebuildErrorChains()
	// Claim the group prefix so 404/405/OPTIONS below it run this group's
	// chain rather than the parent's.
	(&m).scopeErrors()

	return &m
}

// Prefix returns the current prefix of the Mux.
//   - Useful when giving basepath for sub-routers.
func (m *Mux) Prefix() string {
	return m.prefix
}

// NotFound sets the handler for 404 Not Found responses.
//   - If not set, it defaults to http.NotFound.
func (m *Mux) NotFound(handler http.HandlerFunc) {
	m.notFound = handler
	m.rebuildErrorChains()
	// Claim the prefix so a group's handler actually takes effect without
	// requiring an unrelated Use call first.
	m.scopeErrors()
}

func (m *Mux) notFoundHandler(w http.ResponseWriter, r *http.Request, scope *Mux) {
	// Pre-chained at registration time; no per-request chain rebuild.
	m.errorMux(scope).notFoundChain.ServeHTTP(w, r)
}

// MethodNotAllowed sets the handler for 405 Method Not Allowed responses.
//   - If not set, it defaults to a standard 405 text response.
//   - The Allow header is always set before the handler is called.
func (m *Mux) MethodNotAllowed(handler http.HandlerFunc) {
	m.methodNotAllowed = handler
	m.rebuildErrorChains()
	m.scopeErrors()
}

func (m *Mux) methodNotAllowedHandler(w http.ResponseWriter, r *http.Request, allowed string, scope *Mux) {
	w.Header().Set("Allow", allowed)

	// Pre-chained at registration time; no per-request chain rebuild.
	m.errorMux(scope).methodNotAllowedChain.ServeHTTP(w, r)
}

// buildAllowHeader returns a sorted, comma-separated list of HTTP methods
// allowed on the given node. Returns "" if the node is nil or has a catch-all
// handler (which accepts any method). HEAD is included if GET is registered.
// OPTIONS is always included when at least one method is registered.
// Called at registration time only (SetHandler caches it in node.allow).
func buildAllowHeader(n *node) string {
	if n == nil || n.catchAll != nil {
		// catch-all handler accepts any method — not a 405 case
		return ""
	}

	if len(n.entries) == 0 {
		return ""
	}

	// entries cannot contain duplicate methods (SetHandler replaces),
	// so no dedup map is needed.
	methods := make([]string, 0, len(n.entries)+2)
	var hasGet, hasHead, hasOptions bool
	for i := range n.entries {
		method := n.entries[i].method
		methods = append(methods, method)
		switch method {
		case http.MethodGet:
			hasGet = true
		case http.MethodHead:
			hasHead = true
		case http.MethodOptions:
			hasOptions = true
		}
	}

	// Auto-HEAD: if GET is registered, HEAD is implicitly available
	if hasGet && !hasHead {
		methods = append(methods, http.MethodHead)
	}

	// OPTIONS is always available when at least one method is registered
	if !hasOptions {
		methods = append(methods, http.MethodOptions)
	}

	sort.Strings(methods)

	return strings.Join(methods, ", ")
}

// ErrorHandler sets the handler for 500 Internal Server Error responses.
//   - If not set, it defaults to a generic error handler.
//   - Only usable for ada.HandlerFunc handlers.
func (m *Mux) ErrorHandler(handler func(c *Context, err error)) {
	m.errHandler = handler
}

// matchResult carries everything the dispatch half needs from the trie walk.
//
// Single-segment capture values deliberately do not live here. Once the
// winning route is known, bindPathValues derives them directly from the URL by
// segment index. This avoids per-request capture storage and stays correct when
// matching rewinds to an earlier dynamic branch.
type matchResult struct {
	// node is the terminal node the walk settled on; nil means no match.
	node *node

	// wildcard is the deepest trailing-wildcard node passed on the way
	// down. It doubles as the fallback when the more specific walk dead
	// ends, and as the anchor for the greedy capture.
	wildcard *node
	// wildcardIndex is the segment index at which wildcard was captured and
	// wildcardOffset the byte offset in the URL where its value starts.
	// The two must stay consistent so the greedy value is bound under the
	// wildcard's registered name (e.g. {p...}) and not the "*" fallback.
	wildcardIndex  int
	wildcardOffset int

	// errorScope is the deepest Group claiming error dispatch for this
	// path; nil means the serving Mux handles it.
	errorScope *Mux
}

// ServeHTTP implements the http.Handler interface for Mux.
func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var res matchResult
	m.match(r.URL.Path, &res)

	if res.node == nil {
		m.notFoundHandler(w, r, res.errorScope)

		return
	}

	// Optimization #6: use r.Method directly.
	// HTTP methods from net/http are always uppercase per RFC 7230.
	// lookupEntry resolves method → auto-HEAD (GET fallback) → catch-all.
	method := r.Method
	entry := res.node.lookupEntry(method)

	// Fallback to the wildcard handler if no handler exists for this method.
	if entry == nil && res.wildcard != nil {
		if wildcardEntry := res.wildcard.lookupEntry(method); wildcardEntry != nil {
			entry = wildcardEntry
			res.node = res.wildcard
		}
	}

	if entry == nil {
		m.dispatchNoHandler(w, r, &res, method)

		return
	}

	bindPathValues(r, &res, entry)

	// Set the route pattern (used by telemetry/log middleware) and
	// dispatch. Assigning here instead of in a per-handler wrapper
	// closure saves one indirect call on every request.
	r.Pattern = entry.pattern
	entry.handler(w, r)
}

// choicePoint records a segment start where the walk had a dynamic alternative
// it did not take, so a dead end further down the path can rewind and try it.
//
// Without this the matcher committed to the first static edge that matched a
// segment and never reconsidered, which let a static alias shadow an entire
// parameterised subtree: with /users/me and /users/{id}/posts registered,
// /users/me/posts answered 404 while every other mainstream Go router served
// the parameterised route.
type choicePoint struct {
	// node is the segment-start node holding the alternatives.
	node *node

	segStart int
	segIndex int

	// tried is the next alternative to attempt: 0 param, 1 wildcard, 2 done.
	tried uint8
}

// segmentEnd returns the offset just past the segment starting at start.
func segmentEnd(urlPath string, start int) int {
	if i := strings.IndexByte(urlPath[start:], '/'); i >= 0 {
		return start + i
	}

	return len(urlPath)
}

// match walks the full-path radix trie for urlPath and fills res.
//
// The trie stores compressed full-path keys, so one comparison can consume
// several segments. That is why segment bookkeeping is explicit:
//
//   - segStart is the byte offset where the current segment begins and
//     segIndex its ordinal. Both advance only when a key containing '/' is
//     matched in full, using the '/' metadata precomputed by setKey.
//   - segOwner is the node sitting exactly at segStart, the only place param
//     and wildcard alternatives for the current segment can live. It is nil
//     once the walk has moved past that segment.
//
// Static edges are preferred but the choice is not final. A dead end retries
// the alternatives for the segment the walk is still inside (segOwner, no
// bookkeeping needed), and otherwise rewinds to a choicePoint recorded when a
// key carried the walk past a segment that had alternatives left. A param or
// wildcard always consumes exactly one segment, so a rewind target is
// unambiguous. Termination holds because choicePoints are only pushed while
// moving forward and each offers at most two alternatives.
func (m *Mux) match(urlPath string, res *matchResult) {
	current := m.root

	pos := 0
	if len(urlPath) > 0 && urlPath[0] == '/' {
		pos = 1 // skip leading '/'
	}

	segStart := pos
	segIndex := 0

	var segOwner *node

	// Backtracking stack, kept local so it stays on the stack. Entries are
	// only pushed for segments the walk leaves behind with an alternative
	// still untried, which is rare: the common param and alias shapes
	// resolve through segOwner without touching it at all.
	var choiceBuf [8]choicePoint

	choices := choiceBuf[:0]

	for {
		if pos == segStart {
			segOwner = current

			if current.TypeWildcard != nil {
				wildcard := current.TypeWildcard.Children

				// Capture a trailing (greedy) wildcard as the fallback for
				// everything at/under this segment.
				if wildcard.Possible {
					res.wildcard = wildcard
					res.wildcardIndex = segIndex
					res.wildcardOffset = pos
				}

				// Deepest scope wins: a group takes over error dispatch
				// from its parent for everything below the group prefix.
				if wildcard.errorScope != nil {
					res.errorScope = wildcard.errorScope
				}
			}
		}

		if pos == len(urlPath) && current.IsHandlerExists() {
			break
		}

		// ── Static descent: one child hop ──
		if pos < len(urlPath) {
			if child, ok := current.getStaticChild(urlPath[pos]); ok {
				key := child.StaticKey
				if len(urlPath)-pos >= len(key) && urlPath[pos:pos+len(key)] == key {
					if sp := child.keySlashPos; sp > 0 {
						// The key carries us out of the current segment.
						// Remember its alternatives before committing.
						if segOwner != nil && (segOwner.TypeParam != nil || segOwner.TypeWildcard != nil) {
							choices = append(choices, choicePoint{
								node:     segOwner,
								segStart: segStart,
								segIndex: segIndex,
							})
						}

						segStart = pos + sp
						segIndex += child.keySlashCount
						segOwner = nil
					}

					pos += len(key)
					current = child

					continue
				}
			}
		}

		// ── Dead end ──
		// Fast path: the walk is still inside a segment whose alternatives
		// have not been tried, so no stack traffic is needed.
		if segOwner != nil {
			owner := segOwner
			segOwner = nil

			if end := segmentEnd(urlPath, segStart); end > segStart {
				var next *node

				param := owner.TypeParam != nil
				if param {
					next = owner.TypeParam.Children
				} else if owner.TypeWildcard != nil {
					next = owner.TypeWildcard.Children
				}

				if next != nil {
					// Only taking the param leaves a second alternative
					// behind, so only that case needs the stack.
					if param && owner.TypeWildcard != nil {
						choices = append(choices, choicePoint{
							node:     owner,
							segStart: segStart,
							segIndex: segIndex,
							tried:    1,
						})
					}

					current = next
					pos = end

					continue
				}
			}
		}

		// Slow path: rewind to the most recent untried alternative.
		resumed := false

		for len(choices) > 0 {
			choice := &choices[len(choices)-1]

			var next *node

			for choice.tried < 2 && next == nil {
				if choice.tried == 0 {
					if choice.node.TypeParam != nil {
						next = choice.node.TypeParam.Children
					}
				} else if choice.node.TypeWildcard != nil {
					next = choice.node.TypeWildcard.Children
				}

				choice.tried++
			}

			if next == nil {
				// Exhausted. Pop WITHOUT rewinding: the branch this point
				// led to was taken, not abandoned, so whatever it
				// discovered — a deeper greedy fallback in particular — is
				// still valid for this URL.
				choices = choices[:len(choices)-1]

				continue
			}

			// Abandon the branch tried so far and restart this segment.
			//
			// res.wildcard and res.errorScope are deliberately NOT rewound.
			// Both describe a prefix of the URL rather than the branch that
			// matched: reaching either node means the static prefix leading
			// to it matched, so it stays a legitimate fallback no matter
			// which alternative eventually wins.
			segStart = choice.segStart
			segIndex = choice.segIndex

			end := segmentEnd(urlPath, segStart)
			if end <= segStart {
				continue // a param or wildcard cannot match an empty segment
			}

			current = next
			pos = end
			segOwner = nil
			resumed = true

			break
		}

		if resumed {
			continue
		}

		// Nothing left to try: fall back to the last trailing wildcard seen.
		current = res.wildcard

		break
	}

	res.node = current
}

// dispatchNoHandler answers a request whose path was reached but which has no
// handler for its method: auto-OPTIONS, 405, or 404.
//
// All three run through the middleware chain of the deepest matching scope, so
// headers set by middleware (CORS above all) are present on exactly the
// responses that most need them.
func (m *Mux) dispatchNoHandler(w http.ResponseWriter, r *http.Request, res *matchResult, method string) {
	allowed := res.node.allow

	// Auto-OPTIONS: respond 204 with an Allow header listing the available
	// methods. The Allow value is precomputed on the node at registration.
	if allowed != "" && method == http.MethodOptions {
		w.Header().Set("Allow", allowed)
		m.errorMux(res.errorScope).autoOptionsChain.ServeHTTP(w, r)

		return
	}

	// 405: the path exists (the node has handlers) but not for this method.
	if allowed != "" {
		m.methodNotAllowedHandler(w, r, allowed, res.errorScope)

		return
	}

	m.notFoundHandler(w, r, res.errorScope)
}

// bindPathValues publishes the matched route's captures through
// r.SetPathValue.
//
// Single-segment captures are derived from the URL rather than from values
// recorded during the walk. A parameter at pattern segment i always binds URL
// segment i, because every pattern segment except a trailing greedy consumes
// exactly one URL segment. Reading them back from the path keeps them correct
// even when the winning node was reached through the greedy fallback, i.e. via
// a prefix the walk had already rewound past — recording them during the walk
// silently lost those bindings.
func bindPathValues(r *http.Request, res *matchResult, entry *methodEntry) {
	params := entry.params
	greedy := res.node.Possible

	if !greedy && len(params) == 0 {
		return
	}

	urlPath := r.URL.Path

	if greedy {
		// Reconstruct the joined value from the original path string rather
		// than allocating via strings.Join.
		value := urlPath[res.wildcardOffset:]
		if len(value) > 0 && value[0] == '/' {
			value = value[1:]
		}

		// Insert guarantees exactly one paramInfo at this index: "*" for
		// bare `*` routes and the user-supplied identifier for `{name...}`
		// routes. The fallback covers the catch-all "" method, which has no
		// params slice.
		wrote := false
		for _, p := range params {
			if p.Index == res.wildcardIndex {
				r.SetPathValue(p.Name, value)
				wrote = true
			}
		}
		if !wrote {
			r.SetPathValue("*", value)
		}
	}

	// params are appended in pattern order, so a single forward scan of the
	// URL can hand each one its segment: O(segments + params) rather than a
	// full params sweep per segment.
	pos := 0
	if len(urlPath) > 0 && urlPath[0] == '/' {
		pos = 1
	}

	for index, next := 0, 0; next < len(params); index++ {
		if greedy && params[next].Index >= res.wildcardIndex {
			break // folded into the greedy value above
		}

		end := segmentEnd(urlPath, pos)

		// Insert keeps to one paramInfo per index, but the loop does not
		// stop at the first match so future hooks registering aliases still
		// work.
		for next < len(params) && params[next].Index == index {
			r.SetPathValue(params[next].Name, urlPath[pos:end])
			next++
		}

		if end >= len(urlPath) {
			break
		}
		pos = end + 1
	}
}

// ////////////////////////////////////////////

// Chain is a utility function to chain multiple middleware functions together.
func Chain(middlewares ...func(next http.Handler) http.Handler) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}

		return next
	}
}
