package ada

import (
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
			params = append(params, paramInfo{Index: i, Name: "*"})
			current = current.insertNodeTypeWildcard()
		case typeNodeWildcardParam:
			// `{name...}`: greedy NAMED trailing wildcard. Validation
			// above guarantees this only appears at the trailing
			// position. Tree shape is identical to a bare trailing
			// `*` — we reuse `insertNodeTypeWildcard` — only the
			// PathValue key differs.
			flush()
			name := segment[1 : len(segment)-4] // strip '{' and '...}'
			params = append(params, paramInfo{Index: i, Name: name})
			current = current.insertNodeTypeWildcard()
		case typeNodeParam:
			flush()
			params = append(params, paramInfo{
				Index: i,
				Name:  strings.Trim(segment, "{}"),
			})
			current = current.insertNodeTypeParam(segment)
		default:
			panic("unknown node type") // should never happen
		}
	}

	flush()

	current.SetHandler(method, path, handler, params)
	// Possible marks "trailing wildcard reached" so ServeHTTP can apply
	// the greedy/joined value reconstruction. This applies to both
	// trailing `*` and trailing `{name...}` — they share the same
	// greedy semantics. Middle `*` (the only other wildcard case left
	// after validation) intentionally does NOT set Possible; its value
	// is captured per-segment via the params slice instead.
	if typeNodeSegment == typeNodeWildcard || typeNodeSegment == typeNodeWildcardParam {
		current.Possible = true
	}
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
}

func NewMux() *Mux {
	m := &Mux{
		root: &node{},
	}
	m.rebuildErrorChains()

	return m
}

// rebuildErrorChains re-composes the middleware chain around the 404 and
// 405 handlers. Called at every mutation point (NewMux, Use, Group,
// NotFound, MethodNotAllowed) so ServeHTTP only reads the cached chains.
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
}

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

func (m *Mux) GET(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodGet, path, handler, middlewares...)
}

func (m *Mux) POST(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodPost, path, handler, middlewares...)
}

func (m *Mux) PUT(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodPut, path, handler, middlewares...)
}

func (m *Mux) PATCH(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodPatch, path, handler, middlewares...)
}

func (m *Mux) DELETE(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodDelete, path, handler, middlewares...)
}

func (m *Mux) HEAD(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodHead, path, handler, middlewares...)
}

func (m *Mux) OPTIONS(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodOptions, path, handler, middlewares...)
}

func (m *Mux) TRACE(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodTrace, path, handler, middlewares...)
}

func (m *Mux) CONNECT(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodConnect, path, handler, middlewares...)
}

// QUERY registers a handler for the QUERY HTTP method, a safe and idempotent
// method with a request body carrying the query (RFC 10008).
func (m *Mux) QUERY(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(MethodQuery, path, handler, middlewares...)
}

func (m *Mux) HandleFunc(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod("", path, handler, middlewares...)
}

// HandleFuncWildcard is registering all paths under the given path.
func (m *Mux) HandleFuncWildcard(path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
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

	// Register a wildcard handler to catch all requests under this prefix.
	// This allows middlewares to intercept requests even for unregistered
	// routes. HandleFunc already wraps the handler with the middleware
	// chain at registration time, so the handler must call the RAW not
	// found handler — going through notFoundHandler here would apply the
	// middlewares a second time.
	m.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
		notFound := m.notFound
		if notFound == nil {
			notFound = http.NotFound
		}

		notFound(w, r)
	})
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
}

func (m *Mux) notFoundHandler(w http.ResponseWriter, r *http.Request) {
	// Pre-chained at registration time; no per-request chain rebuild.
	m.notFoundChain.ServeHTTP(w, r)
}

// MethodNotAllowed sets the handler for 405 Method Not Allowed responses.
//   - If not set, it defaults to a standard 405 text response.
//   - The Allow header is always set before the handler is called.
func (m *Mux) MethodNotAllowed(handler http.HandlerFunc) {
	m.methodNotAllowed = handler
	m.rebuildErrorChains()
}

func (m *Mux) methodNotAllowedHandler(w http.ResponseWriter, r *http.Request, allowed string) {
	w.Header().Set("Allow", allowed)

	// Pre-chained at registration time; no per-request chain rebuild.
	m.methodNotAllowedChain.ServeHTTP(w, r)
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

// ServeHTTP implements the http.Handler interface for Mux.
func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path
	current := m.root
	var possible *node
	var possibleIndex int
	var possibleOffset int // byte offset in urlPath for wildcard reconstruction

	pathPattern := make([]indexValue, 0, 4)

	// Walk the path byte-wise over the full-path radix trie: one key
	// comparison can consume several segments. Segment bookkeeping
	// (segStart/segIndex) only advances when a key containing '/' is
	// fully matched; param/wildcard alternatives are anchored at
	// segment-start nodes and are consulted on static dead ends.
	pos := 0
	if len(urlPath) > 0 && urlPath[0] == '/' {
		pos = 1 // skip leading '/'
	}

	segStart := pos // byte offset where the current segment starts
	segIndex := 0   // index of the current segment
	// segOwner is the node positioned exactly at segStart — the only
	// place param/wildcard alternatives for the current segment can
	// live. nil when the current segment started inside a compressed
	// key (no node there ⇒ no alternatives, by construction).
	var segOwner *node

	for {
		if pos == segStart {
			segOwner = current

			// Capture a trailing (greedy) wildcard as the fallback for
			// everything at/under this segment.
			if current.TypeWildcard != nil && current.TypeWildcard.Children.Possible {
				possible = current.TypeWildcard.Children
				possibleIndex = segIndex
				possibleOffset = pos
			}
		}

		if pos == len(urlPath) {
			if !current.IsHandlerExists() {
				current = possible
			}

			break
		}

		// ── Static descent: one child hop ──
		q := pos // first diverging byte on failure
		var keyByte byte
		hasKeyByte := false
		if child, ok := current.getStaticChild(urlPath[pos]); ok {
			key := child.StaticKey
			if len(urlPath)-pos >= len(key) && urlPath[pos:pos+len(key)] == key {
				// Full key match: advance, updating segment bookkeeping
				// when the key crosses '/' boundaries. The '/' metadata
				// is pre-computed at registration time (setKey).
				if sp := child.keySlashPos; sp > 0 {
					segStart = pos + sp
					segIndex += child.keySlashCount
					if sp != len(key) {
						// The new segment started inside this key — no
						// node sits at its start, so no alternatives
						// exist there.
						segOwner = nil
					}
				}
				pos += len(key)
				current = child

				continue
			}

			// Cold path (mismatch): locate the first diverging byte.
			maxCmp := len(key)
			if rem := len(urlPath) - pos; rem < maxCmp {
				maxCmp = rem
			}
			for q-pos < maxCmp && urlPath[q] == key[q-pos] {
				q++
			}
			if q-pos < len(key) {
				keyByte = key[q-pos]
				hasKeyByte = true
			}
		}

		// ── Static dead end: classify against the current segment ──
		e := strings.IndexByte(urlPath[segStart:], '/')
		if e < 0 {
			e = len(urlPath)
		} else {
			e += segStart
		}

		// The failure is "inside" the current segment when static
		// matching could not consume the segment entirely (q < e), or
		// when it consumed it but the key demands more in-segment bytes
		// (q == e with a non-'/' key byte, e.g. path "user" vs key
		// "users"). Only then do param/wildcard alternatives apply —
		// mirroring the per-segment matcher: a fully static-matched
		// segment is committed and never re-tried (no backtracking).
		inSegment := q < e || (q == e && hasKeyByte && keyByte != '/')
		if inSegment && segOwner != nil && e > segStart {
			var next *node
			if segOwner.TypeParam != nil {
				next = segOwner.TypeParam.Children
			} else if segOwner.TypeWildcard != nil {
				next = segOwner.TypeWildcard.Children
			}

			if next != nil {
				// Capture the segment value for the binding loop.
				// Trailing wildcards flow through here too; their
				// per-segment value is superseded by the greedy joined
				// reconstruction (possibleIndex guard in the binding
				// loop skips it).
				pathPattern = append(pathPattern, indexValue{
					index: segIndex,
					value: urlPath[segStart:e],
				})
				current = next
				pos = e // resume at the '/' (or end of path)
				segOwner = nil

				continue
			}
		}

		// Fall back to the last trailing wildcard seen (or 404).
		// possibleIndex and possibleOffset keep the values from the
		// segment where the wildcard was captured — they must stay
		// consistent so the greedy value is bound under the wildcard's
		// registered name (e.g. {p...}), not the "*" fallback.
		current = possible

		break
	}

	if current == nil {
		m.notFoundHandler(w, r)
		return
	}

	// Optimization #6: use r.Method directly.
	// HTTP methods from net/http are always uppercase per RFC 7230.
	// lookupEntry resolves method → auto-HEAD (GET fallback) → catch-all.
	method := r.Method
	entry := current.lookupEntry(method)

	// Fallback to wildcard handler if specific method handler not found.
	if entry == nil && possible != nil {
		entry = possible.lookupEntry(method)
		if entry != nil {
			current = possible
		}
	}

	// Auto-OPTIONS: if OPTIONS is requested and no explicit handler exists,
	// respond with 204 No Content and an Allow header listing available methods.
	// The Allow value is pre-computed on the node at registration time.
	if entry == nil && method == http.MethodOptions {
		if allowed := current.allow; allowed != "" {
			w.Header().Set("Allow", allowed)
			w.WriteHeader(http.StatusNoContent)

			return
		}
	}

	// 405 Method Not Allowed: the path exists (node has handlers) but not
	// for the requested method.
	if entry == nil {
		if allowed := current.allow; allowed != "" {
			m.methodNotAllowedHandler(w, r, allowed)

			return
		}

		m.notFoundHandler(w, r)

		return
	}

	// Param/wildcard binding is only entered when we have something to
	// bind: a trailing wildcard (current.Possible) or one or more
	// captured param/wildcard segments (len(pathPattern) > 0). Pure
	// static routes skip the entire block — including the params-map
	// lookup — so they pay zero binding cost. Static routes are the
	// dominant case for most APIs, and the original code already
	// relied on this short-circuit; we preserve it.
	if current.Possible || len(pathPattern) > 0 {
		// The pre-computed param names live on the resolved entry —
		// no map lookup needed. Hoisted so both the trailing-wildcard
		// reconstruction and the per-segment binding loop reuse it.
		params := entry.params

		if current.Possible {
			// Trailing wildcard: reconstruct the greedy joined value
			// from the original path string without allocating via
			// strings.Join.
			wildcard := urlPath[possibleOffset:]
			if len(wildcard) > 0 && wildcard[0] == '/' {
				wildcard = wildcard[1:]
			}
			// Write the greedy value under the trailing wildcard's
			// registered name. Insert guarantees there's exactly one
			// paramInfo at this index: `"*"` for bare `*` routes and
			// the user-supplied identifier for `{name...}` routes.
			// The defensive fallback catches the catch-all "" method
			// case (no params slice for that method key).
			wrote := false
			for _, p := range params {
				if p.Index == possibleIndex {
					r.SetPathValue(p.Name, wildcard)
					wrote = true
				}
			}
			if !wrote {
				r.SetPathValue("*", wildcard)
			}
		}

		for _, v := range pathPattern {
			if current.Possible && possibleIndex <= v.index {
				// This segment is part of the trailing-wildcard's
				// greedy capture; the reconstruction block above has
				// already written it under its registered name.
				continue
			}

			// Single-segment params and middle wildcards: write each
			// captured value under its registered name. Insert keeps
			// to one paramInfo per index, but we don't `break` after
			// the first match so future hooks that register multiple
			// aliases (e.g. compat shims) can still work.
			for _, p := range params {
				if p.Index == v.index {
					r.SetPathValue(p.Name, v.value)
				}
			}
		}
	}

	// Set the route pattern (used by telemetry/log middleware) and
	// dispatch. Assigning here instead of in a per-handler wrapper
	// closure saves one indirect call on every request.
	r.Pattern = entry.pattern
	entry.handler(w, r)
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

// ////////////////////////////////////////////

type indexValue struct {
	index int
	value string
}
