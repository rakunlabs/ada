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

type node struct {
	Segment  *node
	Possible bool

	// Inlined static trie fields (replaces *nodeStatic).
	// StaticKey is the compressed radix label for this node.
	// StaticChildren is a sorted slice of children keyed by first byte.
	StaticKey      string
	StaticChildren []staticChild

	TypeWildcard *nodeWildcard
	TypeParam    *nodeParam

	MethodHandler map[string]http.HandlerFunc
	Handler       http.HandlerFunc

	// Path of the node, used for telemetry.
	Path string

	// Params holds per-method pre-computed param names.
	// Key "" is used for the catch-all (no method) handler.
	Params map[string][]paramInfo
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
	if n.Handler != nil || len(n.MethodHandler) > 0 {
		return true
	}

	return false
}

func (n *node) FindNode(path string, r *http.Request) (*node, typeNode) {
	if path == "" {
		if n.IsHandlerExists() {
			return n, 0
		}

		return nil, 0
	}

	if len(n.StaticChildren) > 0 {
		current := n
		isFound := true

		for i := 0; i < len(path); {
			char := path[i]
			child, ok := current.getStaticChild(char)
			if !ok {
				isFound = false

				break
			}

			remaining := path[i:]
			childKey := child.StaticKey
			if len(remaining) < len(childKey) || remaining[:len(childKey)] != childKey {
				isFound = false

				break
			}

			i += len(childKey)
			current = child
		}

		if isFound {
			return current, typeNodeStatic
		}
	}

	// Check for parameter nodes - they match any segment and capture the value
	if n.TypeParam != nil && path != "" {
		return n.TypeParam.Children, typeNodeParam
	}

	// Check for wildcard nodes - they match any remaining path
	if n.TypeWildcard != nil {
		return n.TypeWildcard.Children, typeNodeWildcard
	}

	return nil, 0
}

func (n *node) SetHandler(method, path string, handler http.HandlerFunc, params []paramInfo) {
	n.Path = path // Store the path template for telemetry

	handlerAssign := func(w http.ResponseWriter, r *http.Request) {
		r.Pattern = path // Set the pattern
		handler(w, r)
	}

	if n.Params == nil {
		n.Params = make(map[string][]paramInfo)
	}
	n.Params[method] = params

	if method == "" {
		n.Handler = handlerAssign

		return
	}

	if n.MethodHandler == nil {
		n.MethodHandler = make(map[string]http.HandlerFunc)
	}

	n.MethodHandler[method] = handlerAssign
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
	var typeNodeSegment typeNode
	var params []paramInfo
	current := n
	for i, segment := range pathSegments {
		if segment == "" {
			continue // skip empty segments
		}

		typeNodeSegment = findTypeNode(segment)
		switch typeNodeSegment {
		case typeNodeStatic:
			current = current.insertNodeTypeStatic(segment)
		case typeNodeWildcard:
			// Bare `*`: exposed under PathValue("*") regardless of
			// whether it's middle or trailing. Middle `*` captures one
			// segment via the params slice; trailing `*` is greedy and
			// is reconstructed from the original URL string in
			// ServeHTTP — but both share this one paramInfo entry.
			params = append(params, paramInfo{Index: i, Name: "*"})
			current = current.insertNodeTypeWildcard()
		case typeNodeWildcardParam:
			// `{name...}`: greedy NAMED trailing wildcard. Validation
			// above guarantees this only appears at the trailing
			// position. Tree shape is identical to a bare trailing
			// `*` — we reuse `insertNodeTypeWildcard` — only the
			// PathValue key differs.
			name := segment[1 : len(segment)-4] // strip '{' and '...}'
			params = append(params, paramInfo{Index: i, Name: name})
			current = current.insertNodeTypeWildcard()
		case typeNodeParam:
			params = append(params, paramInfo{
				Index: i,
				Name:  strings.Trim(segment, "{}"),
			})
			current = current.insertNodeTypeParam(segment)
		default:
			panic("unknown node type") // should never happen
		}

		if i != len(pathSegments)-1 {
			if current.Segment != nil {
				current = current.Segment
			} else {
				current.Segment = &node{}
				current = current.Segment
			}
		}
	}

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
				splitNode := &node{
					StaticKey: child.StaticKey[:commonLen],
				}

				// Update existing child
				child.StaticKey = child.StaticKey[commonLen:]
				splitNode.setStaticChild(child.StaticKey[0], child)

				// Add new path if needed
				if commonLen < len(remaining) {
					newSuffix := remaining[commonLen:]
					newNode := &node{
						StaticKey: newSuffix,
					}

					splitNode.setStaticChild(newSuffix[0], newNode)
					current.setStaticChild(char, splitNode)

					return newNode
				}
				current.setStaticChild(char, splitNode)

				return splitNode
			}
		} else {
			// Create new node with remaining characters
			newNode := &node{
				StaticKey: path[byteIndex:],
			}
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
}

func NewMux() *Mux {
	return &Mux{
		root: &node{},
	}
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

	// Register a wildcard handler to catch all requests under this prefix
	// This allows middlewares to intercept requests even for unregistered routes
	m.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
		m.notFoundHandler(w, r)
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
}

func (m *Mux) notFoundHandler(w http.ResponseWriter, r *http.Request) {
	notFound := m.notFound
	if notFound == nil {
		notFound = http.NotFound
	}

	// Call the not found handler with middlewares applied
	Chain(m.middlewares...)(notFound).ServeHTTP(w, r)
}

// MethodNotAllowed sets the handler for 405 Method Not Allowed responses.
//   - If not set, it defaults to a standard 405 text response.
//   - The Allow header is always set before the handler is called.
func (m *Mux) MethodNotAllowed(handler http.HandlerFunc) {
	m.methodNotAllowed = handler
}

func (m *Mux) methodNotAllowedHandler(w http.ResponseWriter, r *http.Request, allowed string) {
	w.Header().Set("Allow", allowed)

	handler := m.methodNotAllowed
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}

	Chain(m.middlewares...)(handler).ServeHTTP(w, r)
}

// buildAllowHeader returns a sorted, comma-separated list of HTTP methods
// allowed on the given node. Returns "" if the node is nil or has a catch-all
// handler (which accepts any method). HEAD is included if GET is registered.
// OPTIONS is always included when at least one method is registered.
func buildAllowHeader(n *node) string {
	if n == nil || n.Handler != nil {
		// catch-all handler accepts any method — not a 405 case
		return ""
	}

	if len(n.MethodHandler) == 0 {
		return ""
	}

	seen := make(map[string]struct{}, len(n.MethodHandler)+2)
	for method := range n.MethodHandler {
		seen[method] = struct{}{}
	}

	// Auto-HEAD: if GET is registered, HEAD is implicitly available
	if _, hasGet := seen[http.MethodGet]; hasGet {
		seen[http.MethodHead] = struct{}{}
	}

	// OPTIONS is always available when at least one method is registered
	seen[http.MethodOptions] = struct{}{}

	methods := make([]string, 0, len(seen))
	for method := range seen {
		methods = append(methods, method)
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

	// Walk the path in-place without allocating a []string slice.
	// We iterate character-by-character, finding '/' delimiters.
	segmentIndex := 0
	pos := 1 // skip leading '/'
	if len(urlPath) == 0 || urlPath[0] != '/' {
		pos = 0
	}

	for pos <= len(urlPath) {
		// Find the end of the current segment.
		end := strings.IndexByte(urlPath[pos:], '/')
		var segment string
		if end < 0 {
			segment = urlPath[pos:]
			end = len(urlPath)
		} else {
			segment = urlPath[pos : pos+end]
			end = pos + end
		}

		isLast := end >= len(urlPath)

		if current.TypeWildcard != nil && current.TypeWildcard.Children.Possible {
			possible = current.TypeWildcard.Children
			possibleIndex = segmentIndex
			possibleOffset = pos
		}

		// Find the type of the node.
		nd, nodeType := current.FindNode(segment, r)
		if nd == nil {
			current = possible
			break
		}

		// Capture this segment's value for the binding loop at the
		// end of ServeHTTP. Both single-segment params (`{id}`) and
		// wildcards (bare `*`) record a single-segment value here.
		// Trailing wildcards also flow through this branch but their
		// per-segment value is later superseded by the greedy joined
		// reconstruction (see `current.Possible` block at the bottom)
		// — the pathPattern entry is skipped by the `possibleIndex`
		// guard in the binding loop, so this isn't a double write.
		//
		// Greedy named wildcards (`{name...}`) are matched as
		// `typeNodeWildcard` here too because they share the same
		// trie branch; the name distinction lives in the params slice.
		if nodeType == typeNodeParam || nodeType == typeNodeWildcard {
			pathPattern = append(pathPattern, indexValue{
				index: segmentIndex,
				value: segment,
			})
		}

		if !isLast {
			if nd.Possible {
				possible = nd
				// Note: possibleOffset is NOT updated here. It stays at the value
				// from the top-of-loop wildcard check, which is the correct byte
				// position for reconstructing the wildcard path value.
			}

			if nd.Segment == nil {
				current = possible
				possibleIndex = segmentIndex
				break
			}

			current = nd.Segment
		} else {
			if nd.IsHandlerExists() {
				current = nd
			} else {
				current = possible
			}
		}

		pos = end + 1
		segmentIndex++
	}

	if current == nil {
		m.notFoundHandler(w, r)
		return
	}

	// Optimization #6: use r.Method directly.
	// HTTP methods from net/http are always uppercase per RFC 7230.
	method := r.Method
	handler := current.MethodHandler[method]

	// Auto-HEAD: if HEAD is requested and no explicit HEAD handler exists,
	// fall back to the GET handler. Go's http.ResponseWriter automatically
	// suppresses the body for HEAD responses.
	if handler == nil && method == http.MethodHead {
		handler = current.MethodHandler[http.MethodGet]
	}

	if handler == nil {
		handler = current.Handler
	}

	// Fallback to wildcard handler if specific method handler not found.
	if handler == nil && possible != nil {
		handler = possible.MethodHandler[method]
		if handler == nil && method == http.MethodHead {
			handler = possible.MethodHandler[http.MethodGet]
		}
		if handler == nil {
			handler = possible.Handler
		}
		if handler != nil {
			current = possible
		}
	}

	// Auto-OPTIONS: if OPTIONS is requested and no explicit handler exists,
	// respond with 204 No Content and an Allow header listing available methods.
	if handler == nil && method == http.MethodOptions {
		if allowed := buildAllowHeader(current); allowed != "" {
			w.Header().Set("Allow", allowed)
			w.WriteHeader(http.StatusNoContent)

			return
		}
	}

	// 405 Method Not Allowed: the path exists (node has handlers) but not
	// for the requested method.
	if handler == nil {
		if allowed := buildAllowHeader(current); allowed != "" {
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
		// Look up the pre-computed param names for this method (or
		// catch-all ""). Hoisted so both the trailing-wildcard
		// reconstruction and the per-segment binding loop reuse it.
		params := current.Params[method]
		if params == nil {
			params = current.Params[""]
		}

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

	handler.ServeHTTP(w, r)
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
	name  string
	value string
}
