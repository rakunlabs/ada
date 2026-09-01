package ada

import (
	"fmt"
	"net/http"
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

// methodEntry bundles everything needed to dispatch one method on a node: the
// handler, route pattern, and pre-computed param names. Nodes hold these in a
// small slice instead of maps — a linear scan over 1-4 entries beats map hashing
// on the hot path.
type methodEntry struct {
	method  string
	pattern string
	params  []paramInfo
	handler http.HandlerFunc
}

type node struct {
	// Possible marks a trailing (greedy) wildcard child: after reaching its
	// separator, the node can consume the entire remaining path, including an
	// empty final segment.
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

	// errorScope is the Mux whose error chains apply at and below this
	// structural prefix. If multiple Groups claim the same prefix, the most
	// recent scopeErrors call replaces this pointer for all routes below it.
	errorScope *Mux

	// allow is the pre-computed Allow header value for 405/auto-OPTIONS
	// responses. Maintained by SetHandler; "" when a catch-all handler
	// exists (any method is accepted) or no methods are registered.
	allow string
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
//     to a prefix (see Mux.scopeErrors).
func (n *node) insertPath(path string) (*node, []paramInfo, typeNode) {
	pathSegments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	segmentTypes := make([]typeNode, len(pathSegments))
	segmentNames := make([]string, len(pathSegments))

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
	//   2. At most ONE `{name...}` segment, and it must be the LAST raw
	//      segment — a trailing slash after it is rejected too. A greedy
	//      in the middle would have nothing to backtrack against —
	//      there'd be no way for the matcher to know where to stop.
	//
	// We panic rather than return an error because Insert's signature
	// is `void` and routes are registered at startup: a bad pattern
	// here means the program is misconfigured. Failing loud at boot is
	// strictly better than silent runtime surprises (which is exactly
	// the failure mode that prompted this whole refactor in the first
	// place — see history of middle-`*` returning empty strings).
	var (
		starCount   int
		greedyCount int
		greedyIndex = -1
		seenNames   = make(map[string]struct{})
	)
	for i, seg := range pathSegments {
		if seg == "" {
			continue
		}

		segmentType, name, err := parseRouteSegment(seg)
		if err != nil {
			panic("ada: invalid route pattern " + path + ": " + err.Error())
		}
		segmentTypes[i] = segmentType
		segmentNames[i] = name

		if segmentType == typeNodeParam || segmentType == typeNodeWildcardParam {
			if _, exists := seenNames[name]; exists {
				panic("ada: duplicate path parameter " + name + " in pattern: " + path)
			}
			seenNames[name] = struct{}{}
		}

		switch segmentType {
		case typeNodeWildcard:
			starCount++
		case typeNodeWildcardParam:
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
	// The greedy must be the LAST raw segment, not merely the last non-empty
	// one: a trailing slash after it ("/a/{p...}/") would demote the greedy
	// to a single-segment match followed by '/', silently contradicting the
	// pattern's stated intent. net/http.ServeMux rejects the same shape.
	if greedyIndex >= 0 && greedyIndex != len(pathSegments)-1 {
		panic("ada: greedy '{name...}' must be the trailing segment (no trailing slash): " + path)
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
	typeNodeSegment := typeNodeSelf
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

		typeNodeSegment = segmentTypes[i]
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
			name := segmentNames[i]
			params = append(params, paramInfo{Index: segIdx, Name: name})
			current = current.insertNodeTypeWildcard()
		case typeNodeParam:
			flush()
			params = append(params, paramInfo{
				Index: segIdx,
				Name:  segmentNames[i],
			})
			current = current.insertNodeTypeParam(segmentNames[i])
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

func (n *node) insertNodeTypeParam(paramName string) *node {
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
	t, _, err := parseRouteSegment(part)
	if err != nil {
		panic("ada: invalid route segment " + part + ": " + err.Error())
	}

	return t
}

// parseRouteSegment is the single grammar for registration-time validation,
// trie insertion and test/reference matchers. Braces are route syntax only
// when they wrap the entire segment; accepting a stray brace as a parameter
// silently turns static patterns such as "v{id}" into dynamic routes.
func parseRouteSegment(part string) (typeNode, string, error) {
	if part == "*" {
		return typeNodeWildcard, "*", nil
	}

	hasOpen := strings.Contains(part, "{")
	hasClose := strings.Contains(part, "}")
	if !hasOpen && !hasClose {
		return typeNodeStatic, "", nil
	}

	if len(part) < 3 || part[0] != '{' || part[len(part)-1] != '}' {
		return typeNodeSelf, "", fmt.Errorf("braces must wrap a complete path segment %q", part)
	}

	name := part[1 : len(part)-1]
	if strings.ContainsAny(name, "{}") {
		return typeNodeSelf, "", fmt.Errorf("path parameter contains a brace in %q", part)
	}

	if strings.HasSuffix(name, "...") {
		name = strings.TrimSuffix(name, "...")
		if name == "" {
			return typeNodeSelf, "", fmt.Errorf("greedy path parameter has no name in %q", part)
		}
		if name == "*" {
			return typeNodeSelf, "", fmt.Errorf("path parameter name '*' is reserved in %q", part)
		}

		return typeNodeWildcardParam, name, nil
	}

	if name == "" {
		return typeNodeSelf, "", fmt.Errorf("path parameter has no name in %q", part)
	}
	if name == "*" {
		return typeNodeSelf, "", fmt.Errorf("path parameter name '*' is reserved in %q", part)
	}

	return typeNodeParam, name, nil
}

// isGreedyParam reports whether `seg` is a `{name...}` token. The
// inner name must be non-empty so we don't accidentally accept the
// degenerate `{...}` form, which would be ambiguous with a regular
// `{}` param missing its name. Greedy params are also the named
// counterpart of the trailing `*` wildcard: they match a non-empty
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
