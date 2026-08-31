package ada

import (
	"net/http"
	"sort"
	"strings"
)

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

// anyMethod is not a valid HTTP request method. Callers that only ask whether
// a path is reachable at all pass it to matchMethod to mean "any registered
// handler terminates the walk".
const anyMethod = ""

// fallbackEntry resolves what lookupEntry does beyond an exact method hit: the
// auto-HEAD fallback to GET, the catch-all handler, and the anyMethod probe.
// It preserves lookupEntry's precedence, so the walk and dispatch answer the
// same question.
//
// The split exists for the matching loop. Inlining all of lookupEntry into the
// loop's terminal test nearly doubled the walk's code (1.9KB -> 3.6KB) and
// slowed every lookup, while routing the whole test through one outlined call
// cost a function call on the hot path. Splitting it leaves the common case —
// the request method is registered on the node — as a single inlined scan with
// no call at all, and pays for a call only where that scan comes up empty.
func (n *node) fallbackEntry(method string, probe bool) *methodEntry {
	if method == http.MethodHead {
		if entry := n.lookupMethod(http.MethodGet); entry != nil {
			return entry
		}
	}

	if n.catchAll != nil {
		return n.catchAll
	}

	if probe && len(n.entries) > 0 {
		return &n.entries[0]
	}

	return nil
}

// matchEntry is fallbackEntry's fully-outlined counterpart, for the call sites
// where the extra inlined scan is not worth the code it adds.
func (n *node) matchEntry(method string, probe bool) *methodEntry {
	if entry := n.lookupMethod(method); entry != nil {
		return entry
	}

	return n.fallbackEntry(method, probe)
}

// matchResult carries everything the dispatch half needs from the trie walk.
//
// Single-segment capture values deliberately do not live here. Once the
// winning route is known, bindPathValues derives them directly from the URL by
// segment index. This avoids per-request capture storage and stays correct when
// matching rewinds to an earlier dynamic branch.
//
// It is zeroed on every request, so it carries only what has to cross the
// match/dispatch boundary and nothing else. The request method is a parameter
// rather than a field, the trailing-wildcard node and its entry are locals
// inside matchMethod, and the error scope is a dispatchNoHandler argument. All
// three were fields at one point, and the extra zeroing measured worse than
// the method check this whole fix added.
type matchResult struct {
	// node is the terminal node the walk settled on; nil means no route
	// serves this method on this path.
	node *node
	// entry is the handler resolved on node for the request method. nil
	// means the request is a 404 or a 405; pathAllow tells the two apart.
	entry *methodEntry

	// wildcardIndex is the segment index at which the winning greedy
	// wildcard was captured and wildcardOffset the byte offset in the URL
	// where its value starts. The two must stay consistent so the greedy
	// value is bound under the wildcard's registered name (e.g. {p...}) and
	// not the "*" fallback. Both are meaningless unless node.Possible.
	wildcardIndex  int
	wildcardOffset int
}

// ServeHTTP implements the http.Handler interface for Mux.
func (m *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// One snapshot for the whole request: a route added or removed midway
	// through must not change which tree this request is being matched
	// against.
	root := m.routes.load()

	var res matchResult

	// Optimization #6: use r.Method directly. HTTP methods from net/http
	// are always uppercase per RFC 7230. Route selection resolves it
	// itself, so a node that matches the path but not the method does not
	// end the search.
	m.matchMethod(root, r.Method, r.URL.Path, &res)

	entry := res.entry
	if entry == nil {
		m.dispatchNoHandler(w, r, root, matchErrorScope(root, r.URL.Path))

		return
	}

	bindPathValues(r, &res, entry)

	// Set the route pattern (used by telemetry/log middleware) and
	// dispatch. Assigning here instead of in a per-handler wrapper
	// closure saves one indirect call on every request.
	r.Pattern = entry.pattern
	entry.handler(w, r)
}

// matchErrorScope finds the deepest Group prefix matching urlPath. At equal
// depths, traversal order preserves route precedence: static, then param, then
// wildcard. It runs only after handler lookup fails, so considering scopes on
// alternative branches cannot change successful route selection.
func matchErrorScope(root *node, urlPath string) *Mux {
	pos := 0
	if len(urlPath) > 0 && urlPath[0] == '/' {
		pos = 1
	}

	bestPos := -1
	var best *Mux

	var walk func(current *node, pos int)
	walk = func(current *node, pos int) {
		atBoundary := current == root || pos == len(urlPath) || urlPath[pos] == '/'
		if current.errorScope != nil && atBoundary && pos > bestPos {
			best = current.errorScope
			bestPos = pos
		}

		if pos >= len(urlPath) {
			return
		}

		// Explore in route-precedence order. A later branch replaces the
		// current choice only when it reaches a strictly deeper scope.
		if child, ok := current.getStaticChild(urlPath[pos]); ok {
			key := child.StaticKey
			if len(urlPath)-pos >= len(key) && urlPath[pos:pos+len(key)] == key {
				walk(child, pos+len(key))
			}
		}

		end := segmentEnd(urlPath, pos)
		if end <= pos {
			return
		}

		if current.TypeParam != nil {
			walk(current.TypeParam.Children, end)
		}
		if current.TypeWildcard != nil {
			walk(current.TypeWildcard.Children, end)
		}
	}

	walk(root, pos)

	return best
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

// match resolves urlPath without constraining the method: any registered
// handler terminates the walk. It answers "is this path reachable in this
// snapshot at all", which is what route-table introspection wants; request
// dispatch goes through matchMethod.
func (m *Mux) match(root *node, urlPath string, res *matchResult) {
	m.matchMethod(root, anyMethod, urlPath, res)
}

// matchMethod walks the full-path radix trie for urlPath and fills res with the
// route that serves method.
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
//
// The walk is method-aware: "matched the path but has no handler for this
// method" is a dead end like any other, so it keeps backtracking instead of
// committing. Stopping at the first node with any handler let a static route
// registered under one method shadow the param/wildcard alternative that could
// have served the request — /a/b registered POST-only answered 405 for
// GET /a/b even with GET /a/{id} registered. Selection precedence is
// unchanged whenever more than one candidate can serve the method: static is
// still tried before param before wildcard, and the greedy fallback is still
// consulted only after every alternative is exhausted.
func (m *Mux) matchMethod(root *node, method, urlPath string, res *matchResult) {
	current := root

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

	// Hoisted out of the loop: whether this is an anyMethod reachability
	// probe rather than a real request.
	probe := method == anyMethod

	// The last trailing wildcard passed that can serve the method, and the
	// entry it qualified on. Locals rather than result fields: only the
	// walk consults them, and every field costs zeroing on every request.
	var (
		wildcardNode  *node
		wildcardEntry *methodEntry
	)

	for {
		if pos == segStart {
			segOwner = current

			if current.TypeWildcard != nil {
				wildcard := current.TypeWildcard.Children

				// Capture a trailing (greedy) wildcard as the fallback for
				// everything at/under this segment.
				//
				// Only one that can serve the request method is worth
				// keeping. The fallback is consulted after every
				// alternative is exhausted, so remembering a greedy that
				// cannot answer would turn the request into a 405 while a
				// shallower greedy that can answer is still on offer.
				if wildcard.Possible && pos < len(urlPath) && urlPath[pos] != '/' {
					if entry := wildcard.matchEntry(method, probe); entry != nil {
						wildcardNode = wildcard
						wildcardEntry = entry
						res.wildcardIndex = segIndex
						res.wildcardOffset = pos
					}
				}
			}
		}

		// A node that matches the path but cannot serve the method is a
		// dead end, not a match: falling through here is what sends the
		// walk back into the param and wildcard alternatives behind it.
		if pos == len(urlPath) {
			// lookupMethod is inlined here; everything it does not cover
			// is one call away. See fallbackEntry.
			entry := current.lookupMethod(method)
			if entry == nil {
				entry = current.fallbackEntry(method, probe)
			}

			if entry != nil {
				res.entry = entry

				break
			}
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
			// wildcardNode is deliberately NOT rewound. It describes a prefix
			// of the URL rather than the branch that matched, so it stays a
			// legitimate fallback no matter which alternative eventually wins.
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

		// Nothing left to try: fall back to the last trailing wildcard that
		// could serve this method, along with the entry it qualified on.
		current = wildcardNode
		res.entry = wildcardEntry

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
// scope is the deepest Group prefix the request walked through; nil means the
// serving Mux handles the error.
func (m *Mux) dispatchNoHandler(w http.ResponseWriter, r *http.Request, root *node, scope *Mux) {
	// Route selection is method-aware, so getting here means no node that
	// matches the path can serve the method. Which of the two answers is
	// owed depends on whether any node matches the path at all, and the
	// Allow header is the union over every one of them — a second,
	// exhaustive walk the successful path never pays for.
	allowed := pathAllow(root, r.URL.Path)

	// Auto-OPTIONS: respond 204 with an Allow header listing the available
	// methods. Each node's portion is precomputed at registration; the
	// candidates that match this path are merged here.
	if allowed != "" && r.Method == http.MethodOptions {
		w.Header().Set("Allow", allowed)
		m.errorMux(scope).autoOptionsChain.ServeHTTP(w, r)

		return
	}

	// 405: the path exists (some node has handlers) but not for this method.
	if allowed != "" {
		m.methodNotAllowedHandler(w, r, allowed, scope)

		return
	}

	m.notFoundHandler(w, r, scope)
}

// pathAllow returns the Allow header for a path no route could serve: the
// sorted, deduplicated union of the methods registered on every node that
// matches the path, regardless of method. "" means the path matches nothing,
// i.e. a 404 rather than a 405.
//
// Route selection stops at the first node that can serve the request, so it
// never enumerates the alternatives. This walk does, which is why it is kept
// off the hot path and runs only once dispatch has already failed. It is
// written without closures so a miss costs no allocation, and the per-node
// values it unions are the ones buildAllowHeader cached at registration —
// implicit HEAD and OPTIONS included.
func pathAllow(root *node, urlPath string) string {
	pos := 0
	if len(urlPath) > 0 && urlPath[0] == '/' {
		pos = 1
	}

	// A path rarely has more than a couple of candidates, so the collection
	// buffer lives on the stack: the walk stays allocation-free for the 404
	// case and for the single-candidate 405 that dominates in practice.
	var buf [4]string

	allows := collectAllow(root, urlPath, pos, buf[:0])
	switch len(allows) {
	case 0:
		return ""
	case 1:
		return allows[0]
	}

	return mergeAllow(allows)
}

// collectAllow appends the cached Allow value of every node matching urlPath
// from current at pos onwards. It mirrors match's traversal, minus the method
// test and minus the early exit, so it sees exactly the candidate set match
// would have had to reject.
func collectAllow(current *node, urlPath string, pos int, allows []string) []string {
	if pos == len(urlPath) {
		return appendAllow(allows, current)
	}

	// A trailing wildcard anchored here swallows the whole remainder, so it
	// is a candidate without any further descent. Wildcards only attach to
	// segment-start nodes, which is what makes the '/' test below the same
	// boundary check match performs.
	if current.TypeWildcard != nil {
		if greedy := current.TypeWildcard.Children; greedy.Possible && urlPath[pos] != '/' {
			allows = appendAllow(allows, greedy)
		}
	}

	if child, ok := current.getStaticChild(urlPath[pos]); ok {
		key := child.StaticKey
		if len(urlPath)-pos >= len(key) && urlPath[pos:pos+len(key)] == key {
			allows = collectAllow(child, urlPath, pos+len(key), allows)
		}
	}

	end := segmentEnd(urlPath, pos)
	if end <= pos {
		return allows
	}

	if current.TypeParam != nil {
		allows = collectAllow(current.TypeParam.Children, urlPath, end, allows)
	}
	if current.TypeWildcard != nil {
		allows = collectAllow(current.TypeWildcard.Children, urlPath, end, allows)
	}

	return allows
}

// appendAllow records n's cached Allow value unless it is empty or already
// present. Empty covers both "no methods registered" and "a catch-all handler
// lives here"; a catch-all serves every method, so it can never be part of a
// 405 in the first place.
func appendAllow(allows []string, n *node) []string {
	if n.allow == "" {
		return allows
	}

	for _, existing := range allows {
		if existing == n.allow {
			return allows
		}
	}

	return append(allows, n.allow)
}

// mergeAllow unions several cached Allow values into one sorted, deduplicated
// header value, matching buildAllowHeader's output format.
func mergeAllow(allows []string) string {
	methods := make([]string, 0, len(allows)*4)
	for _, allow := range allows {
		for rest := allow; rest != ""; {
			method := rest
			if i := strings.Index(rest, ", "); i >= 0 {
				method, rest = rest[:i], rest[i+2:]
			} else {
				rest = ""
			}

			methods = append(methods, method)
		}
	}

	sort.Strings(methods)

	unique := methods[:1]
	for _, method := range methods[1:] {
		if method != unique[len(unique)-1] {
			unique = append(unique, method)
		}
	}

	return strings.Join(unique, ", ")
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

	// Drop the params the greedy value already covers, once, so the scan
	// below carries no per-segment greedy test. params is sorted by Index,
	// so the first one at or past the wildcard segment truncates the rest.
	if greedy {
		for i := range params {
			if params[i].Index >= res.wildcardIndex {
				params = params[:i]

				break
			}
		}
	}

	if len(params) == 0 {
		return
	}

	pos := 0
	if len(urlPath) > 0 && urlPath[0] == '/' {
		pos = 1
	}

	// params are appended in pattern order, so a single forward scan of the
	// URL can hand each one its segment: O(segments + params) rather than a
	// full params sweep per segment.
	//
	// The segment boundary is found by an inline byte loop rather than
	// strings.IndexByte. IndexByte is the faster instruction sequence on
	// long inputs, but it is a call with SIMD setup to amortise, and URL
	// segments are a handful of bytes ("v2", "42"): profiling put this loop
	// at roughly half of bindPathValues, which in turn cost more than the
	// trie walk itself. Scanning the bytes directly removes the call.
	next := 0

	for index := 0; ; index++ {
		end := pos
		for end < len(urlPath) && urlPath[end] != '/' {
			end++
		}

		// Insert keeps to one paramInfo per index, but the loop does not
		// stop at the first match so future hooks registering aliases still
		// work.
		for next < len(params) && params[next].Index == index {
			r.SetPathValue(params[next].Name, urlPath[pos:end])
			next++
		}

		if next == len(params) || end >= len(urlPath) {
			return
		}

		pos = end + 1
	}
}
