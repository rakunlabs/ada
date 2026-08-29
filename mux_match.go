package ada

import (
	"net/http"
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

	// One snapshot for the whole request: a route added or removed midway
	// through must not change which tree this request is being matched
	// against.
	m.match(m.routes.load(), r.URL.Path, &res)

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
func (m *Mux) match(root *node, urlPath string, res *matchResult) {
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
