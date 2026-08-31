package ada

// Property-based test: a naive, obviously-correct reference matcher is fed
// the same route sets and requests as the real Mux, and every observable
// output (status, Allow header, matched pattern, bound path values) must be
// identical. This locks the documented routing semantics:
//
//   - per-segment preference: static first, then {param}, then wildcard
//   - cross-segment backtracking when a preferred branch dead-ends
//   - method-aware selection: a node that matches the path but cannot serve
//     the request method is a dead end the walk backtracks out of
//   - single trailing-wildcard fallback ("possible")
//   - auto-HEAD (GET fallback), auto-OPTIONS, 405 whose Allow header is the
//     union over every path-matching node
//
// The reference is intentionally built on maps and string slices — slow and
// simple — so it stays trustworthy while the production trie is optimized.

import (
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// ── Reference implementation ───────────────────────────────────────────

type refEntry struct {
	pattern string
	params  []paramInfo
}

type refNode struct {
	segment  *refNode
	trailing bool // set on trailing wildcard children (ada: node.Possible)

	static   map[string]*refNode
	param    *refNode
	wildcard *refNode

	entries  map[string]*refEntry
	catchAll *refEntry
}

func (n *refNode) hasHandler() bool {
	return n.catchAll != nil || len(n.entries) > 0
}

func (n *refNode) lookupEntry(method string) *refEntry {
	entry := n.entries[method]
	if entry == nil && method == http.MethodHead {
		entry = n.entries[http.MethodGet]
	}
	if entry == nil {
		entry = n.catchAll
	}

	return entry
}

// refAllow unions the methods of every candidate node into one Allow header.
// A node holding a catch-all contributes nothing: it serves every method, so
// it can never be part of a request that failed to find a handler.
func refAllow(nodes []*refNode) string {
	methodSet := make(map[string]struct{})
	var hasGet, hasHead, hasOptions bool
	for _, n := range nodes {
		if n == nil || n.catchAll != nil {
			continue
		}
		for method := range n.entries {
			methodSet[method] = struct{}{}
			switch method {
			case http.MethodGet:
				hasGet = true
			case http.MethodHead:
				hasHead = true
			case http.MethodOptions:
				hasOptions = true
			}
		}
	}
	if len(methodSet) == 0 {
		return ""
	}

	methods := make([]string, 0, len(methodSet)+2)
	for method := range methodSet {
		methods = append(methods, method)
	}
	if hasGet && !hasHead {
		methods = append(methods, http.MethodHead)
	}
	if !hasOptions {
		methods = append(methods, http.MethodOptions)
	}
	sort.Strings(methods)

	return strings.Join(methods, ", ")
}

func refInsert(root *refNode, method, pattern string, ok *bool) {
	segments := strings.Split(strings.TrimPrefix(pattern, "/"), "/")

	var params []paramInfo
	var lastType typeNode
	current := root
	// segIdx counts EMITTED segments so the indices line up with the
	// matcher's segment numbering, which never sees collapsed empties.
	segIdx := 0
	for i, segment := range segments {
		if segment == "" {
			continue
		}

		lastType = findTypeNode(segment)
		switch lastType {
		case typeNodeStatic:
			if current.static == nil {
				current.static = map[string]*refNode{}
			}
			if current.static[segment] == nil {
				current.static[segment] = &refNode{}
			}
			current = current.static[segment]
		case typeNodeWildcard:
			params = append(params, paramInfo{Index: segIdx, Name: "*"})
			if current.wildcard == nil {
				current.wildcard = &refNode{}
			}
			current = current.wildcard
		case typeNodeWildcardParam:
			name := segment[1 : len(segment)-4]
			params = append(params, paramInfo{Index: segIdx, Name: name})
			if current.wildcard == nil {
				current.wildcard = &refNode{}
			}
			current = current.wildcard
		case typeNodeParam:
			params = append(params, paramInfo{Index: segIdx, Name: strings.Trim(segment, "{}")})
			if current.param == nil {
				current.param = &refNode{}
			}
			current = current.param
		}

		segIdx++

		if i != len(segments)-1 {
			if current.segment == nil {
				current.segment = &refNode{}
			}
			current = current.segment
		}
	}

	entry := &refEntry{pattern: pattern, params: params}
	if method == "" {
		current.catchAll = entry
	} else {
		if current.entries == nil {
			current.entries = map[string]*refEntry{}
		}
		current.entries[method] = entry
	}

	if lastType == typeNodeWildcard || lastType == typeNodeWildcardParam {
		current.trailing = true
	}

	*ok = true
}

type refResult struct {
	status  int
	allow   string
	pattern string
	values  map[string]string
}

// refWalk resolves a request path against the reference trie, trying static,
// then param, then wildcard at every segment and backtracking when a branch
// dead-ends. This mirrors ada's choicePoint stack.
//
// The walk is method-aware, which is the whole point of the oracle: a node
// that matches the path but has no entry for the request method is rejected
// like any other dead end, so the search continues into the alternatives
// behind it. Every node it rejects is remembered in candidates, whose union
// is the Allow header owed on a 405.
type refWalk struct {
	segments []string
	method   string

	possible    *refNode
	possibleIdx int

	candidates []*refNode
}

// note records a node that matches the path, whatever its methods.
func (w *refWalk) note(n *refNode) {
	for _, seen := range w.candidates {
		if seen == n {
			return
		}
	}

	w.candidates = append(w.candidates, n)
}

// terminal accepts n as the answer only if it can serve the request method.
func (w *refWalk) terminal(n *refNode) *refNode {
	if !n.hasHandler() {
		return nil
	}

	w.note(n)

	if n.lookupEntry(w.method) == nil {
		return nil
	}

	return n
}

// resolve returns the terminal node for segments[i:] starting from the
// segment-dispatch node n, or nil when no branch below n can serve the
// request.
func (w *refWalk) resolve(n *refNode, i int) *refNode {
	if n == nil {
		return nil
	}

	// The greedy fallback is recorded and never rewound: like ada, it
	// describes a matched prefix of the URL rather than the branch taken.
	// Only a greedy that can serve the method is kept, so a deeper greedy
	// registered under some other method cannot mask a shallower one.
	if n.wildcard != nil && n.wildcard.trailing && i < len(w.segments) && w.segments[i] != "" {
		if n.wildcard.hasHandler() {
			w.note(n.wildcard)
		}
		if n.wildcard.lookupEntry(w.method) != nil {
			w.possible = n.wildcard
			w.possibleIdx = i
		}
	}

	if i == len(w.segments) {
		return w.terminal(n)
	}

	segment := w.segments[i]

	// An empty segment binds to nothing; only a node that already holds a
	// handler can terminate here.
	if segment == "" {
		if !n.hasHandler() {
			return nil
		}

		return w.advance(n, i)
	}

	if child, ok := n.static[segment]; ok {
		if found := w.advance(child, i); found != nil {
			return found
		}
	}

	for _, child := range []*refNode{n.param, n.wildcard} {
		if child == nil {
			continue
		}

		if found := w.advance(child, i); found != nil {
			return found
		}
	}

	return nil
}

// advance steps from a node that consumed segment i to the rest of the path.
func (w *refWalk) advance(nd *refNode, i int) *refNode {
	if i == len(w.segments)-1 {
		return w.terminal(nd)
	}

	return w.resolve(nd.segment, i+1)
}

func refServe(root *refNode, method, path string) refResult {
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")

	walk := &refWalk{segments: segments, method: method}

	current := walk.resolve(root, 0)
	if current == nil {
		current = walk.possible
	}

	possibleIdx := walk.possibleIdx

	// Both the walk and its greedy fallback already screened for the
	// method, so a node here is guaranteed to serve the request; reaching
	// this with none means the request is a 404 or a 405.
	if current == nil {
		allowed := refAllow(walk.candidates)
		switch {
		case allowed == "":
			return refResult{status: http.StatusNotFound}
		case method == http.MethodOptions:
			return refResult{status: http.StatusNoContent, allow: allowed}
		default:
			return refResult{status: http.StatusMethodNotAllowed, allow: allowed}
		}
	}

	entry := current.lookupEntry(method)

	values := map[string]string{}
	if current.trailing {
		wildcard := strings.Join(segments[possibleIdx:], "/")
		// Mirror ada: the greedy value never keeps a leading '/'
		// (only reachable when the first captured segment is empty).
		if len(wildcard) > 0 && wildcard[0] == '/' {
			wildcard = wildcard[1:]
		}
		wrote := false
		for _, p := range entry.params {
			if p.Index == possibleIdx {
				values[p.Name] = wildcard
				wrote = true
			}
		}
		if !wrote {
			values["*"] = wildcard
		}
	}
	// Single-segment captures follow the URL: a parameter at pattern segment
	// i binds URL segment i, because every pattern segment except a trailing
	// greedy consumes exactly one URL segment.
	for _, p := range entry.params {
		if current.trailing && p.Index >= possibleIdx {
			continue // folded into the greedy value above
		}
		if p.Index < len(segments) {
			values[p.Name] = segments[p.Index]
		}
	}

	return refResult{status: http.StatusOK, pattern: entry.pattern, values: values}
}

// ── Generator + comparison ─────────────────────────────────────────────

func patternParamNames(pattern string) []string {
	var names []string
	for _, seg := range strings.Split(strings.TrimPrefix(pattern, "/"), "/") {
		switch {
		case seg == "*":
			names = append(names, "*")
		case isGreedyParam(seg):
			names = append(names, seg[1:len(seg)-4])
		case strings.Contains(seg, "{"):
			names = append(names, strings.Trim(seg, "{}"))
		}
	}

	return names
}

func TestMuxMatchesReference(t *testing.T) {
	staticSegs := []string{"a", "b", "ab", "files", "v1", "users"}
	paramNames := []string{"id", "name", "p", "slug"}
	// Registering several methods per shape is what makes the oracle bite:
	// route selection has to reject a node that matches the path but was
	// registered under a different method and keep backtracking.
	methods := []string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodDelete, "", // "" = catch-all
	}
	reqMethods := []string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodPatch,
		http.MethodHead, http.MethodOptions,
	}
	reqSegs := append([]string{"zz", "q", ""}, staticSegs...)

	const rounds = 800

	for round := range rounds {
		rng := rand.New(rand.NewSource(int64(round))) //nolint:gosec // deterministic test

		// ── Generate a random valid route set ──
		mux := NewMux()
		root := &refNode{}

		routeCount := 1 + rng.Intn(8)
		var routes []string
		for range routeCount {
			depth := 1 + rng.Intn(4)
			segs := make([]string, 0, depth)
			usedStar := false
			for d := range depth {
				last := d == depth-1
				switch p := rng.Intn(10); {
				case p < 6:
					segs = append(segs, staticSegs[rng.Intn(len(staticSegs))])
				case p < 8:
					segs = append(segs, "{"+paramNames[d]+"}")
				case p < 9 && !usedStar && last:
					segs = append(segs, "*")
					usedStar = true
				default:
					if last {
						segs = append(segs, "{"+paramNames[d]+"...}")
					} else {
						segs = append(segs, staticSegs[rng.Intn(len(staticSegs))])
					}
				}
			}

			pattern := "/" + strings.Join(segs, "/")
			method := methods[rng.Intn(len(methods))]

			names := patternParamNames(pattern)
			handler := func(pattern string, names []string) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					var sb strings.Builder
					sb.WriteString(r.Pattern)
					for _, name := range names {
						sb.WriteString("|" + name + "=" + r.PathValue(name))
					}
					_, _ = w.Write([]byte(sb.String()))
				}
			}(pattern, names)

			mux.HandleWithMethod(method, pattern, handler)
			var ok bool
			refInsert(root, method, pattern, &ok)
			routes = append(routes, method+" "+pattern)
		}

		// ── Fire random requests at both ──
		for range 40 {
			depth := rng.Intn(5)
			segs := make([]string, 0, depth)
			for range depth {
				segs = append(segs, reqSegs[rng.Intn(len(reqSegs))])
			}
			path := "/" + strings.Join(segs, "/")
			method := reqMethods[rng.Intn(len(reqMethods))]

			want := refServe(root, method, path)

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))

			ctx := "round=" + string(rune('0'+round%10)) + " routes=[" + strings.Join(routes, ", ") + "] req=" + method + " " + path

			if rec.Code != want.status {
				t.Fatalf("%s: status got %d want %d", ctx, rec.Code, want.status)
			}
			if want.allow != "" && rec.Header().Get("Allow") != want.allow {
				t.Fatalf("%s: Allow got %q want %q", ctx, rec.Header().Get("Allow"), want.allow)
			}
			if want.status == http.StatusOK {
				var sb strings.Builder
				sb.WriteString(want.pattern)
				for _, name := range patternParamNames(want.pattern) {
					sb.WriteString("|" + name + "=" + want.values[name])
				}
				if got := rec.Body.String(); got != sb.String() {
					t.Fatalf("%s: body got %q want %q", ctx, got, sb.String())
				}
			}
		}
	}
}
