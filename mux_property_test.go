package ada

// Property-based test: a naive, obviously-correct reference matcher is fed
// the same route sets and requests as the real Mux, and every observable
// output (status, Allow header, matched pattern, bound path values) must be
// identical. This locks the documented routing semantics:
//
//   - per-segment greedy matching: static first, then {param}, then wildcard
//   - no backtracking across segments
//   - single trailing-wildcard fallback ("possible")
//   - auto-HEAD (GET fallback), auto-OPTIONS, 405 with Allow header
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

func refAllow(n *refNode) string {
	if n == nil || n.catchAll != nil || len(n.entries) == 0 {
		return ""
	}

	methods := make([]string, 0, len(n.entries)+2)
	var hasGet, hasHead, hasOptions bool
	for method := range n.entries {
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
			params = append(params, paramInfo{Index: i, Name: "*"})
			if current.wildcard == nil {
				current.wildcard = &refNode{}
			}
			current = current.wildcard
		case typeNodeWildcardParam:
			name := segment[1 : len(segment)-4]
			params = append(params, paramInfo{Index: i, Name: name})
			if current.wildcard == nil {
				current.wildcard = &refNode{}
			}
			current = current.wildcard
		case typeNodeParam:
			params = append(params, paramInfo{Index: i, Name: strings.Trim(segment, "{}")})
			if current.param == nil {
				current.param = &refNode{}
			}
			current = current.param
		}

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

func (n *refNode) find(segment string) (*refNode, typeNode) {
	if segment == "" {
		if n.hasHandler() {
			return n, typeNodeSelf
		}

		return nil, typeNodeSelf
	}

	if child, ok := n.static[segment]; ok {
		return child, typeNodeStatic
	}
	if n.param != nil {
		return n.param, typeNodeParam
	}
	if n.wildcard != nil {
		return n.wildcard, typeNodeWildcard
	}

	return nil, typeNodeSelf
}

type refResult struct {
	status  int
	allow   string
	pattern string
	values  map[string]string
}

func refServe(root *refNode, method, path string) refResult {
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")

	current := root
	var possible *refNode
	possibleIdx := 0
	captured := map[int]string{}

	for i, segment := range segments {
		if current.wildcard != nil && current.wildcard.trailing {
			possible = current.wildcard
			possibleIdx = i
		}

		nd, kind := current.find(segment)
		if nd == nil {
			current = possible

			break
		}

		if kind == typeNodeParam || kind == typeNodeWildcard {
			captured[i] = segment
		}

		if i != len(segments)-1 {
			if nd.segment == nil {
				current = possible

				break
			}
			current = nd.segment
		} else {
			if nd.hasHandler() {
				current = nd
			} else {
				current = possible
			}
		}
	}

	if current == nil {
		return refResult{status: http.StatusNotFound}
	}

	entry := current.lookupEntry(method)
	if entry == nil && possible != nil {
		entry = possible.lookupEntry(method)
		if entry != nil {
			current = possible
		}
	}

	if entry == nil && method == http.MethodOptions {
		if allowed := refAllow(current); allowed != "" {
			return refResult{status: http.StatusNoContent, allow: allowed}
		}
	}

	if entry == nil {
		if allowed := refAllow(current); allowed != "" {
			return refResult{status: http.StatusMethodNotAllowed, allow: allowed}
		}

		return refResult{status: http.StatusNotFound}
	}

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
	// Iterate captured segments in index order: ada writes them in walk
	// order, so with repeated param names the later segment wins.
	capturedIdx := make([]int, 0, len(captured))
	for idx := range captured {
		capturedIdx = append(capturedIdx, idx)
	}
	sort.Ints(capturedIdx)
	for _, idx := range capturedIdx {
		if current.trailing && possibleIdx <= idx {
			continue
		}
		for _, p := range entry.params {
			if p.Index == idx {
				values[p.Name] = captured[idx]
			}
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
	paramNames := []string{"id", "name", "p"}
	methods := []string{http.MethodGet, http.MethodPost, ""} // "" = catch-all
	reqMethods := []string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodHead, http.MethodOptions,
	}
	reqSegs := append([]string{"zz", "q", ""}, staticSegs...)

	const rounds = 300

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
					segs = append(segs, "{"+paramNames[rng.Intn(len(paramNames))]+"}")
				case p < 9 && !usedStar && last:
					segs = append(segs, "*")
					usedStar = true
				default:
					if last {
						segs = append(segs, "{"+paramNames[rng.Intn(len(paramNames))]+"...}")
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
					w.Write([]byte(sb.String()))
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
