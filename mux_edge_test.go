package ada

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// These tests pin down contracts that are easy to break without noticing:
// decoded-path matching, dispatch-time method case sensitivity, per-entry
// param naming, handler replacement, radix splitting, multi-byte keys, and
// greedy-fallback bindings after a rewind. Each one failed silently in some
// router at some point — ada's or someone else's.

// TestDecodedPathMatching locks the documented rule that Mux matches on the
// DECODED r.URL.Path: %2F becomes a real separator before matching, encoded
// traversal reaches greedy captures verbatim, and %7B/%7D turn into literal
// braces that are plain path bytes, not route syntax.
func TestDecodedPathMatching(t *testing.T) {
	t.Run("percent-2F is a separator", func(t *testing.T) {
		mux := NewMux()
		mux.GET("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(r.PathValue("id")))
		})
		mux.GET("/pair/{a}/{b}", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(r.PathValue("a") + "+" + r.PathValue("b")))
		})

		// One param cannot swallow an encoded slash: the request becomes
		// two segments and /users/{id} no longer matches.
		if code, _ := statusOf(t, mux, http.MethodGet, "/users/a%2Fb"); code != http.StatusNotFound {
			t.Errorf("/users/a%%2Fb = %d, want 404", code)
		}

		// The same request DOES match a two-param route, one segment each.
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/pair/a%2Fb", nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "a+b" {
			t.Errorf("/pair/a%%2Fb = %d %q, want 200 %q", rec.Code, rec.Body.String(), "a+b")
		}
	})

	t.Run("encoded traversal reaches the greedy capture", func(t *testing.T) {
		mux := NewMux()
		mux.GET("/static/{p...}", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(r.PathValue("p")))
		})

		for _, tc := range []struct{ target, want string }{
			{"/static/../../etc/passwd", "../../etc/passwd"},
			{"/static/..%2f..%2fetc/passwd", "../../etc/passwd"},
			{"/static/%2e%2e/x", "../x"},
		} {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.target, nil))
			if rec.Code != http.StatusOK || rec.Body.String() != tc.want {
				t.Errorf("%s = %d %q, want 200 %q", tc.target, rec.Code, rec.Body.String(), tc.want)
			}
		}
	})

	t.Run("encoded braces are path bytes, not route syntax", func(t *testing.T) {
		mux := NewMux()
		mux.GET("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(r.PathValue("id")))
		})

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users/%7Bid%7D", nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "{id}" {
			t.Errorf("/users/%%7Bid%%7D = %d %q, want 200 %q", rec.Code, rec.Body.String(), "{id}")
		}
	})
}

// TestDispatchMethodCaseSensitivity: registration normalizes method tokens to
// uppercase, but dispatch compares r.Method byte-for-byte (net/http servers
// deliver methods verbatim). A lowercase method must therefore be a 405 — a
// path match without a method match — never a silent 200.
func TestDispatchMethodCaseSensitivity(t *testing.T) {
	mux := NewMux()
	mux.HandleWithMethod("purge", "/cache", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Registered as "purge", normalized to PURGE, dispatched as PURGE.
	if code, _ := statusOf(t, mux, "PURGE", "/cache"); code != http.StatusOK {
		t.Errorf("PURGE = %d, want 200", code)
	}

	// The raw lowercase token does not match; Allow still advertises it.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PURGE", "/cache", nil)
	req.Method = "purge"
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("purge = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "PURGE") {
		t.Errorf("Allow = %q, want to contain PURGE", allow)
	}
}

// TestSharedParamNodeDistinctNames: two routes can hang off the SAME param
// node under different names. The binding must come from the winning route's
// own entry, not from the trie node (which keeps only the first name).
func TestSharedParamNodeDistinctNames(t *testing.T) {
	mux := NewMux()
	mux.GET("/a/{id}/x", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("id=" + r.PathValue("id") + " name=" + r.PathValue("name")))
	})
	mux.GET("/a/{name}/y", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("id=" + r.PathValue("id") + " name=" + r.PathValue("name")))
	})

	for _, tc := range []struct{ path, want string }{
		{"/a/7/x", "id=7 name="},
		{"/a/7/y", "id= name=7"},
	} {
		if _, body := statusOf(t, mux, http.MethodGet, tc.path); body != tc.want {
			t.Errorf("%s body = %q, want %q", tc.path, body, tc.want)
		}
	}
}

// TestReRegisterReplacesHandler: registering the same method+path again must
// swap the handler in place — no duplicate entries, no stale Allow header.
func TestReRegisterReplacesHandler(t *testing.T) {
	mux := NewMux()
	mux.GET("/v", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("old")) })
	mux.GET("/v", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("new")) })

	if _, body := statusOf(t, mux, http.MethodGet, "/v"); body != "new" {
		t.Errorf("body = %q, want %q", body, "new")
	}

	// One Remove drops the route entirely: replacement did not stack.
	if !mux.Remove(http.MethodGet, "/v") {
		t.Fatal("Remove found nothing")
	}
	if code, _ := statusOf(t, mux, http.MethodGet, "/v"); code != http.StatusNotFound {
		t.Errorf("after remove = %d, want 404", code)
	}

	// Same contract for the catch-all slot.
	mux.HandleFunc("/c", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("old")) })
	mux.HandleFunc("/c", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("new")) })
	if _, body := statusOf(t, mux, http.MethodDelete, "/c"); body != "new" {
		t.Errorf("catch-all body = %q, want %q", body, "new")
	}
}

// TestRadixSplitEdges drives the key-splitting paths in insertNodeTypeStatic:
// shared prefixes force node splits, and a request must stop exactly at key
// boundaries — never match a prefix of a longer key or overshoot a shorter one.
func TestRadixSplitEdges(t *testing.T) {
	mux := NewMux()
	for _, p := range []string{"/ab", "/abc", "/abd", "/a", "/abcde"} {
		p := p
		mux.GET(p, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(p)) })
	}

	for _, tc := range []struct {
		path string
		code int
	}{
		{"/a", http.StatusOK},
		{"/ab", http.StatusOK},
		{"/abc", http.StatusOK},
		{"/abd", http.StatusOK},
		{"/abcde", http.StatusOK},
		{"/abe", http.StatusNotFound},  // shares "ab", no such branch
		{"/abcd", http.StatusNotFound}, // between two registered keys
		{"/abcdef", http.StatusNotFound},
	} {
		code, body := statusOf(t, mux, http.MethodGet, tc.path)
		if code != tc.code {
			t.Errorf("%s = %d, want %d", tc.path, code, tc.code)
		}
		if tc.code == http.StatusOK && body != tc.path {
			t.Errorf("%s body = %q, want the route's own pattern", tc.path, body)
		}
	}
}

// TestUnicodeSegments: the radix trie indexes by byte, so multi-byte UTF-8
// sequences get split mid-rune by shared-prefix compression. Matching must
// remain exact anyway, for static keys and captures alike.
func TestUnicodeSegments(t *testing.T) {
	mux := NewMux()
	// "café" and "caftan" share the byte prefix "caf"; "café"[3] is 0xC3.
	mux.GET("/café/menü", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("menu")) })
	mux.GET("/caftan", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("caftan")) })
	mux.GET("/emoji/{sym}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.PathValue("sym")))
	})

	for _, tc := range []struct {
		path string
		code int
		body string
	}{
		{"/café/menü", http.StatusOK, "menu"},
		{"/caftan", http.StatusOK, "caftan"},
		{"/café", http.StatusNotFound, ""},
		{"/caf", http.StatusNotFound, ""},
		{"/emoji/🦫", http.StatusOK, "🦫"},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://x", nil)
		req.URL.Path = tc.path
		mux.ServeHTTP(rec, req)
		if rec.Code != tc.code {
			t.Errorf("%s = %d, want %d", tc.path, rec.Code, tc.code)
		}
		if tc.code == http.StatusOK && rec.Body.String() != tc.body {
			t.Errorf("%s body = %q, want %q", tc.path, rec.Body.String(), tc.body)
		}
	}
}

// TestGreedyFallbackBindingsAfterRewind: the walk explores the param branch,
// dead-ends, and only then falls back to a greedy captured earlier. The
// winning entry's bindings must be derived from the URL for THAT entry:
// the greedy value present, the abandoned branch's params absent.
func TestGreedyFallbackBindingsAfterRewind(t *testing.T) {
	mux := NewMux()
	mux.GET("/{a}/{b}/c", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("params")) })
	mux.GET("/x/*", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("greedy *=" + r.PathValue("*") + " a=" + r.PathValue("a") + " b=" + r.PathValue("b")))
	})

	// /x/y/c walks x→param{a=x}→{b=y}→"c": the param route wins outright.
	if _, body := statusOf(t, mux, http.MethodGet, "/x/y/c"); body != "params" {
		t.Errorf("/x/y/c body = %q, want %q", body, "params")
	}

	// /x/y/z dead-ends the param branch at "z" and rewinds to the greedy
	// captured at "/x/". Nothing from the abandoned branch may leak.
	if _, body := statusOf(t, mux, http.MethodGet, "/x/y/z"); body != "greedy *=y/z a= b=" {
		t.Errorf("/x/y/z body = %q, want %q", body, "greedy *=y/z a= b=")
	}
}

// TestHeadPrecedenceOverCatchAll: on a node holding both a GET entry and a
// catch-all, HEAD must resolve through the auto-HEAD fallback to GET — the
// specific entry — while unrelated methods fall through to the catch-all.
func TestHeadPrecedenceOverCatchAll(t *testing.T) {
	mux := NewMux()
	mux.HandleFunc("/r", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("any")) })
	mux.GET("/r", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("get")) })

	for _, tc := range []struct{ method, want string }{
		{http.MethodGet, "get"},
		{http.MethodHead, "get"}, // auto-HEAD prefers the GET entry
		{http.MethodDelete, "any"},
		{http.MethodOptions, "any"}, // catch-all outranks auto-OPTIONS
	} {
		if _, body := statusOf(t, mux, tc.method, "/r"); body != tc.want {
			t.Errorf("%s body = %q, want %q", tc.method, body, tc.want)
		}
	}
}

// TestSpecialCharacterSegments: bytes that are separators or syntax in other
// routers ('.', '-', '~', '@', ':', '$') are plain path bytes here, in static
// keys and captures alike, and must split/match exactly.
func TestSpecialCharacterSegments(t *testing.T) {
	mux := NewMux()
	for _, p := range []string{"/v1.2/status", "/v1.10/status", "/@me", "/~home", "/x:y", "/$batch"} {
		p := p
		mux.GET(p, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(p)) })
	}
	mux.GET("/file/{name}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.PathValue("name")))
	})

	for _, tc := range []struct{ path, want string }{
		{"/v1.2/status", "/v1.2/status"},
		{"/v1.10/status", "/v1.10/status"},
		{"/@me", "/@me"},
		{"/~home", "/~home"},
		{"/x:y", "/x:y"},
		{"/$batch", "/$batch"},
		{"/file/report.v2.tar.gz", "report.v2.tar.gz"},
	} {
		code, body := statusOf(t, mux, http.MethodGet, tc.path)
		if code != http.StatusOK || body != tc.want {
			t.Errorf("%s = %d %q, want 200 %q", tc.path, code, body, tc.want)
		}
	}

	if code, _ := statusOf(t, mux, http.MethodGet, "/v1.20/status"); code != http.StatusNotFound {
		t.Errorf("/v1.20/status = %d, want 404", code)
	}
}

// TestDeepStaticAndParamTrie guards stack-sensitive code paths (choicePoint
// buffer growth, recursion in collectAllow) with a route far deeper than the
// 8-entry choice buffer.
func TestDeepStaticAndParamTrie(t *testing.T) {
	const depth = 40

	segs := make([]string, depth)
	for i := range segs {
		segs[i] = "{p" + string(rune('a'+i%26)) + string(rune('0'+i/26)) + "}"
	}

	paramPattern := "/" + strings.Join(segs, "/")
	staticPath := "/" + strings.Repeat("s/", depth-1) + "s"

	mux := NewMux()
	mux.GET(paramPattern, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("deep-param " + r.PathValue("pa0") + ".." + r.PathValue("pn1")))
	})
	mux.POST(staticPath, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("deep-static")) })

	// The static chain matches POST; GET on it dead-ends every static node
	// and resolves through 40 param segments instead.
	if _, body := statusOf(t, mux, http.MethodPost, staticPath); body != "deep-static" {
		t.Errorf("POST body = %q, want %q", body, "deep-static")
	}
	if _, body := statusOf(t, mux, http.MethodGet, staticPath); body != "deep-param s..s" {
		t.Errorf("GET body = %q, want %q", body, "deep-param s..s")
	}
}
