package ada

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMatch_WalkResult exercises the trie walk directly, without an HTTP
// round-trip. The walk maintains coupled invariants (segStart/segIndex, the
// wildcard triple, the backtracking stack) that were previously only
// observable through response bodies.
func TestMatch_WalkResult(t *testing.T) {
	noop := func(w http.ResponseWriter, r *http.Request) {}

	mux := NewMux()
	mux.GET("/static/deep/leaf", noop)
	mux.GET("/users/{id}", noop)
	mux.GET("/users/{id}/posts/{post}", noop)
	mux.GET("/files/{path...}", noop)
	mux.GET("/teams/*/members", noop)

	for _, tc := range []struct {
		name    string
		path    string
		matched bool
		greedy  bool
		// wildcardIndex/Offset are only meaningful when greedy.
		wildcardIndex  int
		wildcardOffset int
	}{
		{name: "static route", path: "/static/deep/leaf", matched: true},
		{name: "single param", path: "/users/42", matched: true},
		{name: "two params", path: "/users/42/posts/7", matched: true},
		{
			name: "greedy wildcard", path: "/files/a/b/c.txt", matched: true,
			greedy: true, wildcardIndex: 1, wildcardOffset: 7,
		},
		{name: "middle wildcard", path: "/teams/red/members", matched: true},
		{name: "no match", path: "/nothing/here"},
		{name: "middle wildcard does not cross a slash", path: "/teams/red/blue/members"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var res matchResult
			mux.matchMethod(mux.routes.load(), http.MethodGet, tc.path, &res)

			if got := res.node != nil; got != tc.matched {
				t.Fatalf("matched = %v, want %v", got, tc.matched)
			}
			if !tc.matched {
				return
			}

			if got := res.node.Possible; got != tc.greedy {
				t.Fatalf("greedy = %v, want %v", got, tc.greedy)
			}
			if !tc.greedy {
				return
			}

			if res.wildcardIndex != tc.wildcardIndex {
				t.Errorf("wildcardIndex = %d, want %d", res.wildcardIndex, tc.wildcardIndex)
			}
			if res.wildcardOffset != tc.wildcardOffset {
				t.Errorf("wildcardOffset = %d, want %d", res.wildcardOffset, tc.wildcardOffset)
			}
		})
	}
}

// TestMatch_MethodAwareWalk exercises the walk's method awareness directly:
// which node it settles on, and whether it produced a dispatchable entry.
//
// The walk used to answer a pure path question and leave the method to
// dispatch, which meant the first node holding any handler ended the search
// even when it could not serve the request.
func TestMatch_MethodAwareWalk(t *testing.T) {
	noop := func(w http.ResponseWriter, r *http.Request) {}

	mux := NewMux()
	mux.POST("/a/b", noop)
	mux.GET("/a/{id}", noop)
	mux.POST("/files/{p...}", noop)
	mux.GET("/files/deep/{q...}", noop)

	for _, tc := range []struct {
		name    string
		method  string
		path    string
		pattern string // "" means the walk produced no entry
		greedy  bool
	}{
		{name: "static serves its own method", method: http.MethodPost, path: "/a/b", pattern: "/a/b"},
		{name: "static dead end falls to param", method: http.MethodGet, path: "/a/b", pattern: "/a/{id}"},
		{name: "auto-HEAD reaches the param branch", method: http.MethodHead, path: "/a/b", pattern: "/a/{id}"},
		{name: "no candidate serves the method", method: http.MethodPut, path: "/a/b"},
		{
			name:   "deepest greedy wins when it serves",
			method: http.MethodGet, path: "/files/deep/x/y",
			pattern: "/files/deep/{q...}", greedy: true,
		},
		{
			name:   "shallower greedy takes over when the deeper one cannot serve",
			method: http.MethodPost, path: "/files/deep/x/y",
			pattern: "/files/{p...}", greedy: true,
		},
		{name: "neither greedy serves", method: http.MethodPut, path: "/files/deep/x/y"},
		{name: "path miss", method: http.MethodGet, path: "/nothing/here"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var res matchResult
			mux.matchMethod(mux.routes.load(), tc.method, tc.path, &res)

			if tc.pattern == "" {
				if res.entry != nil {
					t.Fatalf("entry = %q, want none", res.entry.pattern)
				}

				return
			}

			if res.entry == nil {
				t.Fatalf("no entry, want %q", tc.pattern)
			}
			if res.entry.pattern != tc.pattern {
				t.Fatalf("pattern = %q, want %q", res.entry.pattern, tc.pattern)
			}
			if res.node == nil {
				t.Fatal("entry resolved but node is nil")
			}
			if res.node.Possible != tc.greedy {
				t.Fatalf("greedy = %v, want %v", res.node.Possible, tc.greedy)
			}
		})
	}
}

// TestPathAllow covers the cold-path walk that decides 404 vs 405 and builds
// the Allow header. It has to see EVERY node matching the path, not just the
// one route selection settled on, or a 405 under-reports what the path
// actually accepts.
func TestPathAllow(t *testing.T) {
	noop := func(w http.ResponseWriter, r *http.Request) {}

	for _, tc := range []struct {
		name   string
		routes func(*Mux)
		path   string
		want   string
	}{
		{
			name:   "single node",
			routes: func(m *Mux) { m.POST("/a/b", noop) },
			path:   "/a/b",
			want:   "OPTIONS, POST",
		},
		{
			name:   "static and param merge",
			routes: func(m *Mux) { m.POST("/a/b", noop); m.GET("/a/{id}", noop) },
			path:   "/a/b",
			want:   "GET, HEAD, OPTIONS, POST",
		},
		{
			name: "static, param and wildcard merge",
			routes: func(m *Mux) {
				m.POST("/a/b", noop)
				m.DELETE("/a/{id}", noop)
				m.GET("/a/*", noop)
			},
			path: "/a/b",
			want: "DELETE, GET, HEAD, OPTIONS, POST",
		},
		{
			name: "greedies at two depths merge",
			routes: func(m *Mux) {
				m.POST("/a/{p...}", noop)
				m.GET("/a/b/{q...}", noop)
			},
			path: "/a/b/c",
			want: "GET, HEAD, OPTIONS, POST",
		},
		{
			name:   "identical method sets dedupe",
			routes: func(m *Mux) { m.GET("/a/b", noop); m.GET("/a/{id}", noop) },
			path:   "/a/b",
			want:   "GET, HEAD, OPTIONS",
		},
		{
			name:   "path miss reports nothing",
			routes: func(m *Mux) { m.POST("/a/b", noop) },
			path:   "/a/b/c",
			want:   "",
		},
		{
			name:   "catch-all contributes nothing: it is never a 405",
			routes: func(m *Mux) { m.HandleFunc("/a/{id}", noop) },
			path:   "/a/b",
			want:   "",
		},
		{
			name:   "greedy needs a non-empty segment",
			routes: func(m *Mux) { m.POST("/a/{p...}", noop) },
			path:   "/a/",
			want:   "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := NewMux()
			tc.routes(mux)

			if got := pathAllow(mux.routes.load(), tc.path); got != tc.want {
				t.Fatalf("pathAllow(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestRoutePatternRejectsMalformedSegments(t *testing.T) {
	patterns := []string{
		"/docs/v{id}",
		"/x/{",
		"/x/}",
		"/x/{}",
		"/x/{...}",
		"/x/{id}}",
		"/x/{{id}",
		"/x/{*}",
		"/x/{*...}",
		"/{id}/{id}",
	}

	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("registering malformed pattern %q did not panic", pattern)
				}
			}()

			NewMux().GET(pattern, func(http.ResponseWriter, *http.Request) {})
		})
	}
}

func TestEmptyWildcardPathTargetsMuxRoot(t *testing.T) {
	mux := NewMux()
	mux.HandleFuncWildcard("", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.PathValue("*")))
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/a/b", nil))

	if rec.Code != http.StatusOK || rec.Body.String() != "a/b" {
		t.Fatalf("status = %d body = %q, want 200 / a/b", rec.Code, rec.Body.String())
	}
	if code, _ := statusOf(t, mux, http.MethodGet, "/"); code != http.StatusNotFound {
		t.Fatalf("root status = %d, want 404 because wildcard segments are non-empty", code)
	}

	if !mux.RemoveWildcard("") {
		t.Fatal("RemoveWildcard did not remove the root wildcard")
	}

	if code, _ := statusOf(t, mux, http.MethodGet, "/a/b"); code != http.StatusNotFound {
		t.Fatalf("status after removal = %d, want 404", code)
	}
}

func TestHandleFuncWildcardNormalizesBasePath(t *testing.T) {
	for _, routePath := range []string{"/assets", "/assets/", "/assets///"} {
		t.Run(routePath, func(t *testing.T) {
			mux := NewMux()
			mux.HandleFuncWildcard(routePath, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(r.Pattern + "|" + r.PathValue("*")))
			})

			rec := serve(mux, http.MethodGet, "/assets/js/app.js")
			if rec.Code != http.StatusOK || rec.Body.String() != "/assets/*|js/app.js" {
				t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
			}
			for _, base := range []string{"/assets", "/assets/"} {
				if code, _ := statusOf(t, mux, http.MethodGet, base); code != http.StatusNotFound {
					t.Fatalf("base path %q status = %d, want 404", base, code)
				}
			}
			if !mux.RemoveWildcard(routePath) {
				t.Fatal("RemoveWildcard did not use the registration normalization")
			}
		})
	}
}

func TestNormalizeWildcardPathPreservesExplicitPatterns(t *testing.T) {
	for _, tc := range []struct {
		path string
		want string
	}{
		{"", "/*"},
		{"/", "/*"},
		{"assets", "assets/*"},
		{"/assets", "/assets/*"},
		{"/assets/", "/assets/*"},
		{"/assets/*", "/assets/*"},
		{"/assets/*/", "/assets/*"},
		{"/teams/*/members", "/teams/*/members"},
		{"/files/{path...}", "/files/{path...}"},
		{"/files/{path...}/", "/files/{path...}"},
	} {
		if got := normalizeWildcardPath(tc.path); got != tc.want {
			t.Errorf("normalizeWildcardPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestBind_ParamIndicesFollowURLSegments is the invariant the "//" index-skew
// bug violated: a parameter at pattern segment i must bind URL segment i.
// Patterns are instantiated with a distinct value per capture, so a
// misalignment shows up as a value bound to the wrong name.
func TestBind_ParamIndicesFollowURLSegments(t *testing.T) {
	for _, pattern := range []string{
		"/users/{id}",
		"/a//b/{id}",
		"//lead/{id}",
		"/orgs/{org}/users/{user}/files/{path...}",
		"/a//b/{x}//c/{y}",
		"/teams/*/members/{m}",
		"/{first}/{second}/{third}",
		"/x/{a}/y/{b}/z/{c}",
	} {
		t.Run(pattern, func(t *testing.T) {
			request, want := instantiate(pattern)

			got := map[string]string{}

			mux := NewMux()
			mux.GET(pattern, func(w http.ResponseWriter, r *http.Request) {
				for name := range want {
					got[name] = r.PathValue(name)
				}
			})

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, request, nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("pattern %q did not match its own instantiation %q (status %d)",
					pattern, request, rec.Code)
			}
			for name, value := range want {
				if got[name] != value {
					t.Errorf("PathValue(%q) = %q, want %q (request %q)",
						name, got[name], value, request)
				}
			}
		})
	}
}

// instantiate turns a pattern into a concrete request path, returning the value
// substituted for each capture name.
func instantiate(pattern string) (string, map[string]string) {
	var (
		path  strings.Builder
		want  = map[string]string{}
		index int
	)

	for _, segment := range strings.Split(strings.TrimPrefix(pattern, "/"), "/") {
		if segment == "" {
			continue
		}

		value := segment
		switch {
		case segment == "*":
			value = "star" + itoa(index)
			want["*"] = value
		case isGreedyParam(segment):
			value = "greedy" + itoa(index) + "/tail"
			want[segment[1:len(segment)-4]] = value
		case segment[0] == '{':
			value = "val" + itoa(index)
			want[strings.Trim(segment, "{}")] = value
		}

		path.WriteByte('/')
		path.WriteString(value)
		index++
	}

	return path.String(), want
}

func itoa(n int) string {
	return string(rune('0' + n))
}
