package ada

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBacktracking covers cross-segment backtracking: when a branch dead-ends,
// the matcher rewinds to the most recent segment that had an untried dynamic
// alternative and tries it.
//
// Without this, committing to the first static edge that matched a segment made
// a static alias shadow an entire parameterised subtree — /users/me alongside
// /users/{id}/posts made /users/me/posts answer 404. The expectations below are
// what net/http.ServeMux, chi, gin, echo and gorilla/mux all produce.
func TestBacktracking(t *testing.T) {
	for _, tc := range []struct {
		name    string
		routes  []string
		request string
		want    string // "" means 404
	}{
		{
			name:    "static alias does not shadow param subtree",
			routes:  []string{"/users/me", "/users/{id}/posts"},
			request: "/users/me/posts",
			want:    "/users/{id}/posts id=me",
		},
		{
			name:    "static prefix falls back to param branch",
			routes:  []string{"/foo/bar", "/{x}/baz"},
			request: "/foo/baz",
			want:    "/{x}/baz x=foo",
		},
		{
			name:    "three segments",
			routes:  []string{"/a/b/c", "/a/{x}/d"},
			request: "/a/b/d",
			want:    "/a/{x}/d x=b",
		},
		{
			name:    "param then static tail",
			routes:  []string{"/users/list", "/users/{id}/edit"},
			request: "/users/list/edit",
			want:    "/users/{id}/edit id=list",
		},
		{
			name:    "falls back through two levels",
			routes:  []string{"/a/b/c/d", "/a/{x}/{y}/e"},
			request: "/a/b/c/e",
			want:    "/a/{x}/{y}/e x=b y=c",
		},
		{
			name:    "wildcard alternative tried after param fails",
			routes:  []string{"/t/{id}/edit", "/t/*/view"},
			request: "/t/7/view",
			want:    "/t/*/view *=7",
		},
		{
			name:    "static still wins when it matches fully",
			routes:  []string{"/users/me", "/users/{id}"},
			request: "/users/me",
			want:    "/users/me ",
		},
		{
			name:    "param still matches its own path",
			routes:  []string{"/users/me", "/users/{id}/posts"},
			request: "/users/42/posts",
			want:    "/users/{id}/posts id=42",
		},
		{
			name:    "greedy fallback survives backtracking",
			routes:  []string{"/files/{p...}", "/files/static/logo.png"},
			request: "/files/static/logo.png/extra",
			want:    "/files/{p...} p=static/logo.png/extra",
		},
		{
			name:    "genuine miss is still 404",
			routes:  []string{"/users/me", "/users/{id}/posts"},
			request: "/users/me/posts/extra",
			want:    "",
		},
		{
			name:    "middle wildcard still consumes exactly one segment",
			routes:  []string{"/users/*/profile"},
			request: "/users/alice/bob/profile",
			want:    "",
		},
		{
			name:    "no alternative to rewind to",
			routes:  []string{"/a/b/c"},
			request: "/a/b/d",
			want:    "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Registration order must not matter, so try both.
			for _, reversed := range []bool{false, true} {
				routes := append([]string(nil), tc.routes...)
				if reversed {
					for i, j := 0, len(routes)-1; i < j; i, j = i+1, j-1 {
						routes[i], routes[j] = routes[j], routes[i]
					}
				}

				mux := NewMux()
				for _, pattern := range routes {
					mux.GET(pattern, describeRoute(pattern))
				}

				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.request, nil))

				got := rec.Body.String()
				if tc.want == "" {
					if rec.Code != http.StatusNotFound {
						t.Errorf("reversed=%v: status = %d body = %q, want 404", reversed, rec.Code, got)
					}

					continue
				}

				if rec.Code != http.StatusOK {
					t.Errorf("reversed=%v: status = %d body = %q, want 200 %q", reversed, rec.Code, got, tc.want)

					continue
				}
				if got != tc.want {
					t.Errorf("reversed=%v: got %q, want %q", reversed, got, tc.want)
				}
			}
		})
	}
}

// describeRoute returns a handler that reports which pattern was selected and
// the values bound for each of its captures.
func describeRoute(pattern string) http.HandlerFunc {
	names := captureNames(pattern)

	return func(w http.ResponseWriter, r *http.Request) {
		out := pattern + " "
		for i, name := range names {
			if i > 0 {
				out += " "
			}
			out += name + "=" + r.PathValue(name)
		}
		_, _ = w.Write([]byte(out))
	}
}

// captureNames lists the PathValue keys a pattern binds, in order.
func captureNames(pattern string) []string {
	var names []string

	start := 0
	for i := 0; i <= len(pattern); i++ {
		if i < len(pattern) && pattern[i] != '/' {
			continue
		}

		segment := pattern[start:i]
		start = i + 1

		switch {
		case segment == "*":
			names = append(names, "*")
		case isGreedyParam(segment):
			names = append(names, segment[1:len(segment)-4])
		case len(segment) > 2 && segment[0] == '{':
			names = append(names, segment[1:len(segment)-1])
		}
	}

	return names
}

// TestBacktracking_Termination guards against runaway exploration: a pattern
// set that offers an alternative at every level must still answer quickly and
// must not loop.
func TestBacktracking_Termination(t *testing.T) {
	mux := NewMux()
	mux.GET("/a/{p1}/{p2}/{p3}/{p4}/{p5}/{p6}/end", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("param"))
	})
	mux.GET("/a/*/x/y/z/w/v/end", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("wildcard"))
	})
	mux.GET("/a/b/c/d/e/f/g/end", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("static"))
	})

	for _, tc := range []struct{ request, want string }{
		{"/a/b/c/d/e/f/g/end", "static"},
		{"/a/1/2/3/4/5/6/end", "param"},
		{"/a/b/c/d/e/f/g/nope", ""},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.request, nil))

		if tc.want == "" {
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s: status = %d, want 404", tc.request, rec.Code)
			}

			continue
		}
		if got := rec.Body.String(); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.request, got, tc.want)
		}
	}
}

// route is one registration in the method-aware tables below. An empty method
// registers a catch-all (HandleFunc), which serves every method.
type route struct {
	method  string
	pattern string
}

// muxWithRoutes builds a Mux whose handlers report the pattern they belong to
// plus every value it captured.
func muxWithRoutes(routes []route) *Mux {
	mux := NewMux()
	for _, r := range routes {
		mux.HandleWithMethod(r.method, r.pattern, describeRoute(r.pattern))
	}

	return mux
}

// TestMethodAwareRouting pins the rule that a node matching the path but not
// the method is a dead end rather than a match.
//
// Selection used to stop at the first node holding any handler and only then
// look the method up, so a route registered under one method shadowed the
// param, wildcard or greedy alternative that could have answered:
// POST /a/b made GET /a/b a 405 even with GET /a/{id} registered. The
// expectations below are what net/http.ServeMux produces (see
// TestMethodAwareRouting_MatchesServeMux), except that ada also advertises
// OPTIONS in Allow because it answers auto-OPTIONS.
func TestMethodAwareRouting(t *testing.T) {
	for _, tc := range []struct {
		name    string
		routes  []route
		method  string
		request string
		want    string // handler output; "" means no handler ran
		status  int
		allow   string
	}{
		{
			name:    "static shadows param only for its own method",
			routes:  []route{{http.MethodPost, "/a/b"}, {http.MethodGet, "/a/{id}"}},
			method:  http.MethodGet,
			request: "/a/b",
			want:    "/a/{id} id=b",
			status:  http.StatusOK,
		},
		{
			name:    "static still wins for the method it registered",
			routes:  []route{{http.MethodPost, "/a/b"}, {http.MethodGet, "/a/{id}"}},
			method:  http.MethodPost,
			request: "/a/b",
			want:    "/a/b ",
			status:  http.StatusOK,
		},
		{
			name:    "unregistered method unions both candidates into Allow",
			routes:  []route{{http.MethodPost, "/a/b"}, {http.MethodGet, "/a/{id}"}},
			method:  http.MethodPut,
			request: "/a/b",
			status:  http.StatusMethodNotAllowed,
			allow:   "GET, HEAD, OPTIONS, POST",
		},
		{
			name:    "static falls through to greedy",
			routes:  []route{{http.MethodPost, "/a/b"}, {http.MethodGet, "/a/{p...}"}},
			method:  http.MethodGet,
			request: "/a/b",
			want:    "/a/{p...} p=b",
			status:  http.StatusOK,
		},
		{
			name:    "static falls through to bare trailing wildcard",
			routes:  []route{{http.MethodPost, "/a/b"}, {http.MethodGet, "/a/*"}},
			method:  http.MethodGet,
			request: "/a/b",
			want:    "/a/* *=b",
			status:  http.StatusOK,
		},
		{
			name:    "static and greedy union into Allow",
			routes:  []route{{http.MethodPost, "/a/b"}, {http.MethodGet, "/a/{p...}"}},
			method:  http.MethodDelete,
			request: "/a/b",
			status:  http.StatusMethodNotAllowed,
			allow:   "GET, HEAD, OPTIONS, POST",
		},
		{
			name:    "deeper greedy yields to a shallower one it cannot serve",
			routes:  []route{{http.MethodPost, "/a/{p...}"}, {http.MethodGet, "/a/b/{q...}"}},
			method:  http.MethodPost,
			request: "/a/b/c/d",
			want:    "/a/{p...} p=b/c/d",
			status:  http.StatusOK,
		},
		{
			name:    "deepest greedy still wins when it can serve",
			routes:  []route{{http.MethodPost, "/a/{p...}"}, {http.MethodGet, "/a/b/{q...}"}},
			method:  http.MethodGet,
			request: "/a/b/c/d",
			want:    "/a/b/{q...} q=c/d",
			status:  http.StatusOK,
		},
		{
			name:    "both greedies union into Allow",
			routes:  []route{{http.MethodPost, "/a/{p...}"}, {http.MethodGet, "/a/b/{q...}"}},
			method:  http.MethodPut,
			request: "/a/b/c/d",
			status:  http.StatusMethodNotAllowed,
			allow:   "GET, HEAD, OPTIONS, POST",
		},
		{
			name:    "deep static yields to a multi-param branch",
			routes:  []route{{http.MethodPost, "/x/y/z"}, {http.MethodGet, "/x/{a}/{b}"}},
			method:  http.MethodGet,
			request: "/x/y/z",
			want:    "/x/{a}/{b} a=y b=z",
			status:  http.StatusOK,
		},
		{
			name:    "deep static and multi-param union into Allow",
			routes:  []route{{http.MethodPost, "/x/y/z"}, {http.MethodGet, "/x/{a}/{b}"}},
			method:  http.MethodPatch,
			request: "/x/y/z",
			status:  http.StatusMethodNotAllowed,
			allow:   "GET, HEAD, OPTIONS, POST",
		},
		{
			name: "three candidates all contribute to Allow",
			routes: []route{
				{http.MethodPost, "/a/b"},
				{http.MethodDelete, "/a/{id}"},
				{http.MethodGet, "/a/*"},
			},
			method:  http.MethodPut,
			request: "/a/b",
			status:  http.StatusMethodNotAllowed,
			allow:   "DELETE, GET, HEAD, OPTIONS, POST",
		},
		{
			name: "param is preferred over wildcard when both can serve",
			routes: []route{
				{http.MethodPost, "/a/b"},
				{http.MethodGet, "/a/{id}"},
				{http.MethodGet, "/a/*"},
			},
			method:  http.MethodGet,
			request: "/a/b",
			want:    "/a/{id} id=b",
			status:  http.StatusOK,
		},
		{
			name:    "backtracking crosses several segments",
			routes:  []route{{http.MethodPost, "/a/b/c/d"}, {http.MethodGet, "/a/{x}/{y}/d"}},
			method:  http.MethodGet,
			request: "/a/b/c/d",
			want:    "/a/{x}/{y}/d x=b y=c",
			status:  http.StatusOK,
		},

		// ── HEAD, OPTIONS and catch-all keep working across a dead end ──
		{
			name:    "HEAD falls back to GET on the alternative branch",
			routes:  []route{{http.MethodPost, "/a/b"}, {http.MethodGet, "/a/{id}"}},
			method:  http.MethodHead,
			request: "/a/b",
			want:    "/a/{id} id=b",
			status:  http.StatusOK,
		},
		{
			name:    "HEAD prefers an exact GET over the param branch",
			routes:  []route{{http.MethodGet, "/a/b"}, {http.MethodGet, "/a/{id}"}},
			method:  http.MethodHead,
			request: "/a/b",
			want:    "/a/b ",
			status:  http.StatusOK,
		},
		{
			name:    "explicit HEAD on the static node still wins",
			routes:  []route{{http.MethodHead, "/a/b"}, {http.MethodGet, "/a/{id}"}},
			method:  http.MethodHead,
			request: "/a/b",
			want:    "/a/b ",
			status:  http.StatusOK,
		},
		{
			name:    "auto-OPTIONS unions every candidate",
			routes:  []route{{http.MethodPost, "/a/b"}, {http.MethodGet, "/a/{id}"}},
			method:  http.MethodOptions,
			request: "/a/b",
			status:  http.StatusNoContent,
			allow:   "GET, HEAD, OPTIONS, POST",
		},
		{
			name:    "a registered OPTIONS route beats auto-OPTIONS",
			routes:  []route{{http.MethodPost, "/a/b"}, {http.MethodOptions, "/a/{id}"}},
			method:  http.MethodOptions,
			request: "/a/b",
			want:    "/a/{id} id=b",
			status:  http.StatusOK,
		},
		{
			name:    "catch-all on the param branch serves any method",
			routes:  []route{{http.MethodPost, "/a/b"}, {"", "/a/{id}"}},
			method:  http.MethodPut,
			request: "/a/b",
			want:    "/a/{id} id=b",
			status:  http.StatusOK,
		},
		{
			name:    "catch-all also answers OPTIONS instead of auto-OPTIONS",
			routes:  []route{{http.MethodPost, "/a/b"}, {"", "/a/{id}"}},
			method:  http.MethodOptions,
			request: "/a/b",
			want:    "/a/{id} id=b",
			status:  http.StatusOK,
		},
		{
			name:    "catch-all on the static node keeps priority",
			routes:  []route{{"", "/a/b"}, {http.MethodGet, "/a/{id}"}},
			method:  http.MethodPut,
			request: "/a/b",
			want:    "/a/b ",
			status:  http.StatusOK,
		},

		// ── 404s must stay 404s: no candidate matches the path at all ──
		{
			name:    "path miss is still 404 not 405",
			routes:  []route{{http.MethodPost, "/a/b"}, {http.MethodGet, "/a/{id}"}},
			method:  http.MethodGet,
			request: "/a/b/c",
			status:  http.StatusNotFound,
		},
		{
			name:    "OPTIONS on an unmatched path is still 404",
			routes:  []route{{http.MethodPost, "/a/b"}, {http.MethodGet, "/a/{id}"}},
			method:  http.MethodOptions,
			request: "/nope",
			status:  http.StatusNotFound,
		},
		{
			name:    "middle wildcard does not stretch across a slash",
			routes:  []route{{http.MethodPost, "/users/*/profile"}},
			method:  http.MethodGet,
			request: "/users/a/b/profile",
			status:  http.StatusNotFound,
		},
		{
			name:    "greedy needs a non-empty first segment",
			routes:  []route{{http.MethodPost, "/a/b"}, {http.MethodGet, "/a/{p...}"}},
			method:  http.MethodGet,
			request: "/a/",
			status:  http.StatusNotFound,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Registration order must not matter, so try both.
			for _, reversed := range []bool{false, true} {
				routes := append([]route(nil), tc.routes...)
				if reversed {
					for i, j := 0, len(routes)-1; i < j; i, j = i+1, j-1 {
						routes[i], routes[j] = routes[j], routes[i]
					}
				}

				rec := httptest.NewRecorder()
				muxWithRoutes(routes).ServeHTTP(rec, httptest.NewRequest(tc.method, tc.request, nil))

				if rec.Code != tc.status {
					t.Errorf("reversed=%v: status = %d body = %q, want %d",
						reversed, rec.Code, rec.Body.String(), tc.status)
				}
				if got := rec.Header().Get("Allow"); got != tc.allow {
					t.Errorf("reversed=%v: Allow = %q, want %q", reversed, got, tc.allow)
				}
				if tc.want != "" && rec.Body.String() != tc.want {
					t.Errorf("reversed=%v: body = %q, want %q", reversed, rec.Body.String(), tc.want)
				}
			}
		})
	}
}

// TestMethodAwareRouting_MatchesServeMux cross-checks the shapes above against
// net/http.ServeMux, the closest thing to a normative reference for
// method-scoped patterns: status, selected pattern and bound values must all
// agree.
//
// Two deliberate ada/ServeMux differences keep this from being a blanket
// comparison, so neither is exercised here:
//   - ada advertises OPTIONS in Allow because it answers auto-OPTIONS, which
//     ServeMux does not; Allow is therefore compared with OPTIONS stripped and
//     OPTIONS requests are left out.
//   - ada's trailing wildcard requires a non-empty first segment, while
//     ServeMux lets `/a/{q...}` match `/a` and redirects `/a/b` to `/a/b/`;
//     request paths are chosen so every greedy captures something.
func TestMethodAwareRouting_MatchesServeMux(t *testing.T) {
	for _, tc := range []struct {
		routes   []route
		requests []string // "METHOD /path"
	}{
		{
			routes: []route{{http.MethodPost, "/a/b"}, {http.MethodGet, "/a/{id}"}},
			requests: []string{
				"GET /a/b", "POST /a/b", "PUT /a/b", "HEAD /a/b",
				"GET /a/b/c", "GET /nope",
			},
		},
		{
			routes:   []route{{http.MethodGet, "/a/b"}, {http.MethodGet, "/a/{id}"}},
			requests: []string{"GET /a/b", "PUT /a/b", "HEAD /a/b", "GET /a/zz"},
		},
		{
			routes: []route{{http.MethodPost, "/a/b"}, {http.MethodGet, "/a/{p...}"}},
			requests: []string{
				"GET /a/b/c/d", "POST /a/b/c/d", "PUT /a/b/c/d", "HEAD /a/b/c/d",
			},
		},
		{
			routes: []route{{http.MethodPost, "/a/{p...}"}, {http.MethodGet, "/a/b/{q...}"}},
			requests: []string{
				"GET /a/b/c/d", "POST /a/b/c/d", "PUT /a/b/c/d", "HEAD /a/b/c/d",
			},
		},
		{
			routes:   []route{{http.MethodPost, "/x/y/z"}, {http.MethodGet, "/x/{a}/{b}"}},
			requests: []string{"GET /x/y/z", "POST /x/y/z", "PUT /x/y/z", "GET /x/q/w"},
		},
		{
			routes:   []route{{http.MethodPost, "/a/b/c/d"}, {http.MethodGet, "/a/{x}/{y}/d"}},
			requests: []string{"GET /a/b/c/d", "POST /a/b/c/d", "PUT /a/b/c/d"},
		},
		{
			routes: []route{
				{http.MethodPost, "/a/b"},
				{http.MethodDelete, "/a/{id}"},
				{http.MethodGet, "/a/{p...}"},
			},
			requests: []string{"GET /a/b/c", "DELETE /a/b", "POST /a/b", "PUT /a/b"},
		},
	} {
		mux := muxWithRoutes(tc.routes)

		std := http.NewServeMux()
		for _, r := range tc.routes {
			std.Handle(r.method+" "+r.pattern, describeRoute(r.pattern))
		}

		for _, request := range tc.requests {
			method, path, _ := strings.Cut(request, " ")

			got := httptest.NewRecorder()
			mux.ServeHTTP(got, httptest.NewRequest(method, path, nil))

			want := httptest.NewRecorder()
			std.ServeHTTP(want, httptest.NewRequest(method, path, nil))

			ctx := describeRouteSet(tc.routes) + " " + request

			if got.Code != want.Code {
				t.Errorf("%s: status = %d, ServeMux = %d", ctx, got.Code, want.Code)

				continue
			}
			if got.Code == http.StatusOK && got.Body.String() != want.Body.String() {
				t.Errorf("%s: body = %q, ServeMux = %q", ctx, got.Body.String(), want.Body.String())
			}
			if got.Code == http.StatusMethodNotAllowed {
				if allow := withoutOptions(got.Header().Get("Allow")); allow != want.Header().Get("Allow") {
					t.Errorf("%s: Allow = %q, ServeMux = %q", ctx, allow, want.Header().Get("Allow"))
				}
			}
		}
	}
}

func describeRouteSet(routes []route) string {
	out := "["
	for i, r := range routes {
		if i > 0 {
			out += ", "
		}
		out += r.method + " " + r.pattern
	}

	return out + "]"
}

func withoutOptions(allow string) string {
	methods := strings.Split(allow, ", ")
	kept := methods[:0]
	for _, method := range methods {
		if method != http.MethodOptions {
			kept = append(kept, method)
		}
	}

	return strings.Join(kept, ", ")
}
