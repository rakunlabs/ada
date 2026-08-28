package ada

import (
	"net/http"
	"net/http/httptest"
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
