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
			mux.match(tc.path, &res)

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
