package ada

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func serve(m *Mux, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(method, path, nil))

	return rec
}

// TestUse_PreservesMethodDispatch guards the regression where Use() registered
// a real catch-all route: that route answered every method, so the 405 and
// auto-OPTIONS branches became unreachable and every app calling Use() — i.e.
// essentially every app — silently lost both.
func TestUse_PreservesMethodDispatch(t *testing.T) {
	for _, withUse := range []bool{false, true} {
		name := "without Use"
		if withUse {
			name = "with Use"
		}

		t.Run(name, func(t *testing.T) {
			mux := NewMux()
			if withUse {
				mux.Use(func(next http.Handler) http.Handler { return next })
			}
			mux.GET("/users", func(w http.ResponseWriter, r *http.Request) {})

			rec := serve(mux, http.MethodPost, "/users")
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("POST: expected 405, got %d", rec.Code)
			}
			if allow := rec.Header().Get("Allow"); allow != "GET, HEAD, OPTIONS" {
				t.Errorf("POST: Allow = %q, want %q", allow, "GET, HEAD, OPTIONS")
			}

			rec = serve(mux, http.MethodOptions, "/users")
			if rec.Code != http.StatusNoContent {
				t.Errorf("OPTIONS: expected 204, got %d", rec.Code)
			}
			if allow := rec.Header().Get("Allow"); allow != "GET, HEAD, OPTIONS" {
				t.Errorf("OPTIONS: Allow = %q, want %q", allow, "GET, HEAD, OPTIONS")
			}
		})
	}
}

// TestUse_KeepsUserCatchAll guards the regression where Use() overwrote a
// user-registered "/*" handler (a SPA fallback, a proxy, ...) because both
// were stored in the same catchAll slot.
func TestUse_KeepsUserCatchAll(t *testing.T) {
	mux := NewMux()
	mux.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("catch-all"))
	})

	if got := serve(mux, http.MethodGet, "/whatever").Body.String(); got != "catch-all" {
		t.Fatalf("before Use: got %q", got)
	}

	mux.Use(func(next http.Handler) http.Handler { return next })

	if got := serve(mux, http.MethodGet, "/whatever").Body.String(); got != "catch-all" {
		t.Errorf("after Use: got %q, want the user catch-all to survive", got)
	}
}

// TestErrorPaths_RunMiddleware pins that 404, 405 and auto-OPTIONS all go
// through the middleware chain of the deepest matching scope. The classic
// symptom of the old behaviour was CORS headers missing from exactly the
// responses that need them (preflight and rejections).
func TestErrorPaths_RunMiddleware(t *testing.T) {
	mux := NewMux()
	api := mux.Group("/api", func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			next.ServeHTTP(w, r)
		})
	})
	api.GET("/users", func(w http.ResponseWriter, r *http.Request) {})

	for _, tc := range []struct {
		method, path string
		code         int
	}{
		{http.MethodGet, "/api/users", http.StatusOK},
		{http.MethodPost, "/api/users", http.StatusMethodNotAllowed},
		{http.MethodOptions, "/api/users", http.StatusNoContent},
		{http.MethodGet, "/api/nope", http.StatusNotFound},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := serve(mux, tc.method, tc.path)

			if rec.Code != tc.code {
				t.Errorf("status = %d, want %d", rec.Code, tc.code)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
				t.Errorf("CORS header = %q, want %q", got, "*")
			}
		})
	}

	// Outside the group the group's middleware must NOT run.
	if got := serve(mux, http.MethodGet, "/nope").Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("outside group: CORS header = %q, want empty", got)
	}
}

// TestGroup_ErrorHandlersWithoutUse pins that a group's NotFound takes effect
// on its own subtree. Previously the group's handler was silently ignored
// unless an unrelated Use() call had been made first.
func TestGroup_ErrorHandlersWithoutUse(t *testing.T) {
	mux := NewMux()
	mux.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("root-404"))
	})

	group := mux.Group("/g")
	group.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("group-404"))
	})

	for _, tc := range []struct{ path, want string }{
		{"/g/nope", "group-404"},
		{"/nope", "root-404"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			if got := serve(mux, http.MethodGet, tc.path).Body.String(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGroup_MethodNotAllowedScoped pins the same scoping for 405.
func TestGroup_MethodNotAllowedScoped(t *testing.T) {
	mux := NewMux()
	group := mux.Group("/g")
	group.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte("group-405"))
	})
	group.GET("/x", func(w http.ResponseWriter, r *http.Request) {})

	rec := serve(mux, http.MethodPost, "/g/x")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if got := rec.Body.String(); got != "group-405" {
		t.Errorf("body = %q, want %q", got, "group-405")
	}
	if rec.Header().Get("Allow") == "" {
		t.Error("Allow header must still be set")
	}
}

// TestInsert_CollapsedSegmentParamIndex guards the index-skew bug: Insert
// collapses interior empty segments when building the trie, but used to number
// parameters with the RAW split index. ServeHTTP counts segments on the
// collapsed trie, so every param at or after a "//" silently bound to nothing
// — a 200 with an empty value, no panic and no log. Trivially reachable from
// string-concatenated base paths.
func TestInsert_CollapsedSegmentParamIndex(t *testing.T) {
	for _, tc := range []struct {
		name, pattern, key, request, want string
	}{
		{"interior double slash", "/a//b/{id}", "id", "/a/b/42", "42"},
		{"leading double slash", "//users/{id}", "id", "/users/7", "7"},
		{"before greedy", "/x//files/{p...}", "p", "/x/files/q/r", "q/r"},
		{"multiple params", "/a//b/{x}//c/{y}", "y", "/a/b/1/c/2", "2"},
		{"no empty segment", "/plain/{id}", "id", "/plain/9", "9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := NewMux()
			mux.GET(tc.pattern, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(r.PathValue(tc.key)))
			})

			rec := serve(mux, http.MethodGet, tc.request)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
			}
			if got := rec.Body.String(); got != tc.want {
				t.Errorf("PathValue(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}
