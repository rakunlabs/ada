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

func TestGroupPrefixUsesGroupErrorScope(t *testing.T) {
	mark := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Error-Scope", "group")
			next.ServeHTTP(w, r)
		})
	}

	t.Run("404 at prefix", func(t *testing.T) {
		mux := NewMux()
		group := mux.Group("/api", mark)
		group.NotFound(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "group not found", http.StatusNotFound)
		})

		rec := serve(mux, http.MethodGet, "/api")
		if rec.Code != http.StatusNotFound || rec.Body.String() != "group not found\n" {
			t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("X-Error-Scope"); got != "group" {
			t.Fatalf("scope header = %q", got)
		}
	})

	t.Run("405 and auto OPTIONS at prefix", func(t *testing.T) {
		mux := NewMux()
		group := mux.Group("/api", mark)
		group.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "group method", http.StatusMethodNotAllowed)
		})
		group.GET("", func(http.ResponseWriter, *http.Request) {})

		rec := serve(mux, http.MethodPost, "/api")
		if rec.Code != http.StatusMethodNotAllowed || rec.Body.String() != "group method\n" {
			t.Fatalf("POST: status = %d body = %q", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("X-Error-Scope"); got != "group" {
			t.Fatalf("POST: scope header = %q", got)
		}

		rec = serve(mux, http.MethodOptions, "/api")
		if rec.Code != http.StatusNoContent {
			t.Fatalf("OPTIONS: status = %d", rec.Code)
		}
		if got := rec.Header().Get("X-Error-Scope"); got != "group" {
			t.Fatalf("OPTIONS: scope header = %q", got)
		}
		if allow := rec.Header().Get("Allow"); allow != "GET, HEAD, OPTIONS" {
			t.Fatalf("OPTIONS: Allow = %q", allow)
		}
	})
}

func TestGroupErrorScopeRequiresSegmentBoundary(t *testing.T) {
	newMux := func(prefix string) *Mux {
		mux := NewMux()
		mux.NotFound(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "root", http.StatusNotFound)
		})
		group := mux.Group(prefix)
		group.NotFound(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "group", http.StatusNotFound)
		})

		return mux
	}

	for _, tc := range []struct {
		name   string
		prefix string
		path   string
		want   string
	}{
		{name: "static prefix", prefix: "/api", path: "/api", want: "group\n"},
		{name: "static descendant", prefix: "/api", path: "/api/x", want: "group\n"},
		{name: "static partial segment", prefix: "/api", path: "/apix", want: "root\n"},
		{name: "dynamic prefix", prefix: "/api/{id}", path: "/api/42", want: "group\n"},
		{name: "dynamic descendant", prefix: "/api/{id}", path: "/api/42/x", want: "group\n"},
		{name: "dynamic empty segment", prefix: "/api/{id}", path: "/api/", want: "root\n"},
		{name: "wildcard prefix", prefix: "/assets/*", path: "/assets/app.js", want: "group\n"},
		{name: "wildcard descendant", prefix: "/assets/*", path: "/assets/js/app.js", want: "group\n"},
		{name: "wildcard empty segment", prefix: "/assets/*", path: "/assets/", want: "root\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := serve(newMux(tc.prefix), http.MethodGet, tc.path)
			if rec.Code != http.StatusNotFound || rec.Body.String() != tc.want {
				t.Fatalf("status = %d body = %q, want %q", rec.Code, rec.Body.String(), tc.want)
			}
		})
	}

	t.Run("static partial segment keeps root 405 scope", func(t *testing.T) {
		mux := NewMux()
		mux.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "root method", http.StatusMethodNotAllowed)
		})
		group := mux.Group("/api")
		group.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "group method", http.StatusMethodNotAllowed)
		})
		mux.GET("/apix", func(http.ResponseWriter, *http.Request) {})

		rec := serve(mux, http.MethodPost, "/apix")
		if rec.Code != http.StatusMethodNotAllowed || rec.Body.String() != "root method\n" {
			t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
		}
	})
}

func TestWildcardGroupErrorScope(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		path   string
	}{
		{prefix: "/tenants/*", path: "/tenants/acme"},
		{prefix: "/files/{path...}", path: "/files/a/b"},
		{prefix: "/*", path: "/anything/deeper"},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			mux := NewMux()
			group := mux.Group(tc.prefix)
			group.NotFound(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "wildcard group", http.StatusNotFound)
			})

			rec := serve(mux, http.MethodGet, tc.path)
			if rec.Code != http.StatusNotFound || rec.Body.String() != "wildcard group\n" {
				t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestDuplicateGroupsUseStructuralErrorScope(t *testing.T) {
	mark := func(value string) MiddlewareFunc {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Group", value)
				next.ServeHTTP(w, r)
			})
		}
	}

	mux := NewMux()
	first := mux.Group("/shared", mark("first"))
	first.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "first", http.StatusMethodNotAllowed)
	})
	first.GET("/one", func(http.ResponseWriter, *http.Request) {})

	second := mux.Group("/shared", mark("second"))
	second.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "second", http.StatusMethodNotAllowed)
	})
	second.GET("/two", func(http.ResponseWriter, *http.Request) {})
	second.POST("/mixed", func(http.ResponseWriter, *http.Request) {})
	// Registering another method through the first Group does not change the
	// structural scope most recently claimed by the second Group.
	first.GET("/mixed", func(http.ResponseWriter, *http.Request) {})

	for _, path := range []string{"/shared/one", "/shared/two", "/shared/mixed"} {
		t.Run(path, func(t *testing.T) {
			rec := serve(mux, http.MethodDelete, path)
			if rec.Code != http.StatusMethodNotAllowed || rec.Body.String() != "second\n" {
				t.Fatalf("DELETE: status = %d body = %q", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("X-Group"); got != "second" {
				t.Fatalf("DELETE: X-Group = %q", got)
			}

			rec = serve(mux, http.MethodOptions, path)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("OPTIONS: status = %d", rec.Code)
			}
			if got := rec.Header().Get("X-Group"); got != "second" {
				t.Fatalf("OPTIONS: X-Group = %q", got)
			}
		})
	}

	first.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "first reclaimed", http.StatusMethodNotAllowed)
	})
	rec := serve(mux, http.MethodDelete, "/shared/two")
	if rec.Code != http.StatusMethodNotAllowed || rec.Body.String() != "first reclaimed\n" {
		t.Fatalf("reclaimed scope: status = %d body = %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Group"); got != "first" {
		t.Fatalf("reclaimed scope: X-Group = %q", got)
	}
}

func TestAllowIncludesExactAndGreedyMethods(t *testing.T) {
	mux := NewMux()
	mux.GET("/files/readme", func(http.ResponseWriter, *http.Request) {})
	mux.POST("/files/*", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("wildcard post"))
	})

	rec := serve(mux, http.MethodDelete, "/files/readme")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE: status = %d", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET, HEAD, OPTIONS, POST" {
		t.Fatalf("DELETE: Allow = %q", allow)
	}

	rec = serve(mux, http.MethodOptions, "/files/readme")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS: status = %d", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET, HEAD, OPTIONS, POST" {
		t.Fatalf("OPTIONS: Allow = %q", allow)
	}

	rec = serve(mux, http.MethodPost, "/files/readme")
	if rec.Code != http.StatusOK || rec.Body.String() != "wildcard post" {
		t.Fatalf("POST fallback: status = %d body = %q", rec.Code, rec.Body.String())
	}
}

func TestOverlappingGroupErrorScopePrecedence(t *testing.T) {
	type scope struct {
		prefix string
		label  string
	}

	tests := []struct {
		name   string
		path   string
		scopes []scope
		want   string
	}{
		{
			name: "dynamic scope through static terminal",
			path: "/users/me",
			scopes: []scope{
				{prefix: "/users/{id}", label: "dynamic"},
			},
			want: "dynamic",
		},
		{
			name: "wildcard scope through static terminal",
			path: "/users/me",
			scopes: []scope{
				{prefix: "/users/*", label: "wildcard"},
			},
			want: "wildcard",
		},
		{
			name: "static beats dynamic and wildcard at equal depth",
			path: "/users/me",
			scopes: []scope{
				{prefix: "/users/me", label: "static"},
				{prefix: "/users/{id}", label: "dynamic"},
				{prefix: "/users/*", label: "wildcard"},
			},
			want: "static",
		},
		{
			name: "dynamic beats wildcard at equal depth",
			path: "/users/me",
			scopes: []scope{
				{prefix: "/users/{id}", label: "dynamic"},
				{prefix: "/users/*", label: "wildcard"},
			},
			want: "dynamic",
		},
		{
			name: "deeper scope beats shallower static scope",
			path: "/users/me/settings",
			scopes: []scope{
				{prefix: "/users/me", label: "static"},
				{prefix: "/users/{id}/settings", label: "dynamic-deep"},
			},
			want: "dynamic-deep",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, routeFirst := range []bool{false, true} {
				name := "groups first"
				if routeFirst {
					name = "route first"
				}

				t.Run(name, func(t *testing.T) {
					mux := NewMux()
					registerRoute := func() {
						mux.GET(tc.path, func(w http.ResponseWriter, _ *http.Request) {
							_, _ = w.Write([]byte("static route"))
						})
					}
					if routeFirst {
						registerRoute()
					}

					for _, scope := range tc.scopes {
						label := scope.label
						group := mux.Group(scope.prefix, func(next http.Handler) http.Handler {
							return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								w.Header().Set("X-Error-Scope", label)
								next.ServeHTTP(w, r)
							})
						})
						group.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
							http.Error(w, label, http.StatusMethodNotAllowed)
						})
					}

					if !routeFirst {
						registerRoute()
					}

					rec := serve(mux, http.MethodGet, tc.path)
					if rec.Code != http.StatusOK || rec.Body.String() != "static route" {
						t.Fatalf("GET: status = %d body = %q", rec.Code, rec.Body.String())
					}
					if got := rec.Header().Get("X-Error-Scope"); got != "" {
						t.Fatalf("GET: error scope middleware ran: %q", got)
					}

					rec = serve(mux, http.MethodPost, tc.path)
					if rec.Code != http.StatusMethodNotAllowed || rec.Body.String() != tc.want+"\n" {
						t.Fatalf("POST: status = %d body = %q", rec.Code, rec.Body.String())
					}
					if got := rec.Header().Get("X-Error-Scope"); got != tc.want {
						t.Fatalf("POST: X-Error-Scope = %q, want %q", got, tc.want)
					}
					if allow := rec.Header().Get("Allow"); allow != "GET, HEAD, OPTIONS" {
						t.Fatalf("POST: Allow = %q", allow)
					}

					rec = serve(mux, http.MethodOptions, tc.path)
					if rec.Code != http.StatusNoContent {
						t.Fatalf("OPTIONS: status = %d", rec.Code)
					}
					if got := rec.Header().Get("X-Error-Scope"); got != tc.want {
						t.Fatalf("OPTIONS: X-Error-Scope = %q, want %q", got, tc.want)
					}
				})
			}
		})
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

// TestGroupInheritsLaterParentErrorConfig pins the regression where Group
// unconditionally claimed its prefix for error dispatch with a frozen copy of
// the parent. Because the prefix node pointed at the child Mux, a NotFound,
// MethodNotAllowed or Use applied to the parent afterwards rebuilt only the
// parent's chains and every 404/405 below the group kept answering with the
// defaults the child had captured at creation time.
func TestGroupInheritsLaterParentErrorConfig(t *testing.T) {
	t.Run("NotFound set after Group", func(t *testing.T) {
		mux := NewMux()
		group := mux.Group("/api")
		group.GET("/x", func(http.ResponseWriter, *http.Request) {})

		mux.NotFound(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "custom-404", http.StatusNotFound)
		})

		for _, path := range []string{"/missing", "/api/missing", "/api"} {
			rec := serve(mux, http.MethodGet, path)
			if rec.Code != http.StatusNotFound || rec.Body.String() != "custom-404\n" {
				t.Errorf("%s: status = %d body = %q", path, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("MethodNotAllowed set after Group", func(t *testing.T) {
		mux := NewMux()
		group := mux.Group("/api")
		group.GET("/x", func(http.ResponseWriter, *http.Request) {})
		mux.GET("/root", func(http.ResponseWriter, *http.Request) {})

		mux.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "custom-405", http.StatusMethodNotAllowed)
		})

		for _, path := range []string{"/root", "/api/x"} {
			rec := serve(mux, http.MethodPost, path)
			if rec.Code != http.StatusMethodNotAllowed || rec.Body.String() != "custom-405\n" {
				t.Errorf("%s: status = %d body = %q", path, rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Allow") == "" {
				t.Errorf("%s: Allow header must still be set", path)
			}
		}
	})

	t.Run("Use set after Group runs on group 404 and 405", func(t *testing.T) {
		mux := NewMux()
		group := mux.Group("/api")
		group.GET("/x", func(http.ResponseWriter, *http.Request) {})

		mux.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Root", "1")
				next.ServeHTTP(w, r)
			})
		})

		rec := serve(mux, http.MethodGet, "/api/missing")
		if rec.Code != http.StatusNotFound {
			t.Errorf("404: status = %d", rec.Code)
		}
		if got := rec.Header().Get("X-Root"); got != "1" {
			t.Errorf("404: X-Root = %q, want %q", got, "1")
		}

		rec = serve(mux, http.MethodPost, "/api/x")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("405: status = %d", rec.Code)
		}
		if got := rec.Header().Get("X-Root"); got != "1" {
			t.Errorf("405: X-Root = %q, want %q", got, "1")
		}

		rec = serve(mux, http.MethodOptions, "/api/x")
		if rec.Code != http.StatusNoContent {
			t.Errorf("OPTIONS: status = %d", rec.Code)
		}
		if got := rec.Header().Get("X-Root"); got != "1" {
			t.Errorf("OPTIONS: X-Root = %q, want %q", got, "1")
		}
	})

	t.Run("group override still wins over later parent", func(t *testing.T) {
		mux := NewMux()
		group := mux.Group("/api")
		group.NotFound(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "group-404", http.StatusNotFound)
		})

		mux.NotFound(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "root-404", http.StatusNotFound)
		})

		rec := serve(mux, http.MethodGet, "/api/missing")
		if rec.Code != http.StatusNotFound || rec.Body.String() != "group-404\n" {
			t.Errorf("/api/missing: status = %d body = %q", rec.Code, rec.Body.String())
		}

		rec = serve(mux, http.MethodGet, "/missing")
		if rec.Code != http.StatusNotFound || rec.Body.String() != "root-404\n" {
			t.Errorf("/missing: status = %d body = %q", rec.Code, rec.Body.String())
		}
	})

	// Overriding one behaviour must not detach the group from the others.
	t.Run("partial override inherits the rest", func(t *testing.T) {
		mux := NewMux()
		group := mux.Group("/api")
		group.NotFound(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "group-404", http.StatusNotFound)
		})
		group.GET("/x", func(http.ResponseWriter, *http.Request) {})

		mux.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "root-405", http.StatusMethodNotAllowed)
		})
		mux.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Root", "1")
				next.ServeHTTP(w, r)
			})
		})

		rec := serve(mux, http.MethodGet, "/api/missing")
		if rec.Code != http.StatusNotFound || rec.Body.String() != "group-404\n" {
			t.Errorf("404: status = %d body = %q", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("X-Root"); got != "1" {
			t.Errorf("404: X-Root = %q, want %q", got, "1")
		}

		rec = serve(mux, http.MethodPost, "/api/x")
		if rec.Code != http.StatusMethodNotAllowed || rec.Body.String() != "root-405\n" {
			t.Errorf("405: status = %d body = %q", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("X-Root"); got != "1" {
			t.Errorf("405: X-Root = %q, want %q", got, "1")
		}
	})

	t.Run("group middlewares survive a later parent Use", func(t *testing.T) {
		mark := func(header string) MiddlewareFunc {
			return func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("X-Order", header)
					next.ServeHTTP(w, r)
				})
			}
		}

		mux := NewMux()
		group := mux.Group("/api", mark("group"))
		group.GET("/x", func(http.ResponseWriter, *http.Request) {})

		mux.Use(mark("root"))

		rec := serve(mux, http.MethodGet, "/api/missing")
		got := rec.Header().Values("X-Order")
		// Root middleware is outermost; the group's own stays innermost.
		if len(got) != 2 || got[0] != "root" || got[1] != "group" {
			t.Errorf("X-Order = %v, want [root group]", got)
		}
	})
}

// TestNestedGroupInheritsLaterAncestorConfig checks the cascade reaches past
// one level: refresh has to walk the whole subtree, not just direct children.
func TestNestedGroupInheritsLaterAncestorConfig(t *testing.T) {
	mux := NewMux()
	api := mux.Group("/api")
	v1 := api.Group("/v1")
	v1.GET("/x", func(http.ResponseWriter, *http.Request) {})

	mux.NotFound(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "root-404", http.StatusNotFound)
	})
	mux.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Root", "1")
			next.ServeHTTP(w, r)
		})
	})

	rec := serve(mux, http.MethodGet, "/api/v1/missing")
	if rec.Code != http.StatusNotFound || rec.Body.String() != "root-404\n" {
		t.Fatalf("root cascade: status = %d body = %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Root"); got != "1" {
		t.Errorf("root cascade: X-Root = %q", got)
	}

	// An intermediate override stops the inheritance at that level only.
	api.NotFound(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "api-404", http.StatusNotFound)
	})

	rec = serve(mux, http.MethodGet, "/api/v1/missing")
	if rec.Code != http.StatusNotFound || rec.Body.String() != "api-404\n" {
		t.Fatalf("intermediate override: status = %d body = %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Root"); got != "1" {
		t.Errorf("intermediate override: X-Root = %q", got)
	}

	v1.NotFound(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "v1-404", http.StatusNotFound)
	})

	rec = serve(mux, http.MethodGet, "/api/v1/missing")
	if rec.Code != http.StatusNotFound || rec.Body.String() != "v1-404\n" {
		t.Fatalf("leaf override: status = %d body = %q", rec.Code, rec.Body.String())
	}

	rec = serve(mux, http.MethodGet, "/api/missing")
	if rec.Code != http.StatusNotFound || rec.Body.String() != "api-404\n" {
		t.Fatalf("api level: status = %d body = %q", rec.Code, rec.Body.String())
	}
}

// TestSiblingGroupsUnaffectedByEachOther pins that the parent/child cascade did
// not couple groups that only share a parent: neither their error handlers nor
// their middleware chains may leak sideways.
func TestSiblingGroupsUnaffectedByEachOther(t *testing.T) {
	mark := func(value string) MiddlewareFunc {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("X-Order", value)
				next.ServeHTTP(w, r)
			})
		}
	}

	mux := NewMux()
	a := mux.Group("/a", mark("a"))
	b := mux.Group("/b", mark("b"))

	a.NotFound(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "a-404", http.StatusNotFound)
	})
	b.Use(mark("b2"))
	mux.NotFound(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "root-404", http.StatusNotFound)
	})

	rec := serve(mux, http.MethodGet, "/a/missing")
	if rec.Body.String() != "a-404\n" {
		t.Errorf("/a: body = %q", rec.Body.String())
	}
	if got := rec.Header().Values("X-Order"); len(got) != 1 || got[0] != "a" {
		t.Errorf("/a: X-Order = %v, want [a]", got)
	}

	rec = serve(mux, http.MethodGet, "/b/missing")
	if rec.Body.String() != "root-404\n" {
		t.Errorf("/b: body = %q", rec.Body.String())
	}
	if got := rec.Header().Values("X-Order"); len(got) != 2 || got[0] != "b" || got[1] != "b2" {
		t.Errorf("/b: X-Order = %v, want [b b2]", got)
	}
}
