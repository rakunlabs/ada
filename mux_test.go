package ada

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestMux(t *testing.T) {
	type testHandler struct {
		name        string
		path        string
		method      string
		handler     http.HandlerFunc
		middlewares []func(next http.Handler) http.Handler
	}
	type testHandlerGroup struct {
		group       string
		handler     []testHandler
		middlewares []func(next http.Handler) http.Handler
	}
	type testWant struct {
		request func() *http.Request
		status  int
		body    string
		header  http.Header
	}
	type testCase struct {
		name         string
		handlerGroup []testHandlerGroup
		tests        []testWant
	}

	testCases := []testCase{
		{
			name: "Path parameter multiple and method match",
			handlerGroup: []testHandlerGroup{
				{
					handler: []testHandler{
						{
							name:   "GET /abc/{code_1}/test",
							path:   "/abc/{code_1}/test",
							method: http.MethodOptions,
							handler: func(w http.ResponseWriter, r *http.Request) {
								pathAsterisk := r.PathValue("code_1")
								w.Write([]byte("GET " + pathAsterisk))
							},
						},
						{
							name:   "GET /abc/{code_2}/signal",
							path:   "/abc/{code_2}/signal",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								code := r.PathValue("code_2")
								w.Write([]byte("GET " + code))
							},
						},
					},
				},
			},
			tests: []testWant{
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/abc/1234/signal", nil)
						return req
					},
					status: http.StatusOK,
					body:   "GET 1234",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodOptions, "/abc/yyy/test", nil)
						return req
					},
					status: http.StatusOK,
					body:   "GET yyy",
				},
			},
		},
		{
			handlerGroup: []testHandlerGroup{
				{
					handler: []testHandler{
						{
							name:   "OPTIONS /abc/*",
							path:   "/abc/*",
							method: http.MethodOptions,
							handler: func(w http.ResponseWriter, r *http.Request) {
								pathAsterisk := r.PathValue("*")
								w.Write([]byte("Asterisk: " + pathAsterisk))
							},
						},
						{
							name:   "GET /abc/{code}/signal",
							path:   "/abc/{code}/signal",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								code := r.PathValue("code")
								w.Write([]byte("GET " + code))
							},
						},
					},
				},
			},
			tests: []testWant{
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/abc/1234/signal", nil)
						return req
					},
					status: http.StatusOK,
					body:   "GET 1234",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodOptions, "/abc/yyy/signal", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Asterisk: yyy/signal",
				},
			},
		},
		{
			handlerGroup: []testHandlerGroup{
				{
					handler: []testHandler{
						{
							name:   "GET /abc/*",
							path:   "/abc/*",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								pathTest := r.PathValue("test")
								pathAsterisk := r.PathValue("*")
								w.Write([]byte("Test Param: " + pathTest + ", Asterisk: " + pathAsterisk))
							},
						},
						{
							name:   "GET /abc/{test}/dd/*",
							path:   "/abc/{test}/dd/*",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								pathTest := r.PathValue("test")
								pathAsterisk := r.PathValue("*")
								w.Write([]byte("Test Param: " + pathTest + ", Asterisk: " + pathAsterisk))
							},
						},
					},
				},
			},
			tests: []testWant{
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/abc/ee/none/1234", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Test Param: , Asterisk: ee/none/1234",
				},
			},
		},
		{
			handlerGroup: []testHandlerGroup{
				{
					handler: []testHandler{
						{
							name:   "GET /{test}/*",
							path:   "/{test}/*",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								pathTest := r.PathValue("test")
								pathAsterisk := r.PathValue("*")
								w.Write([]byte("Test Param: " + pathTest + ", Asterisk: " + pathAsterisk))
							},
						},
					},
				},
			},
			tests: []testWant{
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/mmmm/1234/vvv/555", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Test Param: mmmm, Asterisk: 1234/vvv/555",
				},
			},
		},
		{
			handlerGroup: []testHandlerGroup{
				{
					handler: []testHandler{
						{
							name:   "GET /",
							path:   "/",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Base!"))
							},
						},
						{
							name:   "GET /{test}",
							path:   "/{test}",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Test!"))
							},
						},
						{
							name:   "GET /grpc.reflection.v1alpha.ServerReflection/",
							path:   "/grpc.reflection.v1alpha.ServerReflection/",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("gRPC Reflection!"))
							},
						},
					},
				},
			},
			tests: []testWant{
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/grpc.reflection.v1alpha.ServerReflection/", nil)
						return req
					},
					status: http.StatusOK,
					body:   "gRPC Reflection!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Base!",
				},
			},
		},
		{
			handlerGroup: []testHandlerGroup{
				{
					handler: []testHandler{
						{
							name:   "GET /*",
							path:   "/*",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Wildcard!"))
							},
						},
						{
							name:   "GET /test",
							path:   "/test",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Test!"))
							},
						},
					},
				},
			},
			tests: []testWant{
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/wildcard/1/2/3/4", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Wildcard!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Wildcard!",
				},
			},
		},
		{
			handlerGroup: []testHandlerGroup{
				{
					handler: []testHandler{
						{
							name:   "GET /*",
							path:   "/*",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Wildcard!"))
							},
						},
						{
							name:   "GET /{test}",
							path:   "/{test}",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Test Param!"))
							},
						},
					},
				},
			},
			tests: []testWant{
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/wildcard/1/2/3/4", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Wildcard!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Wildcard!",
				},
			},
		},
		{
			handlerGroup: []testHandlerGroup{
				{
					group: "/",
					handler: []testHandler{
						{
							name:   "GET /",
							path:   "/",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Root!"))
							},
						},
						{
							name:   "GET /",
							path:   "/",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Root Override!"))
							},
						},
						{
							name:   "GET /どうしたの",
							path:   "/どうしたの",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("ありがとう"))
							},
						},
						{
							name:   "GET /どういたしまして",
							path:   "/どういたしまして",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("まあまあです"))
							},
						},
						{
							name:   "GET /*",
							path:   "/*",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Wildcard!"))
							},
						},
						{
							name:   "GET /*/under/1/2/3/4",
							path:   "/*/under/1/2/3/4",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Wildcard Under!"))
							},
						},
						{
							name:   "GET /*/under/1/2/3",
							path:   "/*/under/1/2/3",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Wildcard Under 1-2-3!"))
							},
						},
						{
							name:   "GET /*/under/*",
							path:   "/*/under/*",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Wildcard Under Wildcard!"))
							},
						},
					},
				},
				{
					group: "/base",
					handler: []testHandler{
						{
							name:   "GET /*",
							path:   "/*",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Base!"))
							},
						},
					},
				},
				{
					group: "/api/v1",
					middlewares: []func(next http.Handler) http.Handler{
						func(next http.Handler) http.Handler {
							return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								w.Header().Set("X-API-Version", "v1")
								next.ServeHTTP(w, r)
							})
						},
					},
					handler: []testHandler{
						{
							name:   "GET /hello",
							path:   "/hello",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Hello, world!"))
							},
						},
						{
							name:   "POST /hello",
							path:   "/hello",
							method: http.MethodPost,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(http.StatusAccepted)
								w.Write([]byte("OK!"))
							},
						},
						{
							name:   "GET /hell",
							path:   "/hell",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(http.StatusOK)
								w.Write([]byte("Welcome!"))
							},
						},
						{
							name:   "GET /how/1",
							path:   "/how/1",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(http.StatusOK)
								w.Write([]byte("how how!"))
							},
						},
						{
							name:   "GET /how/1/2/3/4",
							path:   "/how/1/2/3/4",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(http.StatusOK)
								w.Write([]byte("how how 4!"))
							},
						},
						{
							name:   "GET /ho/*",
							path:   "/ho/*",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(http.StatusOK)
								w.Write([]byte("ho ho ho *!"))
							},
						},
						{
							name:   "GET /how/{id}",
							path:   "/how/{id}",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								id := r.PathValue("id")
								w.WriteHeader(http.StatusOK)
								w.Write([]byte("how how " + id + "!"))
							},
						},
						{
							name: "/path/{user}",
							path: "/path/{user}",
							handler: func(w http.ResponseWriter, r *http.Request) {
								user := r.PathValue("user")
								w.WriteHeader(http.StatusCreated)
								w.Write([]byte("path user is " + user + "!"))
							},
						},
					},
				},
			},
			tests: []testWant{
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/api/v1/hello", nil)
						return req
					},
					header: http.Header{"X-Api-Version": {"v1"}},
					status: http.StatusOK,
					body:   "Hello, world!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodPost, "/api/v1/hello", nil)
						return req
					},
					header: http.Header{"X-Api-Version": {"v1"}},
					status: http.StatusAccepted,
					body:   "OK!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/api/v1/hell", nil)
						return req
					},
					header: http.Header{"X-Api-Version": {"v1"}},
					status: http.StatusOK,
					body:   "Welcome!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/api/v1/how/1", nil)
						return req
					},
					header: http.Header{"X-Api-Version": {"v1"}},
					status: http.StatusOK,
					body:   "how how!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/api/v1/how/1/2/3/4", nil)
						return req
					},
					header: http.Header{"X-Api-Version": {"v1"}},
					status: http.StatusOK,
					body:   "how how 4!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/api/v1/ho/12345", nil)
						return req
					},
					header: http.Header{"X-Api-Version": {"v1"}},
					status: http.StatusOK,
					body:   "ho ho ho *!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/api/v1/how/999", nil)
						return req
					},
					header: http.Header{"X-Api-Version": {"v1"}},
					status: http.StatusOK,
					body:   "how how 999!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Root Override!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/どういたしまして", nil)
						return req
					},
					status: http.StatusOK,
					body:   "まあまあです",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/どうしたの", nil)
						return req
					},
					status: http.StatusOK,
					body:   "ありがとう",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/api/v1/path/ada", nil)
						return req
					},
					status: http.StatusCreated,
					body:   "path user is ada!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodPost, "/api/v1/path/ada", nil)
						return req
					},
					status: http.StatusCreated,
					body:   "path user is ada!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/wildcard/1/2/3/4", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Wildcard!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/wildcard/under/1/2/3/4/5", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Wildcard Under Wildcard!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/wildcard/under/1/2/3/4", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Wildcard Under!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/wildcard-x/under/1/2/3", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Wildcard Under 1-2-3!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/base/", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Base!",
				},
			},
		},
		{
			name: "Group with empty path registration",
			handlerGroup: []testHandlerGroup{
				{
					group: "/api/v1/announcements",
					handler: []testHandler{
						{
							name:   "GET /self",
							path:   "/self",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("Self!"))
							},
						},
						{
							name:   "GET (empty - list)",
							path:   "",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("List!"))
							},
						},
						{
							name:   "POST (empty - create)",
							path:   "",
							method: http.MethodPost,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(http.StatusCreated)
								w.Write([]byte("Created!"))
							},
						},
						{
							name:   "GET /{id}",
							path:   "/{id}",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								id := r.PathValue("id")
								w.Write([]byte("ID: " + id))
							},
						},
					},
				},
			},
			tests: []testWant{
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/api/v1/announcements", nil)
						return req
					},
					status: http.StatusOK,
					body:   "List!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodPost, "/api/v1/announcements", nil)
						return req
					},
					status: http.StatusCreated,
					body:   "Created!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/api/v1/announcements/self", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Self!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/api/v1/announcements/abc123", nil)
						return req
					},
					status: http.StatusOK,
					body:   "ID: abc123",
				},
			},
		},
	}

	for _, tc := range testCases {
		mux := NewMux()
		for _, handler := range tc.handlerGroup {
			group := mux
			if handler.group != "" {
				group = mux.Group(handler.group, handler.middlewares...)
			}
			for _, h := range handler.handler {
				group.HandleWithMethod(h.method, h.path, h.handler, h.middlewares...)
			}
		}

		for _, test := range tc.tests {
			req := test.request()
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, req)

			if recorder.Code != test.status {
				t.Errorf("name [%s] expected status %d, got %d for request %s", tc.name, test.status, recorder.Code, req.URL.Path)
			}
			if recorder.Body.String() != test.body {
				t.Errorf("name [%s] expected body '%s', got '%s' for request %s", tc.name, test.body, recorder.Body.String(), req.URL.Path)
			}

			recordHeader := recorder.Header()
			for key, value := range test.header {
				if !slices.Equal(recordHeader[key], value) {
					t.Errorf("name [%s] expected header %s to be %v, got %v for request %s", tc.name, key, value, recordHeader[key], req.URL.Path)
				}
			}
		}
	}
}

func TestInsertStatic(t *testing.T) {
	mux := NewMux()
	mux.root.insertNodeTypeStatic("static")
	mux.root.insertNodeTypeStatic("stat")
	mux.root.insertNodeTypeStatic("alpha")

	if mux.root.StaticKey != "" {
		t.Errorf("expected root.StaticKey to be '', got '%s'", mux.root.StaticKey)
	}

	for _, c := range mux.root.StaticChildren {
		switch c.char {
		case 's':
			node := c.node
			if node.StaticKey != "stat" {
				t.Errorf("expected node.StaticKey to be 'stat', got '%s'", node.StaticKey)
			}
			if len(node.StaticChildren) == 0 {
				t.Errorf("expected node.StaticChildren to be non-empty")
			}
			for _, cc := range node.StaticChildren {
				switch cc.char {
				case 't':
					if cc.node.StaticKey != "ic" {
						t.Errorf("expected child.StaticKey to be 'ic', got '%s'", cc.node.StaticKey)
					}
				}
			}
		case 'a':
			node := c.node
			if node.StaticKey != "alpha" {
				t.Errorf("expected node.StaticKey to be 'alpha', got '%s'", node.StaticKey)
			}
			if len(node.StaticChildren) != 0 {
				t.Errorf("expected node.StaticChildren to be zero length")
			}
		}
	}
}

func TestUse(t *testing.T) {
	mux := NewMux()

	groupTest := mux.Group("/test")

	groupTest.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				w.Write([]byte("OK"))
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// Use HandleFunc to register for all methods, allowing middleware to intercept OPTIONS
	groupTest.HandleFunc("/xxx", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("GET Test"))
	})

	// OPTIONS request should be intercepted by middleware
	reqOptions, _ := http.NewRequest(http.MethodOptions, "/test/abc", nil)
	recorderOptions := httptest.NewRecorder()
	mux.ServeHTTP(recorderOptions, reqOptions)

	if recorderOptions.Body.String() != "OK" {
		t.Errorf("expected OPTIONS middleware to return 'OK', got '%s'", recorderOptions.Body.String())
	}

	// OPTIONS request should be intercepted by middleware
	reqOptions, _ = http.NewRequest(http.MethodOptions, "/test/xxx", nil)
	recorderOptions = httptest.NewRecorder()
	mux.ServeHTTP(recorderOptions, reqOptions)

	if recorderOptions.Body.String() != "OK" {
		t.Errorf("expected OPTIONS middleware to return 'OK', got '%s'", recorderOptions.Body.String())
	}

	// OPTIONS request should not be intercepted by middleware
	reqOptions, _ = http.NewRequest(http.MethodOptions, "/abc/xxx", nil)
	recorderOptions = httptest.NewRecorder()
	mux.ServeHTTP(recorderOptions, reqOptions)

	if recorderOptions.Body.String() != "404 page not found\n" {
		t.Errorf("expected OPTIONS middleware to return '404 page not found', got '%s'", recorderOptions.Body.String())
	}

	reqGet, _ := http.NewRequest(http.MethodGet, "/test/xxx", nil)
	recorderGet := httptest.NewRecorder()
	mux.ServeHTTP(recorderGet, reqGet)

	if recorderGet.Body.String() != "GET Test" {
		t.Errorf("expected GET /test to return 'GET Test', got '%s'", recorderGet.Body.String())
	}
}

func TestMethodNotAllowed(t *testing.T) {
	t.Run("basic 405", func(t *testing.T) {
		mux := NewMux()
		mux.GET("/users", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("users"))
		})

		req, _ := http.NewRequest(http.MethodPost, "/users", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rec.Code)
		}

		allow := rec.Header().Get("Allow")
		if !strings.Contains(allow, "GET") {
			t.Fatalf("expected Allow header to contain GET, got %q", allow)
		}
		if !strings.Contains(allow, "HEAD") {
			t.Fatalf("expected Allow header to contain HEAD (auto), got %q", allow)
		}
		if !strings.Contains(allow, "OPTIONS") {
			t.Fatalf("expected Allow header to contain OPTIONS (auto), got %q", allow)
		}
	})

	t.Run("multiple methods", func(t *testing.T) {
		mux := NewMux()
		mux.GET("/users", func(w http.ResponseWriter, r *http.Request) {})
		mux.POST("/users", func(w http.ResponseWriter, r *http.Request) {})

		req, _ := http.NewRequest(http.MethodDelete, "/users", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rec.Code)
		}

		allow := rec.Header().Get("Allow")
		if !strings.Contains(allow, "GET") || !strings.Contains(allow, "POST") {
			t.Fatalf("expected Allow to contain GET and POST, got %q", allow)
		}
	})

	t.Run("custom 405 handler", func(t *testing.T) {
		mux := NewMux()
		mux.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte(`{"error":"method not allowed"}`))
		})
		mux.GET("/users", func(w http.ResponseWriter, r *http.Request) {})

		req, _ := http.NewRequest(http.MethodPut, "/users", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rec.Code)
		}
		if rec.Body.String() != `{"error":"method not allowed"}` {
			t.Fatalf("expected custom body, got %q", rec.Body.String())
		}
		if rec.Header().Get("Allow") == "" {
			t.Fatal("expected Allow header to be set even with custom handler")
		}
	})

	t.Run("404 for nonexistent path", func(t *testing.T) {
		mux := NewMux()
		mux.GET("/users", func(w http.ResponseWriter, r *http.Request) {})

		req, _ := http.NewRequest(http.MethodGet, "/nope", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rec.Code)
		}
		if rec.Header().Get("Allow") != "" {
			t.Fatalf("expected no Allow header on 404, got %q", rec.Header().Get("Allow"))
		}
	})

	t.Run("catch-all handler accepts any method", func(t *testing.T) {
		mux := NewMux()
		mux.HandleFunc("/any", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("any"))
		})

		// HandleFunc registers with empty method — accepts all methods
		req, _ := http.NewRequest(http.MethodDelete, "/any", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if rec.Body.String() != "any" {
			t.Fatalf("expected 'any', got %q", rec.Body.String())
		}
	})
}

func TestAutoHead(t *testing.T) {
	t.Run("HEAD uses GET handler", func(t *testing.T) {
		mux := NewMux()
		mux.GET("/users", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Custom", "value")
			w.Write([]byte("users"))
		})

		req, _ := http.NewRequest(http.MethodHead, "/users", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		if rec.Header().Get("X-Custom") != "value" {
			t.Fatalf("expected X-Custom header from GET handler, got %q", rec.Header().Get("X-Custom"))
		}
	})

	t.Run("explicit HEAD overrides auto", func(t *testing.T) {
		mux := NewMux()
		mux.GET("/users", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Source", "get")
		})
		mux.HEAD("/users", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Source", "head")
		})

		req, _ := http.NewRequest(http.MethodHead, "/users", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Header().Get("X-Source") != "head" {
			t.Fatalf("expected explicit HEAD handler, got X-Source=%q", rec.Header().Get("X-Source"))
		}
	})

	t.Run("HEAD 405 when only POST registered", func(t *testing.T) {
		mux := NewMux()
		mux.POST("/users", func(w http.ResponseWriter, r *http.Request) {})

		req, _ := http.NewRequest(http.MethodHead, "/users", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 for HEAD when only POST registered, got %d", rec.Code)
		}
	})
}

func TestAutoOptions(t *testing.T) {
	t.Run("auto OPTIONS with Allow header", func(t *testing.T) {
		mux := NewMux()
		mux.GET("/users", func(w http.ResponseWriter, r *http.Request) {})
		mux.POST("/users", func(w http.ResponseWriter, r *http.Request) {})

		req, _ := http.NewRequest(http.MethodOptions, "/users", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rec.Code)
		}

		allow := rec.Header().Get("Allow")
		if !strings.Contains(allow, "GET") || !strings.Contains(allow, "POST") {
			t.Fatalf("expected Allow to contain GET and POST, got %q", allow)
		}
		if !strings.Contains(allow, "HEAD") {
			t.Fatalf("expected Allow to include HEAD (auto from GET), got %q", allow)
		}
		if !strings.Contains(allow, "OPTIONS") {
			t.Fatalf("expected Allow to include OPTIONS, got %q", allow)
		}
	})

	t.Run("explicit OPTIONS overrides auto", func(t *testing.T) {
		mux := NewMux()
		mux.GET("/users", func(w http.ResponseWriter, r *http.Request) {})
		mux.OPTIONS("/users", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Source", "explicit")
			w.WriteHeader(http.StatusOK)
		})

		req, _ := http.NewRequest(http.MethodOptions, "/users", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Header().Get("X-Source") != "explicit" {
			t.Fatalf("expected explicit OPTIONS handler, got X-Source=%q", rec.Header().Get("X-Source"))
		}
	})

	t.Run("OPTIONS 404 for nonexistent path", func(t *testing.T) {
		mux := NewMux()

		req, _ := http.NewRequest(http.MethodOptions, "/nope", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for OPTIONS on nonexistent path, got %d", rec.Code)
		}
	})
}

func TestMux_Prefix(t *testing.T) {
	mux := NewMux()

	mux = mux.Group("")
	if mux.Prefix() != "" {
		t.Errorf("expected root mux prefix to be '', got '%s'", mux.Prefix())
	}

	group := mux.Group("/api/v1")
	if group.Prefix() != "/api/v1" {
		t.Errorf("expected group mux prefix to be '/api/v1', got '%s'", group.Prefix())
	}

	subGroup := group.Group("/users")
	if subGroup.Prefix() != "/api/v1/users" {
		t.Errorf("expected subgroup mux prefix to be '/api/v1/users', got '%s'", subGroup.Prefix())
	}
}
