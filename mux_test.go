package ada

import (
	"io"
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
								_, _ = w.Write([]byte("GET " + pathAsterisk))
							},
						},
						{
							name:   "GET /abc/{code_2}/signal",
							path:   "/abc/{code_2}/signal",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								code := r.PathValue("code_2")
								_, _ = w.Write([]byte("GET " + code))
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
								_, _ = w.Write([]byte("Asterisk: " + pathAsterisk))
							},
						},
						{
							name:   "GET /abc/{code}/signal",
							path:   "/abc/{code}/signal",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								code := r.PathValue("code")
								_, _ = w.Write([]byte("GET " + code))
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
								_, _ = w.Write([]byte("Test Param: " + pathTest + ", Asterisk: " + pathAsterisk))
							},
						},
						{
							name:   "GET /abc/{test}/dd/*",
							path:   "/abc/{test}/dd/*",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								pathTest := r.PathValue("test")
								pathAsterisk := r.PathValue("*")
								_, _ = w.Write([]byte("Test Param: " + pathTest + ", Asterisk: " + pathAsterisk))
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
								_, _ = w.Write([]byte("Test Param: " + pathTest + ", Asterisk: " + pathAsterisk))
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
								_, _ = w.Write([]byte("Base!"))
							},
						},
						{
							name:   "GET /{test}",
							path:   "/{test}",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								_, _ = w.Write([]byte("Test!"))
							},
						},
						{
							name:   "GET /grpc.reflection.v1alpha.ServerReflection/",
							path:   "/grpc.reflection.v1alpha.ServerReflection/",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								_, _ = w.Write([]byte("gRPC Reflection!"))
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
								_, _ = w.Write([]byte("Wildcard!"))
							},
						},
						{
							name:   "GET /test",
							path:   "/test",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								_, _ = w.Write([]byte("Test!"))
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
								_, _ = w.Write([]byte("Wildcard!"))
							},
						},
						{
							name:   "GET /{test}",
							path:   "/{test}",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								_, _ = w.Write([]byte("Test Param!"))
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
								_, _ = w.Write([]byte("Root!"))
							},
						},
						{
							name:   "GET /",
							path:   "/",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								_, _ = w.Write([]byte("Root Override!"))
							},
						},
						{
							name:   "GET /どうしたの",
							path:   "/どうしたの",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								_, _ = w.Write([]byte("ありがとう"))
							},
						},
						{
							name:   "GET /どういたしまして",
							path:   "/どういたしまして",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								_, _ = w.Write([]byte("まあまあです"))
							},
						},
						{
							name:   "GET /*",
							path:   "/*",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								_, _ = w.Write([]byte("Wildcard!"))
							},
						},
						{
							name:   "GET /*/under/1/2/3/4",
							path:   "/*/under/1/2/3/4",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								_, _ = w.Write([]byte("Wildcard Under!"))
							},
						},
						{
							name:   "GET /*/under/1/2/3",
							path:   "/*/under/1/2/3",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								_, _ = w.Write([]byte("Wildcard Under 1-2-3!"))
							},
						},
						{
							// Migrated from "/*/under/*" — the old
							// double-wildcard form is now rejected at
							// register time (use `{name}` for middle
							// captures or `{name...}` for trailing
							// greedy ones). Semantic equivalent: first
							// segment by bare `*`, rest of the path by
							// the greedy `{rest...}`.
							name:   "GET /*/under/{rest...}",
							path:   "/*/under/{rest...}",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								_, _ = w.Write([]byte("Wildcard Under Wildcard!"))
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
								_, _ = w.Write([]byte("Base!"))
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
								_, _ = w.Write([]byte("Hello, world!"))
							},
						},
						{
							name:   "POST /hello",
							path:   "/hello",
							method: http.MethodPost,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(http.StatusAccepted)
								_, _ = w.Write([]byte("OK!"))
							},
						},
						{
							name:   "GET /hell",
							path:   "/hell",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(http.StatusOK)
								_, _ = w.Write([]byte("Welcome!"))
							},
						},
						{
							name:   "GET /how/1",
							path:   "/how/1",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(http.StatusOK)
								_, _ = w.Write([]byte("how how!"))
							},
						},
						{
							name:   "GET /how/1/2/3/4",
							path:   "/how/1/2/3/4",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(http.StatusOK)
								_, _ = w.Write([]byte("how how 4!"))
							},
						},
						{
							name:   "GET /ho/*",
							path:   "/ho/*",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(http.StatusOK)
								_, _ = w.Write([]byte("ho ho ho *!"))
							},
						},
						{
							name:   "GET /how/{id}",
							path:   "/how/{id}",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								id := r.PathValue("id")
								w.WriteHeader(http.StatusOK)
								_, _ = w.Write([]byte("how how " + id + "!"))
							},
						},
						{
							name: "/path/{user}",
							path: "/path/{user}",
							handler: func(w http.ResponseWriter, r *http.Request) {
								user := r.PathValue("user")
								w.WriteHeader(http.StatusCreated)
								_, _ = w.Write([]byte("path user is " + user + "!"))
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
								_, _ = w.Write([]byte("Self!"))
							},
						},
						{
							name:   "GET (empty - list)",
							path:   "",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								_, _ = w.Write([]byte("List!"))
							},
						},
						{
							name:   "POST (empty - create)",
							path:   "",
							method: http.MethodPost,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(http.StatusCreated)
								_, _ = w.Write([]byte("Created!"))
							},
						},
						{
							name:   "GET /{id}",
							path:   "/{id}",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								id := r.PathValue("id")
								_, _ = w.Write([]byte("ID: " + id))
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
	root := mux.routes.live
	root.insertNodeTypeStatic("static")
	root.insertNodeTypeStatic("stat")
	root.insertNodeTypeStatic("alpha")

	if root.StaticKey != "" {
		t.Errorf("expected root.StaticKey to be '', got '%s'", root.StaticKey)
	}

	for _, c := range root.StaticChildren {
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
				_, _ = w.Write([]byte("OK"))
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// Use HandleFunc to register for all methods, allowing middleware to intercept OPTIONS
	groupTest.HandleFunc("/xxx", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("GET Test"))
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

func TestUse_NotFoundMiddlewareRunsOnce(t *testing.T) {
	mux := NewMux()

	var count int
	mux.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count++
			next.ServeHTTP(w, r)
		})
	})

	mux.GET("/exists", func(w http.ResponseWriter, r *http.Request) {})

	// Unmatched path: middleware must run exactly once, response is 404.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	if count != 1 {
		t.Fatalf("expected middleware to run once on 404, ran %d times", count)
	}

	// Matched path: middleware must also run exactly once.
	count = 0
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/exists", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if count != 1 {
		t.Fatalf("expected middleware to run once on match, ran %d times", count)
	}
}

func TestGreedyParam_StaticOverlapFallback(t *testing.T) {
	mux := NewMux()

	var gotP, gotStar string
	mux.GET("/files/{p...}", func(w http.ResponseWriter, r *http.Request) {
		gotP = r.PathValue("p")
		gotStar = r.PathValue("*")
		_, _ = w.Write([]byte("wild"))
	})
	mux.GET("/files/static/logo.png", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("static"))
	})

	// Request goes deeper than the static route — must fall back to the
	// greedy wildcard and bind the FULL remainder under its name "p".
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/files/static/logo.png/extra", nil))

	if rec.Body.String() != "wild" {
		t.Fatalf("expected wildcard handler, got body %q (status %d)", rec.Body.String(), rec.Code)
	}
	if gotP != "static/logo.png/extra" {
		t.Fatalf("expected PathValue(p)=%q, got %q (PathValue(*)=%q)", "static/logo.png/extra", gotP, gotStar)
	}
}

func TestQueryMethod(t *testing.T) {
	mux := NewMux()
	mux.QUERY("/search", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write([]byte("query: " + string(body)))
	})

	// QUERY request with a body is routed to the handler
	req := httptest.NewRequest(MethodQuery, "/search", strings.NewReader("name=ada"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != "query: name=ada" {
		t.Fatalf("expected body 'query: name=ada', got '%s'", rec.Body.String())
	}

	// Other methods on the same path return 405 with QUERY in Allow header
	req = httptest.NewRequest(http.MethodPost, "/search", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, MethodQuery) {
		t.Fatalf("expected Allow header to contain QUERY, got '%s'", allow)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	t.Run("basic 405", func(t *testing.T) {
		mux := NewMux()
		mux.GET("/users", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("users"))
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
			_, _ = w.Write([]byte(`{"error":"method not allowed"}`))
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
			_, _ = w.Write([]byte("any"))
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
			_, _ = w.Write([]byte("users"))
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

// TestGroup_SiblingMiddlewareIsolation guards against a slice-aliasing bug
// where two sibling groups created from the same parent would share the
// parent's middleware backing array, so a Use() on one sibling could
// silently overwrite a Use() entry on another sibling whenever the shared
// backing array still had spare capacity.
//
// Reproduction shape (matches a real bug observed in pika):
//
//	parent := root.Group("")
//	a := parent.Group("")
//	b := parent.Group("")
//	a.Use(mwA) // appends at index N of the shared backing array
//	b.Use(mwB) // append into b (still len N) overwrites index N in place
//
// After the buggy sequence, a request handled by `a` ran mwB instead of mwA.
func TestGroup_SiblingMiddlewareIsolation(t *testing.T) {
	mux := NewMux()

	// Force the parent's middleware backing array to have spare capacity
	// before children are derived. Without spare capacity, append() in
	// each child reallocates onto a fresh array and the aliasing bug
	// stays hidden behind the allocator's whim. With spare capacity,
	// an in-place append on one sibling writes into a slot another
	// sibling already considers part of its own chain — that's exactly
	// the pika regression this test guards against.
	noop := func(next http.Handler) http.Handler { return next }
	mux.middlewares = make([]func(next http.Handler) http.Handler, 1, 8)
	mux.middlewares[0] = noop

	a := mux.Group("/a")
	b := mux.Group("/b")

	// Sibling A registers a middleware that writes "A" before delegating.
	a.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("A:"))
			next.ServeHTTP(w, r)
		})
	})

	// Sibling B then registers its own middleware that writes "B".
	// With the aliasing bug, this append-in-place stomps over A's entry
	// in the shared backing array, so requests routed to A will run B's
	// middleware instead of A's.
	b.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("B:"))
			next.ServeHTTP(w, r)
		})
	})

	a.GET("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("a-handler"))
	})
	b.GET("/ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("b-handler"))
	})

	for _, tc := range []struct {
		name, path, want string
	}{
		{"sibling A keeps its own middleware", "/a/ping", "A:a-handler"},
		{"sibling B keeps its own middleware", "/b/ping", "B:b-handler"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if got := rec.Body.String(); got != tc.want {
				t.Errorf("path %s: got %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestMiddleWildcard_PathValue guards against a regression where a `*`
// segment that appears in the MIDDLE of a route pattern (i.e. with more
// static or wildcard segments after it) silently failed to expose its
// captured value via r.PathValue("*").
//
// Reproduction shape (matches a real bug observed in pika's
// /api/v1/external/*/test handler — every request returned an empty
// resource name regardless of what the caller sent):
//
//	mux.POST("/api/v1/external/*/test", h)
//	// GET /api/v1/external/myname/test
//	// r.PathValue("*") returned "" instead of "myname"
//
// Root cause was that `node.Possible` is only set on routes whose LAST
// segment is `*`, so the trailing-static leaf reached by walking
// `/api/v1/external/myname/test` had Possible=false and the wildcard
// reconstruction block at the end of ServeHTTP never ran. Additionally
// `possibleOffset` was only updated when the wildcard-children node's
// Possible flag was true — also never the case for middle wildcards —
// so even if we had run the reconstruction the offset would have been
// 0 and we'd have returned the entire URL path.
//
// The fix has to (a) remember where each middle `*` segment started in
// the URL, and (b) make that captured value retrievable through
// PathValue. We retain the existing trailing-`*` semantics (greedy,
// joined with /) and add per-index access for middle ones — both via
// PathValue("*") (when only one wildcard exists) and via
// PathValue("*N") for ambiguous routes with multiple `*` segments.
func TestMiddleWildcard_PathValue(t *testing.T) {
	type tc struct {
		name      string
		pattern   string
		request   string
		wantValue string
		// captureKey is the name passed to r.PathValue() inside the
		// handler. For routes with a single `*` segment we always
		// support "*"; the "*N" indexed form is only required when a
		// pattern has multiple wildcards.
		captureKey string
	}

	cases := []tc{
		{
			name:       "middle wildcard exposes captured segment",
			pattern:    "/api/v1/external/*/test",
			request:    "/api/v1/external/myname/test",
			wantValue:  "myname",
			captureKey: "*",
		},
		{
			name:       "middle wildcard with hyphens and dots in segment",
			pattern:    "/api/v1/external/*/test",
			request:    "/api/v1/external/foo-bar.baz/test",
			wantValue:  "foo-bar.baz",
			captureKey: "*",
		},
		{
			name:       "trailing wildcard continues to work after the fix",
			pattern:    "/api/v1/files/*",
			request:    "/api/v1/files/deep/nested/path.txt",
			wantValue:  "deep/nested/path.txt",
			captureKey: "*",
		},
		{
			name:       "middle wildcard between two statics",
			pattern:    "/users/*/profile",
			request:    "/users/alice/profile",
			wantValue:  "alice",
			captureKey: "*",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mux := NewMux()
			mux.GET(c.pattern, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(r.PathValue(c.captureKey)))
			})

			req := httptest.NewRequest(http.MethodGet, c.request, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("request %s: status=%d body=%q", c.request, rec.Code, rec.Body.String())
			}
			if got := rec.Body.String(); got != c.wantValue {
				t.Errorf("request %s captureKey=%q: got %q, want %q",
					c.request, c.captureKey, got, c.wantValue)
			}
		})
	}
}

// TestMiddleWildcard_DoesNotCrossSlashes documents that a middle `*`
// segment matches exactly one path segment — extra segments cause a
// 404, they do NOT silently fall through to a more permissive handler.
// This contract matters because the fix had to carefully avoid making
// middle wildcards greedy as a side-effect of exposing their captured
// value.
func TestMiddleWildcard_DoesNotCrossSlashes(t *testing.T) {
	mux := NewMux()
	mux.GET("/users/*/profile", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hit:" + r.PathValue("*")))
	})

	req := httptest.NewRequest(http.MethodGet, "/users/alice/bob/profile", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for /users/alice/bob/profile, got %d: %q",
			rec.Code, rec.Body.String())
	}
}

// TestGreedyNamedWildcard exercises the `{name...}` syntax — a NAMED
// greedy trailing wildcard that consumes the rest of the path
// (including embedded slashes) and exposes its value under the given
// identifier. This is the supported replacement for "I want a second
// `*` in my route": you either use bare `*` once (anywhere), or use
// `{name...}` once at the end, or both. The combination cases live in
// their own tests below.
//
// Semantics:
//   - `/files/a/b/c.txt`  → `path = "a/b/c.txt"`  (multi-segment)
//   - `/files/x`          → `path = "x"`          (single segment)
//   - `/files/`           → `path = ""`            (empty trailing segment)
//   - `/files`            → 404                   (no slash separator)
func TestGreedyNamedWildcard(t *testing.T) {
	type want struct {
		status int
		body   string
	}
	cases := []struct {
		name    string
		request string
		want    want
	}{
		{"multi-segment value", "/files/a/b/c.txt", want{200, "a/b/c.txt"}},
		{"single-segment value", "/files/x", want{200, "x"}},
		{"trailing slash empty segment", "/files/", want{200, ""}},
		{"no slash separator → 404", "/files", want{404, ""}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mux := NewMux()
			mux.GET("/files/{path...}", func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(r.PathValue("path")))
			})

			req := httptest.NewRequest(http.MethodGet, c.request, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != c.want.status {
				t.Fatalf("request %s: status=%d (want %d) body=%q",
					c.request, rec.Code, c.want.status, rec.Body.String())
			}
			if c.want.status == 200 {
				if got := rec.Body.String(); got != c.want.body {
					t.Errorf("request %s: body %q, want %q",
						c.request, got, c.want.body)
				}
			}
		})
	}
}

func TestTrailingWildcardEmptySegmentCompatibility(t *testing.T) {
	t.Run("bare wildcard", func(t *testing.T) {
		mux := NewMux()
		mux.GET("/view/*", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(r.PathValue("*")))
		})

		for _, tc := range []struct {
			path string
			code int
		}{
			{path: "/view", code: http.StatusNotFound},
			{path: "/view/", code: http.StatusOK},
			{path: "/view/app", code: http.StatusOK},
			{path: "/", code: http.StatusNotFound},
		} {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != tc.code {
				t.Errorf("%s status = %d, want %d", tc.path, rec.Code, tc.code)
			}
		}
	})

	t.Run("root wildcard", func(t *testing.T) {
		mux := NewMux()
		mux.HandleFunc("/*", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		mux := NewMux()
		mux.POST("/view/*", func(http.ResponseWriter, *http.Request) {})

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/view/", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
		}
		if got := rec.Header().Get("Allow"); got != "OPTIONS, POST" {
			t.Fatalf("Allow = %q, want %q", got, "OPTIONS, POST")
		}
	})

	// Empty segments match nothing — Mux applies no path cleaning, and an
	// interior empty segment is not a capturable value. The only exception
	// is the empty FINAL segment a trailing slash supplies, covered above.
	// A remainder that begins with '/' (i.e. "//" right after the wildcard's
	// separator) therefore stays a 404 rather than capturing "/...".
	// net/http.ServeMux would match these; the divergence is deliberate and
	// documented in the routing guide.
	t.Run("double slash never starts a capture", func(t *testing.T) {
		serve := func(mux *Mux, path string) (int, string) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://x", nil)
			req.URL.Path = path // bypass client-side path cleaning

			mux.ServeHTTP(rec, req)

			return rec.Code, rec.Body.String()
		}

		mux := NewMux()
		mux.GET("/view/*", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(r.PathValue("*")))
		})

		for _, tc := range []struct {
			path string
			code int
			body string
		}{
			{path: "/view//", code: http.StatusNotFound},
			{path: "/view//app", code: http.StatusNotFound},
			// Embedded empty segments past the first captured one are kept
			// verbatim: the greedy already started, the raw tail is the value.
			{path: "/view/app//", code: http.StatusOK, body: "app//"},
			{path: "/view/app//b", code: http.StatusOK, body: "app//b"},
		} {
			code, body := serve(mux, tc.path)
			if code != tc.code {
				t.Errorf("%s status = %d, want %d", tc.path, code, tc.code)
			}
			if tc.code == http.StatusOK && body != tc.body {
				t.Errorf("%s body = %q, want %q", tc.path, body, tc.body)
			}
		}

		// Same rule at the root: "//" leaves the wildcard's remainder
		// starting on '/', so it cannot begin a capture...
		root := NewMux()
		root.GET("/*", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("root:" + r.PathValue("*")))
		})

		if code, _ := serve(root, "//"); code != http.StatusNotFound {
			t.Errorf("// status = %d, want 404", code)
		}

		// ...while a shallower greedy that already started keeps the raw
		// tail, empty segments included.
		if code, body := serve(root, "/view//"); code != http.StatusOK || body != "root:view//" {
			t.Errorf("/view// = %d %q, want 200 %q", code, body, "root:view//")
		}
	})
}

// TestGreedyTrailingSlashPatternPanics locks the registration-time rule that a
// greedy `{name...}` must be the last RAW segment of the pattern. Before this
// check, "/files/{p...}/" slipped through validation and silently behaved as a
// single-segment match followed by '/', contradicting the greedy syntax.
// net/http.ServeMux rejects the same shape.
func TestGreedyTrailingSlashPatternPanics(t *testing.T) {
	for _, pattern := range []string{
		"/files/{p...}/",
		"/files/{p...}//",
		"/{p...}/",
	} {
		t.Run(pattern, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("registering %q did not panic", pattern)
				}
			}()

			NewMux().GET(pattern, func(http.ResponseWriter, *http.Request) {})
		})
	}

	// The middle-star composition stays legal: "/a/*/" is one segment then a
	// trailing slash, exactly like "/a/*/x" is one segment then "/x".
	t.Run("middle star with trailing slash stays valid", func(t *testing.T) {
		mux := NewMux()
		mux.GET("/a/*/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(r.PathValue("*")))
		})

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/a/x/", nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "x" {
			t.Fatalf("/a/x/ = %d %q, want 200 %q", rec.Code, rec.Body.String(), "x")
		}
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/a/x", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("/a/x = %d, want 404", rec.Code)
		}
	})
}

// TestGreedyNamedWildcard_WithMiddleStar shows the recommended way to
// have two captures in one route: a middle `*` plus a trailing
// `{name...}`. Each is reachable under its own PathValue key.
func TestGreedyNamedWildcard_WithMiddleStar(t *testing.T) {
	mux := NewMux()
	mux.GET("/teams/*/files/{path...}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.PathValue("*") + "|" + r.PathValue("path")))
	})

	req := httptest.NewRequest(http.MethodGet, "/teams/red/files/dir/sub/x.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got, want := rec.Body.String(), "red|dir/sub/x.json"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestGreedyAlongsideRegularParams confirms `{name...}` composes
// freely with single-segment params on the same route. Distinct
// PathValue keys, no special-casing.
func TestGreedyAlongsideRegularParams(t *testing.T) {
	mux := NewMux()
	mux.GET("/users/{id}/files/{path...}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.PathValue("id") + "|" + r.PathValue("path")))
	})

	req := httptest.NewRequest(http.MethodGet, "/users/42/files/docs/a.md", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got, want := rec.Body.String(), "42|docs/a.md"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestGreedyMultipleCaptures exercises regular parameters followed by a greedy
// capture, including an empty trailing segment.
//
// Pattern: /users/{name}/files/{path...}
//
//	GET /users/alice/files/docs/note.md → name=alice path=docs/note.md
//	GET /users/bob/files/               → name=bob path=""
//	GET /users/bob/files                → 404
func TestGreedyMultipleCaptures(t *testing.T) {
	mux := NewMux()
	mux.GET("/users/{name}/files/{path...}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.PathValue("name") + "|" + r.PathValue("path")))
	})

	type want struct {
		status int
		body   string
	}
	cases := []struct {
		request string
		want    want
	}{
		{"/users/alice/files/docs/note.md", want{200, "alice|docs/note.md"}},
		{"/users/bob/files/", want{200, "bob|"}},
		{"/users/bob/files", want{404, ""}},
	}

	for _, c := range cases {
		t.Run(c.request, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, c.request, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != c.want.status {
				t.Fatalf("status=%d (want %d) body=%q",
					rec.Code, c.want.status, rec.Body.String())
			}
			if c.want.status == 200 && rec.Body.String() != c.want.body {
				t.Errorf("body %q, want %q", rec.Body.String(), c.want.body)
			}
		})
	}
}

// TestDocExample_ThreeMiddleParamsPlusGreedy covers the doc snippet
// `/orgs/{org}/users/{user}/files/{path...}`. Multiple single-segment
// params stack freely; only the wildcards have count/position
// restrictions. We exercise the happy path plus a slash-bearing
// trailing capture to confirm the greedy still bites past the last
// static segment.
func TestDocExample_ThreeMiddleParamsPlusGreedy(t *testing.T) {
	mux := NewMux()
	mux.GET("/orgs/{org}/users/{user}/files/{path...}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(
			r.PathValue("org") + "|" +
				r.PathValue("user") + "|" +
				r.PathValue("path"),
		))
	})

	req := httptest.NewRequest(http.MethodGet, "/orgs/rakun/users/alice/files/a/b/c.txt", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got, want := rec.Body.String(), "rakun|alice|a/b/c.txt"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestDocExample_RejectsGreedyInMiddle pins the warning callout in the
// "Multiple captures in one route" section: `/users/{name...}/files/{path...}`
// must panic at registration time. Two reasons combine — the first
// greedy isn't trailing (the matcher catches this), and there's a
// second greedy (caught later if the first weren't there). Either
// message is acceptable as long as the route is refused.
func TestDocExample_RejectsGreedyInMiddle(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected Insert to panic on a middle greedy")
		}
		msg, _ := r.(string)
		if msg == "" {
			if e, ok := r.(error); ok {
				msg = e.Error()
			}
		}
		// Acceptable: either the "trailing" rule or the "more than
		// one greedy" rule fires first. Both correctly describe the
		// route as malformed; we just need ONE of them to surface.
		if !strings.Contains(msg, "trailing") && !strings.Contains(msg, "greedy") {
			t.Errorf("panic message %q does not identify the cause", msg)
		}
	}()

	mux := NewMux()
	mux.GET("/users/{name...}/files/{path...}", func(w http.ResponseWriter, r *http.Request) {})
}

// TestRejectsMultipleStars enforces the "one `*` per route" rule at
// register time. Multiple `*` segments are ambiguous in spelling
// (which one is "the" `*`?) and a sign that the operator meant to
// capture a name rather than a position — that's what `{name...}`
// (or, for middle segments, `{name}`) is for.
func TestRejectsMultipleStars(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected Insert to panic on a multi-star route")
		}
		msg, ok := r.(string)
		if !ok {
			// Some callers wrap as error; tolerate that too.
			if e, isErr := r.(error); isErr {
				msg = e.Error()
			} else {
				t.Fatalf("panic value is %T, expected string or error", r)
			}
		}
		if !strings.Contains(msg, "more than one '*'") {
			t.Errorf("panic message %q does not identify the cause", msg)
		}
	}()

	mux := NewMux()
	mux.GET("/a/*/b/*", func(w http.ResponseWriter, r *http.Request) {})
}

// TestRejectsNonTrailingGreedy guarantees `{name...}` can only appear
// as the route's last segment. A greedy in the middle would have no
// stopping rule — the matcher would be permitted to backtrack
// arbitrarily, which leads to ambiguity nightmares.
func TestRejectsNonTrailingGreedy(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected Insert to panic on a non-trailing greedy")
		}
		msg, _ := r.(string)
		if msg == "" {
			if e, ok := r.(error); ok {
				msg = e.Error()
			}
		}
		if !strings.Contains(msg, "trailing segment") {
			t.Errorf("panic message %q does not identify the cause", msg)
		}
	}()

	mux := NewMux()
	mux.GET("/a/{x...}/b", func(w http.ResponseWriter, r *http.Request) {})
}

// TestRejectsMultipleGreedy enforces "at most one greedy per route".
// Practically the first non-trailing greedy would already trip the
// trailing rule, but registering two adjacent ones (e.g.
// `/a/{x...}/{y...}`) takes the dedicated path and surfaces a clearer
// message naming the actual cause.
func TestRejectsMultipleGreedy(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected Insert to panic on a multi-greedy route")
		}
		msg, _ := r.(string)
		if msg == "" {
			if e, ok := r.(error); ok {
				msg = e.Error()
			}
		}
		// The first violation hit by the validator wins — either the
		// "more than one greedy" or "must be trailing" message is
		// acceptable here because both correctly describe the route.
		if !strings.Contains(msg, "greedy") && !strings.Contains(msg, "trailing") {
			t.Errorf("panic message %q does not identify the cause", msg)
		}
	}()

	mux := NewMux()
	mux.GET("/a/{x...}/{y...}", func(w http.ResponseWriter, r *http.Request) {})
}

func TestHandleWithMethodRejectsInvalidMethod(t *testing.T) {
	panicMessage := func(t *testing.T, fn func()) string {
		t.Helper()

		var msg string

		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("expected a panic")
				}

				switch v := r.(type) {
				case string:
					msg = v
				case error:
					msg = v.Error()
				}
			}()

			fn()
		}()

		return msg
	}

	for _, method := range []string{
		"GET ",             // trailing space is not a token character
		"GET\n",            // header-injection shaped
		"G/ET",             // separator
		"POST,GET",         // comma
		"\"GET\"",          // quoted-string
		"GET\x00",          // NUL
		"MÉTHODE",          // non-ASCII
		"multipart/method", // slash
	} {
		t.Run(method, func(t *testing.T) {
			msg := panicMessage(t, func() {
				NewMux().HandleWithMethod(method, "/lc", func(http.ResponseWriter, *http.Request) {})
			})
			if !strings.Contains(msg, "invalid HTTP method") {
				t.Errorf("panic message %q does not identify the cause", msg)
			}
		})
	}

	// RouteBuilder is the same entry point through ApplyRoutes and must reject
	// invalid tokens identically.
	t.Run("RouteBuilder", func(t *testing.T) {
		msg := panicMessage(t, func() {
			NewMux().ApplyRoutes(func(b *RouteBuilder) {
				b.HandleWithMethod("GET ", "/lc", func(http.ResponseWriter, *http.Request) {})
			})
		})
		if !strings.Contains(msg, "invalid HTTP method") {
			t.Errorf("panic message %q does not identify the cause", msg)
		}
	})

	// A panicking batch must leave the live table untouched.
	t.Run("RouteBuilder leaves the table untouched", func(t *testing.T) {
		mux := NewMux()
		mux.GET("/ok", func(http.ResponseWriter, *http.Request) {})

		func() {
			defer func() { _ = recover() }()

			mux.ApplyRoutes(func(b *RouteBuilder) {
				b.HandleWithMethod("GET ", "/lc", func(http.ResponseWriter, *http.Request) {})
			})
		}()

		if got := len(mux.Routes()); got != 1 {
			t.Errorf("routes = %d, want 1", got)
		}
	})
}

func TestHandleWithMethodNormalizesMethod(t *testing.T) {
	mux := NewMux()
	mux.HandleWithMethod("gEt", "/mixed", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	if got := serve(mux, http.MethodGet, "/mixed").Body.String(); got != "ok" {
		t.Fatalf("body = %q, want ok", got)
	}
	if routes := mux.Routes(); len(routes) != 1 || routes[0].Method != http.MethodGet {
		t.Fatalf("routes = %+v, want canonical GET", routes)
	}
	if !mux.Remove("get", "/mixed") {
		t.Fatal("Remove did not normalize method")
	}

	mux.ApplyRoutes(func(b *RouteBuilder) {
		b.HandleWithMethod("pOsT", "/batch", func(http.ResponseWriter, *http.Request) {})
		if !b.Remove("post", "/batch") {
			t.Fatal("RouteBuilder.Remove did not normalize method")
		}
	})
}

// TestHandleWithMethodAcceptsCanonicalMethods keeps the validator from
// over-rejecting: every method the package registers itself, extension methods
// made of ordinary token characters, and the documented empty catch-all.
func TestHandleWithMethodAcceptsCanonicalMethods(t *testing.T) {
	for _, method := range []string{
		http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect,
		http.MethodOptions, http.MethodTrace, MethodQuery,
		"PROPFIND", "MKCOL", "M-SEARCH", "X_CUSTOM", "R2",
	} {
		t.Run(method, func(t *testing.T) {
			mux := NewMux()
			mux.HandleWithMethod(method, "/ok", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("hit"))
			})

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(method, "/ok", nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			// HEAD suppresses the body; the status above is the assertion.
			if method != http.MethodHead && rec.Body.String() != "hit" {
				t.Errorf("body = %q, want %q", rec.Body.String(), "hit")
			}
		})
	}

	// The empty method is the documented catch-all behind Handle and
	// HandleFunc and must keep serving every method.
	t.Run("empty catch-all", func(t *testing.T) {
		mux := NewMux()
		mux.HandleWithMethod("", "/any", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(r.Method))
		})

		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete, "PROPFIND"} {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(method, "/any", nil))

			if rec.Code != http.StatusOK || rec.Body.String() != method {
				t.Errorf("%s: status = %d body = %q", method, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("empty catch-all through HandleFunc and RouteBuilder", func(t *testing.T) {
		mux := NewMux()
		mux.HandleFunc("/hf", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("hf"))
		})
		mux.ApplyRoutes(func(b *RouteBuilder) {
			b.HandleWithMethod("", "/rb", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("rb"))
			})
		})

		for path, want := range map[string]string{"/hf": "hf", "/rb": "rb"} {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, path, nil))

			if rec.Code != http.StatusOK || rec.Body.String() != want {
				t.Errorf("%s: status = %d body = %q", path, rec.Code, rec.Body.String())
			}
		}
	})
}
