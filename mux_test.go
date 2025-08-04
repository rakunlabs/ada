package ada

import (
	"net/http"
	"net/http/httptest"
	"slices"
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
		handlerGroup []testHandlerGroup
		tests        []testWant
	}

	testCases := []testCase{
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
					},
				},
			},
			tests: []testWant{
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
				t.Errorf("expected status %d, got %d for request %s", test.status, recorder.Code, req.URL.Path)
			}
			if recorder.Body.String() != test.body {
				t.Errorf("expected body '%s', got '%s' for request %s", test.body, recorder.Body.String(), req.URL.Path)
			}

			recordHeader := recorder.Header()
			for key, value := range test.header {
				if !slices.Equal(recordHeader[key], value) {
					t.Errorf("expected header %s to be %v, got %v for request %s", key, value, recordHeader[key], req.URL.Path)
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

	if mux.root.TypeStatic.Key != "" {
		t.Errorf("expected root.TypeStatic.Key to be '', got '%s'", mux.root.TypeStatic.Key)
	}

	for r, node := range mux.root.TypeStatic.Children {
		switch r {
		case 's':
			if node.TypeStatic.Key != "stat" {
				t.Errorf("expected node.TypeStatic.Key to be 'stat', got '%s'", node.TypeStatic.Key)
			}
			if node.TypeStatic.Children == nil {
				t.Errorf("expected node.TypeStatic.Children to be non-nil")
			}
			for r, child := range node.TypeStatic.Children {
				switch r {
				case 't':
					if child.TypeStatic.Key != "ic" {
						t.Errorf("expected child.TypeStatic.Key to be 'ic', got '%s'", child.TypeStatic.Key)
					}
				case 'a':
					if child.TypeStatic.Key != "alpha" {
						t.Errorf("expected child.TypeStatic.Key to be 'alpha', got '%s'", child.TypeStatic.Key)
					}
				}
			}
		case 'a':
			if node.TypeStatic.Key != "alpha" {
				t.Errorf("expected node.TypeStatic.Key to be 'alpha', got '%s'", node.TypeStatic.Key)
			}
			if len(node.TypeStatic.Children) != 0 {
				t.Errorf("expected node.TypeStatic.Children to be zero length")
			}
		}
	}
}
