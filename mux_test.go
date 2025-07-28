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
								w.Write([]byte("Welcome!"))
								w.WriteHeader(http.StatusOK)
							},
						},
						{
							name:   "GET /how/1",
							path:   "/how/1",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("how how!"))
								w.WriteHeader(http.StatusOK)
							},
						},
						{
							name:   "GET /how/1/2/3/4",
							path:   "/how/1/2/3/4",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("how how 4!"))
								w.WriteHeader(http.StatusOK)
							},
						},
						{
							name:   "GET /ho/*",
							path:   "/ho/*",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								w.Write([]byte("ho ho ho *!"))
								w.WriteHeader(http.StatusOK)
							},
						},
						{
							name:   "GET /how/{id}",
							path:   "/how/{id}",
							method: http.MethodGet,
							handler: func(w http.ResponseWriter, r *http.Request) {
								id := r.PathValue("id")
								w.Write([]byte("how how " + id + "!"))
								w.WriteHeader(http.StatusOK)
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
				group.MethodHandler(h.method, h.path, h.handler, h.middlewares...)
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
