package ada

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMux(t *testing.T) {
	type testHandler struct {
		name    string
		path    string
		method  string
		handler http.HandlerFunc
	}
	type testWant struct {
		request func() *http.Request
		status  int
		body    string
	}
	type testCase struct {
		handler []testHandler
		tests   []testWant
	}

	testCases := []testCase{
		{
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
			tests: []testWant{
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/hello", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Hello, world!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodPost, "/hello", nil)
						return req
					},
					status: http.StatusAccepted,
					body:   "OK!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/hell", nil)
						return req
					},
					status: http.StatusOK,
					body:   "Welcome!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/how/1", nil)
						return req
					},
					status: http.StatusOK,
					body:   "how how!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/how/1/2/3/4", nil)
						return req
					},
					status: http.StatusOK,
					body:   "how how 4!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/ho/12345", nil)
						return req
					},
					status: http.StatusOK,
					body:   "ho ho ho *!",
				},
				{
					request: func() *http.Request {
						req, _ := http.NewRequest(http.MethodGet, "/how/999", nil)
						return req
					},
					status: http.StatusOK,
					body:   "how how 999!",
				},
			},
		},
	}

	for _, tc := range testCases {
		mux := NewMux()
		for _, handler := range tc.handler {
			mux.addHandler(handler.method, handler.path, handler.handler)
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
		}
	}
}
