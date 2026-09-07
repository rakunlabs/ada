package recover

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultResponse(t *testing.T) {
	for _, value := range []any{errors.New("private credentials"), "private credentials"} {
		t.Run(fmtPanicType(value), func(t *testing.T) {
			var logs bytes.Buffer
			w := httptest.NewRecorder()
			Middleware(WithPrintStack(false), WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))(
				http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(value) }),
			).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if w.Code != 500 || w.Body.String() != "Internal Server Error\n" {
				t.Fatalf("response = %d %q", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String()+w.Header().Get("Content-Type"), "private") {
				t.Fatal("panic details leaked")
			}
			if !strings.Contains(logs.String(), "private credentials") {
				t.Fatalf("original panic not logged: %s", &logs)
			}
		})
	}
}

func fmtPanicType(value any) string {
	if _, ok := value.(error); ok {
		return "error"
	}
	return "string"
}

func TestErrorHandler(t *testing.T) {
	original := errors.New("private error")
	for _, value := range []any{original, "string panic"} {
		t.Run(fmtPanicType(value), func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/original", nil)
			w := httptest.NewRecorder()
			calls := 0
			callback := func(rw http.ResponseWriter, req *http.Request, err error) {
				calls++
				if req != r {
					t.Fatal("request identity lost")
				}
				if value == original && err != original {
					t.Fatal("error identity lost")
				}
				if value != original && err.Error() != value {
					t.Fatalf("string panic = %q", err)
				}
				rw.Header().Set("Content-Type", "application/json")
				rw.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(rw, `{"error":"redacted"}`)
			}
			Middleware(WithLogger(nil), WithPrintStack(false),
				WithErrorHandler(func(http.ResponseWriter, *http.Request, error) { t.Fatal("overridden callback ran") }),
				WithErrorHandler(callback),
			)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(value) })).ServeHTTP(w, r)
			if calls != 1 || w.Code != 503 || w.Body.String() != `{"error":"redacted"}` || w.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("calls=%d, response=%d %v %q", calls, w.Code, w.Header(), w.Body.String())
			}
		})
	}
}

func TestErrorHandlerFieldAndNilOption(t *testing.T) {
	w := httptest.NewRecorder()
	re := &Recover{ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
		w.WriteHeader(http.StatusTeapot)
	}}
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("oops") })
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	re.Middleware(h).ServeHTTP(w, r)
	if w.Code != http.StatusTeapot {
		t.Fatalf("status = %d", w.Code)
	}
	w = httptest.NewRecorder()
	New(WithLogger(nil), WithPrintStack(false), WithErrorHandler(re.ErrorHandler), WithErrorHandler(nil)).Middleware(h).ServeHTTP(w, r)
	if w.Code != 500 || w.Body.String() != "Internal Server Error\n" {
		t.Fatalf("nil callback response = %d %q", w.Code, w.Body.String())
	}
}

// Unlike ResponseRecorder, this writer keeps informational responses separate.
type responseWriter struct {
	header http.Header
	codes  []int
	body   bytes.Buffer
}

func (w *responseWriter) Header() http.Header         { return w.header }
func (w *responseWriter) WriteHeader(code int)        { w.codes = append(w.codes, code) }
func (w *responseWriter) Write(p []byte) (int, error) { return w.body.Write(p) }

type optionalWriter struct {
	*responseWriter
	flushed, hijacked, readFrom, pushed bool
	hijackErr                           error
	closed                              chan bool
}

func (w *optionalWriter) Flush() { w.flushed = true }
func (w *optionalWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = w.hijackErr == nil
	return nil, nil, w.hijackErr
}
func (w *optionalWriter) ReadFrom(r io.Reader) (int64, error) {
	w.readFrom = true
	return io.Copy(&w.body, r)
}
func (w *optionalWriter) Push(string, *http.PushOptions) error { w.pushed = true; return nil }
func (w *optionalWriter) CloseNotify() <-chan bool             { return w.closed }

func TestCommittedResponse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(http.ResponseWriter)
		body  string
		codes []int
	}{
		{"status", func(w http.ResponseWriter) { w.WriteHeader(204) }, "", []int{204}},
		{"body", func(w http.ResponseWriter) { _, _ = w.Write([]byte("partial")) }, "partial", nil},
		{"flush", func(w http.ResponseWriter) { _ = http.NewResponseController(w).Flush() }, "", nil},
		{"hijack", func(w http.ResponseWriter) { _, _, _ = http.NewResponseController(w).Hijack() }, "", nil},
		{"switching protocols", func(w http.ResponseWriter) { w.WriteHeader(101) }, "", []int{101}},
		{"read from", func(w http.ResponseWriter) {
			_, _ = io.Copy(w, struct{ io.Reader }{strings.NewReader("stream")})
		}, "stream", nil},
		{"read from panic", func(w http.ResponseWriter) {
			_, _ = io.Copy(w, struct{ io.Reader }{io.MultiReader(strings.NewReader("stream"), panicReader{})})
		}, "stream", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &optionalWriter{responseWriter: &responseWriter{header: make(http.Header)}}
			var logs bytes.Buffer
			h := Middleware(WithLogger(slog.New(slog.NewTextHandler(&logs, nil))), WithPrintStack(false),
				WithErrorHandler(func(http.ResponseWriter, *http.Request, error) { t.Fatal("callback after commitment") }),
			)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				tc.write(w)
				panic("original panic")
			}))
			assertAbort(t, func() { h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil)) })
			if w.body.String() != tc.body || !reflect.DeepEqual(w.codes, tc.codes) {
				t.Fatalf("response changed: %v %q", w.codes, w.body.String())
			}
			if !strings.Contains(logs.String(), "original panic") {
				t.Fatalf("original panic not logged: %s", &logs)
			}
			if tc.name == "flush" && !w.flushed || tc.name == "hijack" && !w.hijacked || strings.HasPrefix(tc.name, "read from") && !w.readFrom {
				t.Fatal("optional operation not forwarded")
			}
		})
	}
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("original panic") }

func assertAbort(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if got := recover(); got != http.ErrAbortHandler {
			t.Errorf("panic = %v, want http.ErrAbortHandler", got)
		}
	}()
	f()
}

func TestUncommittedResponse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(http.ResponseWriter)
		codes   []int
	}{
		{"informational", func(w http.ResponseWriter) { w.WriteHeader(100); w.WriteHeader(102); w.WriteHeader(103) }, []int{100, 102, 103, 500}},
		{"failed hijack", func(w http.ResponseWriter) { _, _, _ = w.(http.Hijacker).Hijack() }, []int{500}},
		{"headers only", func(w http.ResponseWriter) { w.Header().Set("X-Test", "value") }, []int{500}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &optionalWriter{responseWriter: &responseWriter{header: make(http.Header)}, hijackErr: errors.New("unsupported")}
			Middleware(WithLogger(nil), WithPrintStack(false))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				tc.prepare(w)
				panic("private")
			})).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if !reflect.DeepEqual(w.codes, tc.codes) || w.body.String() != "Internal Server Error\n" {
				t.Fatalf("response = %v %q", w.codes, w.body.String())
			}
		})
	}
}

func TestAbortHandler(t *testing.T) {
	var logs bytes.Buffer
	w := httptest.NewRecorder()
	h := Middleware(WithPrintStack(false), WithLogger(slog.New(slog.NewTextHandler(&logs, nil))),
		WithErrorHandler(func(http.ResponseWriter, *http.Request, error) { t.Fatal("abort callback") }),
	)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))
	assertAbort(t, func() { h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil)) })
	if logs.Len() != 0 || w.Body.Len() != 0 || len(w.Header()) != 0 {
		t.Fatal("abort was logged or written")
	}
}

func TestNormalRequestAndInterfaces(t *testing.T) {
	for _, optional := range []bool{false, true} {
		base := &responseWriter{header: make(http.Header)}
		full := &optionalWriter{responseWriter: base, closed: make(chan bool)}
		var original http.ResponseWriter = base
		if optional {
			original = full
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		Middleware(WithLogger(nil), WithPrintStack(false), WithErrorHandler(func(http.ResponseWriter, *http.Request, error) {
			t.Fatal("callback on normal request")
		}))(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req != r || w.(interface{ Unwrap() http.ResponseWriter }).Unwrap() != original {
				t.Fatal("request or unwrapped writer changed")
			}
			_, flush := w.(http.Flusher)
			_, hijack := w.(http.Hijacker)
			_, readFrom := w.(io.ReaderFrom)
			_, push := w.(http.Pusher)
			_, closeNotify := w.(http.CloseNotifier) //nolint:staticcheck // Verify preservation of the legacy optional interface.
			if flush != optional || hijack != optional || readFrom != optional || push != optional || closeNotify != optional {
				t.Fatal("optional interfaces changed")
			}
			if optional {
				_ = w.(http.Pusher).Push("/asset", nil)
				if w.(http.CloseNotifier).CloseNotify() != full.closed || !full.pushed { //nolint:staticcheck // Verify forwarding of the legacy optional interface.
					t.Fatal("optional forwarding failed")
				}
			}
			w.Header().Set("X-Test", "value")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("normal body"))
		})).ServeHTTP(original, r)
		if base.Header().Get("X-Test") != "value" || !reflect.DeepEqual(base.codes, []int{201}) || base.body.String() != "normal body" {
			t.Fatalf("response changed: %v %v %q", base.header, base.codes, base.body.String())
		}
	}
}
