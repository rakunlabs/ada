package ada

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func TestMuxWrap_UsesMuxErrorHandler(t *testing.T) {
	mux := NewMux()
	mux.ErrorHandler(func(c *Context, err error) {
		c.SetStatus(http.StatusUnprocessableEntity)
		_ = c.SendString(err.Error())
	})

	recorder := httptest.NewRecorder()
	mux.Wrap(func(c *Context) error {
		return errors.New("mux error")
	})(recorder, httptest.NewRequest(http.MethodGet, "/test", nil))

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected status %d, got %d", http.StatusUnprocessableEntity, recorder.Code)
	}
	if recorder.Body.String() != "mux error" {
		t.Fatalf("expected body %q, got %q", "mux error", recorder.Body.String())
	}
}

// TestRouteHandlerShapes pins every handler shape the routing methods accept.
// The plain net/http shapes must keep working unchanged, and the Context-style
// shapes must be resolved through the Mux at registration time.
func TestRouteHandlerShapes(t *testing.T) {
	plain := func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("plain")) }

	mux := NewMux()
	// func(http.ResponseWriter, *http.Request)
	mux.GET("/lit", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("lit")) })
	// named func value with the same underlying type
	mux.GET("/named", plain)
	// http.HandlerFunc
	mux.GET("/hf", http.HandlerFunc(plain))
	// http.Handler method value
	mux.GET("/mv", http.HandlerFunc(plain).ServeHTTP)
	// func(*Context) error
	mux.GET("/ctx", func(c *Context) error { return c.SendString("ctx") })
	// HandlerFunc
	mux.GET("/typed", HandlerFunc(func(c *Context) error { return c.SendString("typed") }))
	// an ada handler pre-wrapped into an http.HandlerFunc still works
	mux.GET("/prewrapped", mux.Wrap(func(c *Context) error { return c.SendString("prewrapped") }))
	// catch-all registration accepts every shape too
	mux.HandleFunc("/any", func(c *Context) error { return c.SendString("any") })

	for _, tc := range []struct{ path, want string }{
		{"/lit", "lit"},
		{"/named", "plain"},
		{"/hf", "plain"},
		{"/mv", "plain"},
		{"/ctx", "ctx"},
		{"/typed", "typed"},
		{"/prewrapped", "prewrapped"},
		{"/any", "any"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
			}
			if got := rec.Body.String(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestContextHandler_BindsToRegisteredMux is the core guarantee: a Context
// handler is resolved against the Mux it is registered on, so that Mux's
// ErrorHandler runs — not DefaultErrHandler, and not another Mux's handler.
func TestContextHandler_BindsToRegisteredMux(t *testing.T) {
	original := DefaultErrHandler
	t.Cleanup(func() { DefaultErrHandler = original })
	DefaultErrHandler = func(c *Context, err error) {
		c.SetStatus(http.StatusInternalServerError)
		_ = c.SendString("default")
	}

	failing := func(c *Context) error { return errors.New("boom") }

	muxA := NewMux()
	muxA.ErrorHandler(func(c *Context, err error) {
		c.SetStatus(http.StatusUnprocessableEntity)
		_ = c.SendString("A:" + err.Error())
	})

	muxB := NewMux()
	muxB.ErrorHandler(func(c *Context, err error) {
		c.SetStatus(http.StatusTeapot)
		_ = c.SendString("B:" + err.Error())
	})

	muxC := NewMux() // no ErrorHandler -> DefaultErrHandler

	// The very same handler registered on three different muxes must resolve
	// independently against each one.
	muxA.GET("/fail", failing)
	muxB.GET("/fail", failing)
	muxC.GET("/fail", failing)

	for _, tc := range []struct {
		name string
		mux  *Mux
		code int
		body string
	}{
		{"mux A error handler", muxA, http.StatusUnprocessableEntity, "A:boom"},
		{"mux B error handler", muxB, http.StatusTeapot, "B:boom"},
		{"fallback to default", muxC, http.StatusInternalServerError, "default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/fail", nil))

			if rec.Code != tc.code {
				t.Fatalf("status=%d (want %d) body=%q", rec.Code, tc.code, rec.Body.String())
			}
			if got := rec.Body.String(); got != tc.body {
				t.Errorf("got %q, want %q", got, tc.body)
			}
		})
	}
}

// TestContextHandler_BindsToGroup guards that a Group — a distinct *Mux value
// carrying its own error handler — resolves the handler against itself rather
// than against the parent it was derived from.
func TestContextHandler_BindsToGroup(t *testing.T) {
	mux := NewMux()
	mux.ErrorHandler(func(c *Context, err error) {
		c.SetStatus(http.StatusInternalServerError)
		_ = c.SendString("root")
	})

	group := mux.Group("/api")
	group.ErrorHandler(func(c *Context, err error) {
		c.SetStatus(http.StatusTeapot)
		_ = c.SendString("group")
	})

	failing := func(c *Context) error { return errors.New("boom") }
	mux.GET("/fail", failing)
	group.GET("/fail", failing)

	for _, tc := range []struct {
		path string
		code int
		body string
	}{
		{"/fail", http.StatusInternalServerError, "root"},
		{"/api/fail", http.StatusTeapot, "group"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))

			if rec.Code != tc.code {
				t.Fatalf("status=%d (want %d) body=%q", rec.Code, tc.code, rec.Body.String())
			}
			if got := rec.Body.String(); got != tc.body {
				t.Errorf("got %q, want %q", got, tc.body)
			}
		})
	}
}

// TestContextHandler_ErrorHandlerSetAfterRegistration documents that the error
// handler is read at request time, so registering routes before calling
// ErrorHandler still works. This mirrors the pre-existing mux.Wrap behaviour.
func TestContextHandler_ErrorHandlerSetAfterRegistration(t *testing.T) {
	mux := NewMux()
	mux.GET("/fail", func(c *Context) error { return errors.New("boom") })

	mux.ErrorHandler(func(c *Context, err error) {
		c.SetStatus(http.StatusTeapot)
		_ = c.SendString("late:" + err.Error())
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/fail", nil))

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "late:boom" {
		t.Errorf("got %q, want %q", got, "late:boom")
	}
}

// TestHandleWithMethod_StaysInterfaceable pins the non-generic primitive that
// downstream code must use when abstracting over *Mux, since Go interfaces can
// neither declare generic methods nor be satisfied by them.
func TestHandleWithMethod_StaysInterfaceable(t *testing.T) {
	type registrar interface {
		HandleWithMethod(method, path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler)
	}

	mux := NewMux()

	var r registrar = mux
	r.HandleWithMethod(http.MethodGet, "/iface", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("iface"))
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/iface", nil))

	if rec.Code != http.StatusOK || rec.Body.String() != "iface" {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

// TestPooledContext_NoStateLeak pins that a Context recycled through the pool
// carries nothing over from the request that used it before. The first request
// dirties every mutable field (status, committed flag); the second must still
// observe the defaults.
func TestPooledContext_NoStateLeak(t *testing.T) {
	mux := NewMux()

	var (
		seenCode      int
		seenCommitted bool
	)

	mux.GET("/leak", func(c *Context) error {
		seenCode = c.code
		seenCommitted = c.committed

		c.SetStatus(http.StatusTeapot)

		return c.SendString("dirty")
	})

	for i := range 2 {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/leak", nil))

		if seenCode != http.StatusOK {
			t.Fatalf("request %d: entered handler with code %d, want %d", i, seenCode, http.StatusOK)
		}
		if seenCommitted {
			t.Fatalf("request %d: entered handler already committed", i)
		}
		if rec.Code != http.StatusTeapot {
			t.Fatalf("request %d: status = %d, want %d", i, rec.Code, http.StatusTeapot)
		}
	}
}

// TestPooledContext_ReleasedContextDropsRequest pins that returning a Context
// to the pool clears its request and response references, so a pooled Context
// cannot pin a finished request (and its body) in memory.
func TestPooledContext_ReleasedContextDropsRequest(t *testing.T) {
	var captured *Context

	mux := NewMux()
	mux.GET("/capture", func(c *Context) error {
		captured = c

		return c.SendString("ok")
	})

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/capture", nil))

	if captured == nil {
		t.Fatal("handler did not run")
	}
	if captured.Request != nil || captured.Response != nil {
		t.Fatal("released Context still references the request/response")
	}
}

func TestWrapUnpooledContextRemainsValidAfterReturn(t *testing.T) {
	mux := NewMux()
	var captured *Context
	handler := mux.WrapUnpooled(func(c *Context) error {
		captured = c
		return c.SendString("ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if captured == nil || captured.Request != req || captured.Response != rec {
		t.Fatal("unpooled Context was cleared or replaced after return")
	}
}

// TestPooledContext_SurvivesConcurrentRequests exercises the pool from many
// goroutines at once; run under -race this is what catches a Context being
// shared between two in-flight requests.
func TestPooledContext_SurvivesConcurrentRequests(t *testing.T) {
	mux := NewMux()
	mux.GET("/users/{id}", func(c *Context) error {
		return c.SendString(c.Request.PathValue("id"))
	})

	const workers = 32

	var wg sync.WaitGroup

	wg.Add(workers)

	for i := range workers {
		go func() {
			defer wg.Done()

			want := strconv.Itoa(i)

			for range 100 {
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users/"+want, nil))

				if rec.Body.String() != want {
					t.Errorf("body = %q, want %q", rec.Body.String(), want)

					return
				}
			}
		}()
	}

	wg.Wait()
}

// TestSendDoesNotOverrideContentType pins that the Send* helpers only supply a
// Content-Type when the handler (or a middleware) has not already chosen one.
// Overriding it silently broke handlers answering with a more specific media
// type, application/problem+json above all.
func TestSendDoesNotOverrideContentType(t *testing.T) {
	tests := []struct {
		name string
		send func(c *Context) error
		set  string
		want string
	}{
		{
			name: "json keeps explicit type",
			send: func(c *Context) error { return c.SendJSON(map[string]string{"a": "b"}) },
			set:  "application/problem+json",
			want: "application/problem+json",
		},
		{
			name: "json defaults when unset",
			send: func(c *Context) error { return c.SendJSON(map[string]string{"a": "b"}) },
			want: MIMEApplicationJSONCharsetUTF8,
		},
		{
			name: "string keeps explicit type",
			send: func(c *Context) error { return c.SendString("<p>hi</p>") },
			set:  "text/html; charset=utf-8",
			want: "text/html; charset=utf-8",
		},
		{
			name: "string defaults when unset",
			send: func(c *Context) error { return c.SendString("hi") },
			want: MIMETextPlainCharsetUTF8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := NewMux()
			mux.GET("/ct", func(c *Context) error {
				if tt.set != "" {
					c.SetHeader(HeaderContentType, tt.set)
				}

				return tt.send(c)
			})

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ct", nil))

			if got := rec.Header().Get(HeaderContentType); got != tt.want {
				t.Fatalf("Content-Type = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSendZipPreparationErrorRemainsUncommitted(t *testing.T) {
	mux := NewMux()
	mux.GET("/zip", func(c *Context) error {
		return c.SendZip("archive.zip", map[string]io.Reader{"broken.txt": failingReader{}})
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/zip", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(rec.Body.String(), "read failed") {
		t.Fatalf("body = %q, want read error", rec.Body.String())
	}
}

func TestSendZipAlreadyCommittedDoesNotConsumeReaders(t *testing.T) {
	rec := httptest.NewRecorder()
	c := NewContext(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if err := c.SendString("first"); err != nil {
		t.Fatalf("SendString: %v", err)
	}

	reader := &countingReader{Reader: strings.NewReader("archive data")}
	if err := c.SendZip("archive.zip", map[string]io.Reader{"file.txt": reader}); !errors.Is(err, ErrAlreadyCommitted) {
		t.Fatalf("SendZip error = %v, want ErrAlreadyCommitted", err)
	}
	if reader.reads != 0 {
		t.Fatalf("already-committed SendZip consumed its reader %d times", reader.reads)
	}
}

type countingReader struct {
	io.Reader
	reads int
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.reads++
	return r.Reader.Read(p)
}

func TestSendZipRejectsUnsafeEntryNames(t *testing.T) {
	for _, name := range []string{"../secret", "/etc/passwd", `..\secret`, `C:\secret`} {
		t.Run(name, func(t *testing.T) {
			c := NewContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
			if err := c.SendZip("archive.zip", map[string]io.Reader{name: strings.NewReader("x")}); err == nil {
				t.Fatalf("SendZip accepted unsafe entry %q", name)
			}
			if c.Committed() {
				t.Fatal("Context committed after rejecting an entry name")
			}
		})
	}
}

func TestSendZipUsesNormalizedSafeNames(t *testing.T) {
	rec := httptest.NewRecorder()
	c := NewContext(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if err := c.SendZip("archive.zip", map[string]io.Reader{`dir\file.txt`: strings.NewReader("ok")}); err != nil {
		t.Fatalf("SendZip: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "dir/file.txt" {
		t.Fatalf("entries = %#v, want dir/file.txt", zr.File)
	}
}
