package ada

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rakunlabs/ada/utils/bind"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

type countingJSONMarshaler struct {
	calls *int
}

func (m countingJSONMarshaler) MarshalJSON() ([]byte, error) {
	(*m.calls)++

	return []byte(`{"value":"ok"}`), nil
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

func TestSendJSONEncodingErrorCanBeHandled(t *testing.T) {
	mux := NewMux()
	mux.ErrorHandler(func(c *Context, err error) {
		if c.Committed() {
			t.Error("JSON encoding error committed the response")
		}
		if !strings.Contains(err.Error(), "unsupported type") {
			t.Errorf("error = %q, want unsupported type", err)
		}

		_ = c.SendString("handled")
	})
	mux.GET("/json", func(c *Context) error {
		c.SetStatus(http.StatusAccepted)

		return c.SendJSON(make(chan int))
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/json", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := rec.Header().Get(HeaderContentType); got != MIMETextPlainCharsetUTF8 {
		t.Fatalf("Content-Type = %q, want %q", got, MIMETextPlainCharsetUTF8)
	}
	if got := rec.Body.String(); got != "handled" {
		t.Fatalf("body = %q, want %q", got, "handled")
	}
}

func TestSendJSONPBuffersPrettyResponseAndPreservesContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	c := NewContext(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	c.SetStatus(http.StatusCreated)
	c.SetHeader(HeaderContentType, "application/problem+json")

	if err := c.SendJSONP(map[string]string{"name": "ada"}, "  "); err != nil {
		t.Fatalf("SendJSONP: %v", err)
	}

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if got := rec.Header().Get(HeaderContentType); got != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json", got)
	}
	if got, want := rec.Body.String(), "{\n  \"name\": \"ada\"\n}\n"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestSendJSONPMarshalsOnce(t *testing.T) {
	rec := httptest.NewRecorder()
	c := NewContext(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	calls := 0

	if err := c.SendJSONP(countingJSONMarshaler{calls: &calls}, "  "); err != nil {
		t.Fatalf("SendJSONP: %v", err)
	}
	if calls != 1 {
		t.Fatalf("MarshalJSON calls = %d, want 1", calls)
	}
	if got, want := rec.Body.String(), "{\n  \"value\": \"ok\"\n}\n"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
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
	// The Context stayed uncommitted, so the error handler could write the
	// response. Its text is the redacted 500 body — the read failure itself is
	// an internal detail and goes to the log, see TestErrorRedaction.
	if got, want := rec.Body.String(), `{"message":"Internal Server Error"}`+"\n"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

// TestSendZipEntryOrderIsDeterministic pins archive layout against Go's
// randomised map iteration. SendZip ranged over the map, so two responses
// built from identical data differed byte for byte, defeating checksums,
// caching and any reproducible-output test downstream.
func TestSendZipEntryOrderIsDeterministic(t *testing.T) {
	names := []string{"zeta.txt", "alpha.txt", "m/inner.txt", "beta.txt", "a/b/c.txt", "0.txt", "M.txt"}

	want := slices.Clone(names)
	slices.Sort(want)

	var first []byte

	// Repeat: one pass can match sorted order by luck, several cannot.
	for i := range 8 {
		files := make(map[string]io.Reader, len(names))
		for _, name := range names {
			files[name] = strings.NewReader("data:" + name)
		}

		rec := httptest.NewRecorder()
		c := NewContext(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if err := c.SendZip("archive.zip", files); err != nil {
			t.Fatalf("SendZip: %v", err)
		}

		body := rec.Body.Bytes()

		zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			t.Fatalf("open zip: %v", err)
		}

		got := make([]string, 0, len(zr.File))
		for _, f := range zr.File {
			got = append(got, f.Name)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("run %d: entries = %v, want %v", i, got, want)
		}

		if first == nil {
			first = body

			continue
		}
		if !bytes.Equal(first, body) {
			t.Fatalf("run %d produced a different archive for the same input", i)
		}
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

// TestBindForwardsOptions covers Context.Bind passing options through to
// bind.Bind. Without it a Context handler could not set a per-endpoint body
// limit at all, and had to bypass Bind entirely.
func TestBindForwardsOptions(t *testing.T) {
	type payload struct {
		Data string `json:"data"`
	}

	const size = (1 << 20) + 1

	body := func() *strings.Reader {
		big := strings.Repeat("x", size)

		return strings.NewReader(`{"data":"` + big + `"}`)
	}

	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", body())
		r.Header.Set(HeaderContentType, MIMEApplicationJSON)

		return r
	}

	// The 1 MiB cap that used to live in bind is gone: it only ever protected
	// requests that reached Bind, and rejected bodies the rest of the service
	// accepted. middleware/bodylimit owns the limit now.
	t.Run("no limit by default", func(t *testing.T) {
		c := NewContext(httptest.NewRecorder(), request())

		var obj payload
		if err := c.Bind(&obj); err != nil {
			t.Fatalf("Bind rejected a %d byte body with no limit configured: %v", size, err)
		}
		if len(obj.Data) != size {
			t.Fatalf("bound %d bytes, want %d", len(obj.Data), size)
		}
	})

	t.Run("option applies a limit", func(t *testing.T) {
		c := NewContext(httptest.NewRecorder(), request())

		var obj payload
		err := c.Bind(&obj, bind.WithBodyLimit(1024))
		if !errors.Is(err, bind.ErrBodyTooLarge) {
			t.Fatalf("Bind with WithBodyLimit(1024) returned %v, want an ErrBodyTooLarge", err)
		}
	})

	t.Run("several options are forwarded", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/?ids=1|2|3", nil)
		c := NewContext(httptest.NewRecorder(), r)

		var obj struct {
			IDs []string `query:"ids"`
		}
		if err := c.Bind(&obj, bind.WithBodyLimit(0), bind.WithQuerySeparator("|")); err != nil {
			t.Fatalf("Bind: %v", err)
		}
		if want := []string{"1", "2", "3"}; !slices.Equal(obj.IDs, want) {
			t.Fatalf("IDs = %v, want %v", obj.IDs, want)
		}
	})
}
