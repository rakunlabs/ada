package ada

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
