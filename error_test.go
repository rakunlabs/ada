package ada

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestErrorStatus_NeverSucceeds guards the worst default in the old behaviour:
// c.code starts at 200 and only Err() promoted it, so a handler returning a
// plain error responded 200 with an error body — a success as far as every
// client, cache and monitor is concerned.
func TestErrorStatus_NeverSucceeds(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler HandlerFunc
		code    int
		body    string
	}{
		{
			// The text is redacted because a plain error reaching a 500 is an
			// internal failure; see TestErrorRedaction.
			name:    "plain error defaults to 500",
			handler: func(c *Context) error { return errors.New("boom") },
			code:    http.StatusInternalServerError,
			body:    `{"message":"Internal Server Error"}` + "\n",
		},
		{
			name:    "explicit 4xx via SetStatus is preserved",
			handler: func(c *Context) error { return c.SetStatus(http.StatusBadRequest).Err(errors.New("bad input")) },
			code:    http.StatusBadRequest,
			body:    `{"message":"bad input"}` + "\n",
		},
		{
			name:    "HTTPError supplies the status",
			handler: func(c *Context) error { return NewHTTPError(http.StatusNotFound, "user not found") },
			code:    http.StatusNotFound,
			body:    `{"message":"user not found"}` + "\n",
		},
		{
			// Only the HTTPError's own message is sent; the "layer:" context
			// added around it belongs to the application, not the client.
			name:    "wrapped HTTPError is still found",
			handler: func(c *Context) error { return fmt.Errorf("layer: %w", NewHTTPError(http.StatusTeapot, "nope")) },
			code:    http.StatusTeapot,
			body:    `{"message":"nope"}` + "\n",
		},
		{
			name: "HTTPError beats a status set on the context",
			handler: func(c *Context) error {
				return c.SetStatus(http.StatusOK).Err(NewHTTPError(http.StatusConflict, "dup"))
			},
			code: http.StatusConflict,
			body: `{"message":"dup"}` + "\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := NewMux()
			mux.GET("/e", tc.handler)

			rec := serve(mux, http.MethodGet, "/e")

			if rec.Code != tc.code {
				t.Errorf("status = %d, want %d", rec.Code, tc.code)
			}
			if got := rec.Body.String(); got != tc.body {
				t.Errorf("body = %q, want %q", got, tc.body)
			}
		})
	}
}

// TestCommitGuard_WriteThenError pins that a handler which writes a response
// and then returns an error emits exactly one body. Previously both were
// written, producing two concatenated JSON documents plus a "superfluous
// WriteHeader" from net/http.
func TestCommitGuard_WriteThenError(t *testing.T) {
	mux := NewMux()
	mux.GET("/x", func(c *Context) error {
		if err := c.SendJSON(map[string]string{"ok": "yes"}); err != nil {
			return err
		}

		return errors.New("boom")
	})

	rec := serve(mux, http.MethodGet, "/x")

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (the first write wins)", rec.Code)
	}
	if got, want := rec.Body.String(), `{"ok":"yes"}`+"\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// TestCommitGuard_DoubleSend pins that a second Send* is refused rather than
// silently appended to the first response.
func TestCommitGuard_DoubleSend(t *testing.T) {
	var second error

	mux := NewMux()
	mux.GET("/x", func(c *Context) error {
		if err := c.SetStatus(http.StatusCreated).SendString("first"); err != nil {
			return err
		}
		second = c.SetStatus(http.StatusTeapot).SendString("second")

		return nil
	})

	rec := serve(mux, http.MethodGet, "/x")

	if !errors.Is(second, ErrAlreadyCommitted) {
		t.Errorf("second Send returned %v, want ErrAlreadyCommitted", second)
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if got := rec.Body.String(); got != "first" {
		t.Errorf("body = %q, want %q", got, "first")
	}
}

// TestCommitted reports the flag through the public accessor, which lets
// middleware and error handlers avoid writing over a committed response.
func TestCommitted(t *testing.T) {
	c := NewContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if c.Committed() {
		t.Fatal("a fresh Context must not be committed")
	}
	if err := c.SendString("x"); err != nil {
		t.Fatalf("SendString: %v", err)
	}
	if !c.Committed() {
		t.Error("Context must be committed after a Send")
	}
}

func TestHTTPError(t *testing.T) {
	t.Run("message wins", func(t *testing.T) {
		if got := NewHTTPError(http.StatusNotFound, "gone").Error(); got != "gone" {
			t.Errorf("Error() = %q, want %q", got, "gone")
		}
	})

	t.Run("falls back to status text", func(t *testing.T) {
		if got := NewHTTPError(http.StatusNotFound, "").Error(); got != "Not Found" {
			t.Errorf("Error() = %q, want %q", got, "Not Found")
		}
	})

	t.Run("wrap keeps the cause reachable", func(t *testing.T) {
		cause := errors.New("dial failed")
		err := WrapHTTPError(http.StatusBadGateway, cause)

		if !errors.Is(err, cause) {
			t.Error("errors.Is must find the wrapped cause")
		}
		if got := err.Error(); got != "dial failed" {
			t.Errorf("Error() = %q, want %q", got, "dial failed")
		}
		if err.Code != http.StatusBadGateway {
			t.Errorf("Code = %d, want %d", err.Code, http.StatusBadGateway)
		}
	})
}

// TestErrorStatus_HTTPErrorNon4xxIsPromoted guards the invariant prepareError
// documents but did not enforce: it applied any non-zero HTTPError Code, so
// NewHTTPError(http.StatusOK, "not really ok") answered 200 — with an error
// body — and every client, cache and monitor read the request as a success.
// Only an error status may come from an HTTPError; anything else takes the
// same promotion path as a plain error.
func TestErrorStatus_HTTPErrorNon4xxIsPromoted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler HandlerFunc
		code    int
		body    string
	}{
		{
			name:    "200 is promoted to 500",
			handler: func(c *Context) error { return NewHTTPError(http.StatusOK, "not really ok") },
			code:    http.StatusInternalServerError,
			body:    `{"message":"Internal Server Error"}` + "\n",
		},
		{
			name:    "204 is promoted to 500",
			handler: func(c *Context) error { return NewHTTPError(http.StatusNoContent, "empty") },
			code:    http.StatusInternalServerError,
			body:    `{"message":"Internal Server Error"}` + "\n",
		},
		{
			name:    "3xx is promoted to 500",
			handler: func(c *Context) error { return NewHTTPError(http.StatusFound, "over there") },
			code:    http.StatusInternalServerError,
			body:    `{"message":"Internal Server Error"}` + "\n",
		},
		{
			name:    "zero code is promoted to 500",
			handler: func(c *Context) error { return &HTTPError{Message: "no code"} },
			code:    http.StatusInternalServerError,
			body:    `{"message":"Internal Server Error"}` + "\n",
		},
		{
			// The promotion must not overwrite a status the handler chose
			// itself: a 2xx HTTPError falls through to the < 400 rule, which
			// keeps an explicit 4xx.
			name: "explicit 4xx survives a 2xx HTTPError",
			handler: func(c *Context) error {
				return c.SetStatus(http.StatusBadRequest).Err(NewHTTPError(http.StatusOK, "nope"))
			},
			code: http.StatusBadRequest,
			body: `{"message":"nope"}` + "\n",
		},
		{
			name:    "400 is applied unchanged",
			handler: func(c *Context) error { return NewHTTPError(http.StatusBadRequest, "bad field id") },
			code:    http.StatusBadRequest,
			body:    `{"message":"bad field id"}` + "\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := NewMux()
			mux.GET("/e", tc.handler)

			rec := serve(mux, http.MethodGet, "/e")

			if rec.Code != tc.code {
				t.Errorf("status = %d, want %d", rec.Code, tc.code)
			}
			if got := rec.Body.String(); got != tc.body {
				t.Errorf("body = %q, want %q", got, tc.body)
			}
		})
	}
}

// TestErrorRedaction pins what DefaultErrHandler is allowed to tell a client.
// It used to answer err.Error() verbatim, so a wrapped driver error published
// the database DSN and credentials to whoever made the request.
func TestErrorRedaction(t *testing.T) {
	secret := `pq: password authentication failed for user "admin" dsn=postgres://u:p@db:5432`

	for _, tc := range []struct {
		name    string
		handler HandlerFunc
		code    int
		body    string
	}{
		{
			name:    "raw 5xx error is redacted",
			handler: func(c *Context) error { return fmt.Errorf("query users: %w", errors.New(secret)) },
			code:    http.StatusInternalServerError,
			body:    `{"message":"Internal Server Error"}` + "\n",
		},
		{
			name:    "explicit 5xx via SetStatus is redacted with its own status text",
			handler: func(c *Context) error { return c.SetStatus(http.StatusBadGateway).Err(errors.New(secret)) },
			code:    http.StatusBadGateway,
			body:    `{"message":"Bad Gateway"}` + "\n",
		},
		{
			name:    "HTTPError 4xx message reaches the client",
			handler: func(c *Context) error { return NewHTTPError(http.StatusForbidden, "token expired") },
			code:    http.StatusForbidden,
			body:    `{"message":"token expired"}` + "\n",
		},
		{
			// Author-supplied text on an HTTPError is client-facing whatever
			// the status: it was written for this response, not leaked into it.
			name:    "HTTPError 5xx message reaches the client",
			handler: func(c *Context) error { return NewHTTPError(http.StatusServiceUnavailable, "reindexing, retry in 30s") },
			code:    http.StatusServiceUnavailable,
			body:    `{"message":"reindexing, retry in 30s"}` + "\n",
		},
		{
			name:    "HTTPError without a message falls back to status text",
			handler: func(c *Context) error { return NewHTTPError(http.StatusNotFound, "") },
			code:    http.StatusNotFound,
			body:    `{"message":"Not Found"}` + "\n",
		},
		{
			// Non-HTTPError 4xx stays useful: reaching a 4xx takes a
			// deliberate SetStatus in the handler.
			name: "deliberate 4xx keeps its text",
			handler: func(c *Context) error {
				return c.SetStatus(http.StatusBadRequest).Err(errors.New("field id must be an int"))
			},
			code: http.StatusBadRequest,
			body: `{"message":"field id must be an int"}` + "\n",
		},
		{
			// Context wrapped around an HTTPError is internal, so only the
			// HTTPError's own message is published.
			name: "wrapper text around an HTTPError is not published",
			handler: func(c *Context) error {
				return fmt.Errorf("load user from %s: %w", secret, NewHTTPError(http.StatusNotFound, "user not found"))
			},
			code: http.StatusNotFound,
			body: `{"message":"user not found"}` + "\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := NewMux()
			mux.GET("/e", tc.handler)

			rec := serve(mux, http.MethodGet, "/e")

			if rec.Code != tc.code {
				t.Errorf("status = %d, want %d", rec.Code, tc.code)
			}
			if got := rec.Body.String(); got != tc.body {
				t.Errorf("body = %q, want %q", got, tc.body)
			}
			if strings.Contains(rec.Body.String(), "postgres://") {
				t.Errorf("body leaked the DSN: %q", rec.Body.String())
			}
		})
	}
}

// TestErrorRedaction_ServerErrorIsLogged is the other half of redaction: the
// detail the client no longer receives must still reach the operator. Losing
// it silently would trade a disclosure bug for an undebuggable service.
func TestErrorRedaction_ServerErrorIsLogged(t *testing.T) {
	var logged bytes.Buffer

	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))

	secret := `pq: password authentication failed for user "admin"`

	mux := NewMux()
	mux.GET("/users", func(c *Context) error {
		return fmt.Errorf("query users: %w", errors.New(secret))
	})

	rec := serve(mux, http.MethodGet, "/users")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "password authentication") {
		t.Fatalf("client body leaked the cause: %q", rec.Body.String())
	}

	out := logged.String()
	for _, want := range []string{"query users", "password authentication", "status=500", "method=GET", "path=/users"} {
		if !strings.Contains(out, want) {
			t.Errorf("log %q does not contain %q", out, want)
		}
	}
}

// TestErrorRedaction_ClientErrorIsNotLogged keeps 4xx out of the error log:
// nothing is hidden from the client, so there is nothing for the operator to
// recover, and a bad request is not an operational failure.
func TestErrorRedaction_ClientErrorIsNotLogged(t *testing.T) {
	var logged bytes.Buffer

	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))

	mux := NewMux()
	mux.GET("/e", func(c *Context) error { return NewHTTPError(http.StatusNotFound, "user not found") })

	if rec := serve(mux, http.MethodGet, "/e"); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if logged.Len() != 0 {
		t.Errorf("4xx wrote to the error log: %q", logged.String())
	}
}

// TestNilDefaultErrHandler pins the fallback for an application that clears
// DefaultErrHandler. Nothing wrote the response, so net/http answered 200 with
// an empty body and reported every failure as a success.
func TestNilDefaultErrHandler(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler HandlerFunc
		code    int
		body    string
	}{
		{
			name:    "plain error writes 500",
			handler: func(c *Context) error { return errors.New("boom") },
			code:    http.StatusInternalServerError,
			body:    "Internal Server Error\n",
		},
		{
			name:    "HTTPError status is honoured",
			handler: func(c *Context) error { return NewHTTPError(http.StatusNotFound, "user not found") },
			code:    http.StatusNotFound,
			body:    "Not Found\n",
		},
		{
			// The fallback never leaks either: it writes the status text only.
			name:    "message is not published",
			handler: func(c *Context) error { return errors.New("dsn=postgres://u:p@db:5432") },
			code:    http.StatusInternalServerError,
			body:    "Internal Server Error\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := DefaultErrHandler
			t.Cleanup(func() { DefaultErrHandler = previous })
			DefaultErrHandler = nil

			mux := NewMux()
			mux.GET("/e", tc.handler)

			rec := serve(mux, http.MethodGet, "/e")

			if rec.Code != tc.code {
				t.Errorf("status = %d, want %d", rec.Code, tc.code)
			}
			if got := rec.Body.String(); got != tc.body {
				t.Errorf("body = %q, want %q", got, tc.body)
			}
		})
	}
}

// TestNilDefaultErrHandler_DoesNotOverwriteCommittedResponse keeps the
// fallback subject to the same commit guard as the Send* methods: a handler
// that wrote a response and then failed must not get a second status line.
func TestNilDefaultErrHandler_DoesNotOverwriteCommittedResponse(t *testing.T) {
	previous := DefaultErrHandler
	t.Cleanup(func() { DefaultErrHandler = previous })
	DefaultErrHandler = nil

	mux := NewMux()
	mux.GET("/e", func(c *Context) error {
		if err := c.SendString("first"); err != nil {
			return err
		}

		return errors.New("boom")
	})

	rec := serve(mux, http.MethodGet, "/e")

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (the first write wins)", rec.Code)
	}
	if got := rec.Body.String(); got != "first" {
		t.Errorf("body = %q, want %q", got, "first")
	}
}
