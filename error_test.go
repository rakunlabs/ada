package ada

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
			name:    "plain error defaults to 500",
			handler: func(c *Context) error { return errors.New("boom") },
			code:    http.StatusInternalServerError,
			body:    `{"message":"boom"}` + "\n",
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
			name:    "wrapped HTTPError is still found",
			handler: func(c *Context) error { return fmt.Errorf("layer: %w", NewHTTPError(http.StatusTeapot, "nope")) },
			code:    http.StatusTeapot,
			body:    `{"message":"layer: nope"}` + "\n",
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
