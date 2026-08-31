package ada

import (
	"errors"
	"log/slog"
	"net/http"
)

// ErrAlreadyCommitted is returned by the Context Send* methods when the
// response has already been written. It lets a handler that both writes a
// response and returns an error fail loudly instead of emitting two bodies.
var ErrAlreadyCommitted = errors.New("ada: response already committed")

// HTTPError carries an HTTP status code alongside an error so a handler can
// express the status through the value it returns, instead of having to set it
// on the Context through a separate channel that can disagree with the error:
//
//	return ada.NewHTTPError(http.StatusNotFound, "user not found")
//	return ada.WrapHTTPError(http.StatusBadGateway, err)
//
// The error handler reads Code and applies it to the response.
type HTTPError struct {
	// Code is the HTTP status to respond with.
	Code int
	// Message is the client-facing text. Defaults to Err's text when built
	// with WrapHTTPError.
	Message string
	// Err is the underlying cause, if any. Exposed via errors.Unwrap.
	Err error
}

// NewHTTPError returns an HTTPError with the given status and message.
func NewHTTPError(code int, message string) *HTTPError {
	return &HTTPError{Code: code, Message: message}
}

// WrapHTTPError attaches a status code to an existing error, keeping it
// reachable through errors.Is / errors.As.
func WrapHTTPError(code int, err error) *HTTPError {
	message := ""
	if err != nil {
		message = err.Error()
	}

	return &HTTPError{Code: code, Message: message, Err: err}
}

func (e *HTTPError) Error() string {
	switch {
	case e.Message != "":
		return e.Message
	case e.Err != nil:
		return e.Err.Error()
	default:
		return http.StatusText(e.Code)
	}
}

func (e *HTTPError) Unwrap() error {
	return e.Err
}

// DefaultErrHandler is used when the Mux has no ErrorHandler of its own. It
// answers with {"message": ...} and never puts an error string the application
// did not mean for a client into that message.
//
// The status code is already normalised before this runs: an HTTPError's Code
// is applied when it is an error status, and any other error falls back to 500
// rather than inheriting a 2xx.
//
// The message is chosen by this rule, in order:
//
//  1. If an *HTTPError with an error status (>= 400) is anywhere in the chain,
//     its own text is sent — Message, else the text of its wrapped Err, else
//     the status text. That value is what supplied the status, and it is
//     author-written for clients. Text wrapped *around* the HTTPError by
//     intermediate layers (fmt.Errorf("query %s: %w", dsn, httpErr)) is not
//     sent: it is internal context that the author never aimed at a client.
//  2. Otherwise, if the status is a 4xx, the error text is sent. Reaching a 4xx
//     without an HTTPError takes a deliberate SetStatus/Err in the handler, and
//     client errors have to say what was wrong to be useful. Do not put secrets
//     in an error you deliberately answer 4xx with.
//  3. Otherwise the status is a 5xx and the error is an internal failure that
//     merely reached the top. The client gets the generic status text and the
//     real error is logged with slog at Error level, so operators keep the
//     detail that used to be handed to whoever made the request.
//
// WrapHTTPError copies the wrapped error's text into Message, so
// WrapHTTPError(status, err) publishes that text by rule 1 — it is an explicit
// statement that the text is fit to send. Use NewHTTPError with a written
// message when the cause is internal.
//
// Rule 3 is the reason this is not simply err.Error(): a wrapped driver error
// ("pq: password authentication failed for user \"admin\" dsn=...") is a
// perfectly ordinary 500, and it used to be echoed to the caller verbatim.
//
// A Mux ErrorHandler replaces this entirely and is responsible for its own
// redaction.
var DefaultErrHandler = func(c *Context, err error) {
	_ = c.SendJSON(map[string]string{"message": clientMessage(c, err)})
}

// clientMessage applies the redaction rule documented on DefaultErrHandler.
func clientMessage(c *Context, err error) string {
	if err == nil {
		return statusMessage(c.code)
	}

	var httpErr *HTTPError
	if errors.As(err, &httpErr) && httpErr.Code >= 400 {
		return httpErr.Error()
	}

	if c.code >= 400 && c.code < 500 {
		return err.Error()
	}

	logServerError(c, err)

	return statusMessage(c.code)
}

// statusMessage is http.StatusText with a fallback, so a non-standard code
// cannot produce an empty message.
func statusMessage(code int) string {
	if text := http.StatusText(code); text != "" {
		return text
	}

	return http.StatusText(http.StatusInternalServerError)
}

// logServerError reports an error that the client is not allowed to see. It is
// the operator's only view of it, so it must never be dropped silently.
//
// Neither Context nor Mux carries a Logger, so this uses the slog default
// logger; swapping it with slog.SetDefault redirects these records.
func logServerError(c *Context, err error) {
	attrs := []any{"status", c.code, "error", err}
	if c.Request != nil {
		attrs = append(attrs, "method", c.Request.Method)

		if c.Request.URL != nil {
			attrs = append(attrs, "path", c.Request.URL.Path)
		}
	}

	slog.Error("ada: unhandled error", attrs...)
}
