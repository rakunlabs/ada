package ada

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/rakunlabs/ada/utils/bind"
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
//  2. If the chain says the request body exceeded a size limit, the message
//     bodyTooLargeError builds is sent, under rule 1: the condition is
//     equivalent to an *HTTPError the handler could have returned itself.
//     Only that message is published, not the surrounding wrapper text.
//  3. Otherwise, if the status is a 4xx, the error text is sent. Reaching a 4xx
//     without an HTTPError takes a deliberate SetStatus/Err in the handler, and
//     client errors have to say what was wrong to be useful. Do not put secrets
//     in an error you deliberately answer 4xx with.
//  4. Otherwise the status is a 5xx and the error is an internal failure that
//     merely reached the top. The client gets the generic status text and the
//     real error is logged with slog at Error level, so operators keep the
//     detail that used to be handed to whoever made the request.
//
// WrapHTTPError copies the wrapped error's text into Message, so
// WrapHTTPError(status, err) publishes that text by rule 1 — it is an explicit
// statement that the text is fit to send. Use NewHTTPError with a written
// message when the cause is internal.
//
// Rule 4 is the reason this is not simply err.Error(): a wrapped driver error
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

	if bodyErr, ok := bodyTooLargeError(err); ok {
		return bodyErr.Error()
	}

	if c.code >= 400 && c.code < 500 {
		return err.Error()
	}

	logServerError(c, err)

	return statusMessage(c.code)
}

// bodyTooLargeError recognises a request body that exceeded a size limit and
// restates it as the *HTTPError a handler could have returned itself.
//
// Two independent mechanisms produce this failure and neither is an
// *HTTPError: bind's WithBodyLimit, and the http.MaxBytesReader installed by
// the bodylimit middleware — the latter reaching a handler that never binds at
// all, as the error from io.ReadAll(r.Body). Both used to arrive as an
// anonymous error, which prepareError promoted to 500 and DefaultErrHandler
// then redacted, so the one fact the client needed to act on was visible only
// in the server log.
//
// Normalising both into one synthetic *HTTPError is what gives them the 413
// and, because rule 1 publishes an *HTTPError's own message, keeps the byte
// count reachable by the client. It is deliberately not left to clientMessage's
// generic 4xx branch, which the 413 would otherwise satisfy: that branch
// publishes err.Error(), i.e. whatever text intermediate layers wrapped around
// the failure. Only the message built here is client-facing.
//
// The limit is read from the error rather than the message, so the text stays
// this package's to choose.
func bodyTooLargeError(err error) (*HTTPError, bool) {
	var bindErr *bind.BodyTooLargeError
	if errors.As(err, &bindErr) {
		return newBodyTooLargeError(bindErr.Limit, err), true
	}

	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return newBodyTooLargeError(maxBytesErr.Limit, err), true
	}

	// An error that wraps the sentinel without carrying a limit still has to
	// answer 413; it just cannot say how many bytes were allowed.
	if errors.Is(err, bind.ErrBodyTooLarge) {
		return &HTTPError{
			Code:    http.StatusRequestEntityTooLarge,
			Message: bind.ErrBodyTooLarge.Error(),
			Err:     err,
		}, true
	}

	return nil, false
}

func newBodyTooLargeError(limit int64, err error) *HTTPError {
	return &HTTPError{
		Code:    http.StatusRequestEntityTooLarge,
		Message: fmt.Sprintf("request body exceeds limit of %d bytes", limit),
		Err:     err,
	}
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
