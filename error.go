package ada

import (
	"errors"
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

// DefaultErrHandler is used when the Mux has no ErrorHandler of its own.
//   - The status code is already normalised before this runs: an HTTPError's
//     Code is applied, and any other error falls back to 500 rather than
//     inheriting a 2xx.
var DefaultErrHandler = func(c *Context, err error) {
	_ = c.SendJSON(map[string]string{"message": err.Error()})
}
