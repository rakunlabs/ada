// Package bodylimit provides enforced size limits for auth HTTP bodies.
package bodylimit

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Code is the machine-readable error code strategies report with a 413.
const Code = "body_too_large"

// ErrUpstreamResponseTooLarge identifies an oversized identity-provider
// response. It is intentionally distinct from a client request error.
var ErrUpstreamResponseTooLarge = errors.New("upstream response too large")

// Read consumes at most limit bytes of r.Body.
//
// A body longer than limit returns an *http.MaxBytesError. Callers must pass
// the writer handling this request so net/http can manage the unread body.
func Read(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return nil, err
	}

	return body, nil
}

// ReadUpstream reads an upstream response and detects the byte beyond limit.
func ReadUpstream(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: limit is %d bytes", ErrUpstreamResponseTooLarge, limit)
	}

	return body, nil
}

// Reject reports whether err came from a body that outgrew its limit and, if
// so, returns the status and message to answer with.
func Reject(err error) (status int, message string, ok bool) {
	var maxBytes *http.MaxBytesError
	if !errors.As(err, &maxBytes) {
		return 0, "", false
	}

	return http.StatusRequestEntityTooLarge, Message(maxBytes.Limit), true
}

// Message is the client-facing wording for a body that exceeded limit.
func Message(limit int64) string {
	return fmt.Sprintf("request body exceeds limit of %d bytes", limit)
}
