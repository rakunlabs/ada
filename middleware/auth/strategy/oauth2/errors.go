package oauth2

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/rakunlabs/ada/middleware/auth/internal/bodylimit"
)

// Never retain upstream bodies, status text, URLs or transport errors: all can
// contain credentials. Only these protocol codes are safe diagnostic metadata.
func safeOAuthCode(code string) string {
	switch code {
	case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
		"unsupported_grant_type", "invalid_scope", "access_denied", "unsupported_response_type",
		"server_error", "temporarily_unavailable", "invalid_token", "insufficient_scope":
		return code
	default:
		return "unknown"
	}
}

type upstreamError struct {
	operation string
	status    int
	code      string
	tooLarge  bool
}

func (e *upstreamError) Is(target error) bool {
	return e.tooLarge && target == bodylimit.ErrUpstreamResponseTooLarge
}

func readError(operation string, status int, err error) error {
	return &upstreamError{operation: operation, status: status, tooLarge: errors.Is(err, bodylimit.ErrUpstreamResponseTooLarge)}
}

func (e *upstreamError) Error() string {
	return fmt.Sprintf("oauth2: %s failed (status=%d code=%s)", e.operation, e.status, e.code)
}

func responseError(operation string, status int, body []byte) error {
	var response struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &response)
	return &upstreamError{operation: operation, status: status, code: safeOAuthCode(response.Error)}
}

func (s *Strategy) logFailure(operation string, err error) {
	attrs := []any{"strategy", s.name, "operation", operation}
	var upstream *upstreamError
	if errors.As(err, &upstream) {
		attrs = append(attrs, "upstream_operation", upstream.operation, "upstream_status", upstream.status, "provider_error", upstream.code)
	}
	slog.Error("oauth2 request failed", attrs...)
}
