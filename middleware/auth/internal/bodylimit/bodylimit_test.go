package bodylimit

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadReportsWrappedMaxBytesError(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345"))
	_, err := Read(httptest.NewRecorder(), r, 4)
	err = fmt.Errorf("strategy read: %w", err)

	var maxBytes *http.MaxBytesError
	if !errors.As(err, &maxBytes) || maxBytes.Limit != 4 {
		t.Fatalf("error = %v, want wrapped MaxBytesError with limit 4", err)
	}
	status, message, ok := Reject(err)
	if !ok || status != http.StatusRequestEntityTooLarge || message != "request body exceeds limit of 4 bytes" {
		t.Fatalf("Reject = (%d, %q, %v)", status, message, ok)
	}
}

func TestReadUpstreamDetectsByteBeyondLimit(t *testing.T) {
	if body, err := ReadUpstream(strings.NewReader("1234"), 4); err != nil || string(body) != "1234" {
		t.Fatalf("at limit: body=%q err=%v", body, err)
	}

	_, err := ReadUpstream(strings.NewReader("12345"), 4)
	if !errors.Is(err, ErrUpstreamResponseTooLarge) || !strings.Contains(err.Error(), "4 bytes") {
		t.Fatalf("over limit error = %v", err)
	}
}
