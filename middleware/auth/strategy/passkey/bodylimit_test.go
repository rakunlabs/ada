package passkey

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

func TestOversizedFinishBodyIs413NotBeginParseError(t *testing.T) {
	wa, err := New(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStrategy("passkey", wa, func(context.Context, []byte) (*Credential, *identity.Identity, error) {
		t.Fatal("credential lookup called")
		return nil, nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// The assertion marker is beyond the old truncation point, which used to
	// misclassify this finish request as a begin request.
	body := strings.Repeat(" ", maxLoginBody+1) + `{"assertion":{}}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	_, _, _ = s.Login(rec, req)

	var response map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusRequestEntityTooLarge || response["error"] != "body_too_large" || !strings.Contains(response["message"], "131072") {
		t.Fatalf("response = %d %s", rec.Code, rec.Body)
	}
}
