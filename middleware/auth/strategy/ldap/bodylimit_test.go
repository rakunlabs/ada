package ldap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type unusedConnector struct{}

func (unusedConnector) Connect(context.Context) (Conn, error) { return nil, nil }

func TestLoginBodyOver64KiBReturns413(t *testing.T) {
	s := New("ldap", unusedConnector{}, Config{}, AttributeMap{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", maxBodyBytes+1)))
	req.Header.Set("Content-Type", "application/json")
	_, _, _ = s.Login(rec, req)

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusRequestEntityTooLarge || body["error"] != "body_too_large" || !strings.Contains(body["message"], "65536") {
		t.Fatalf("response = %d %s", rec.Code, rec.Body)
	}
}
