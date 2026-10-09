package swagger

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/swaggo/swag"
)

type testDoc struct{}

func (testDoc) ReadDoc() string { return `{"swagger":"2.0"}` }

func TestHandler(t *testing.T) {
	swag.Register("swagger-test", testDoc{})

	h := Handler(
		WithInfoInstanceName("swagger-test"),
		WithConfigFns(func(c *Config) { c.DocExpansion = "none" }),
	)

	tests := []struct {
		name        string
		method      string
		path        string
		status      int
		contentType string
		contains    string
	}{
		{name: "redirect", method: http.MethodGet, path: "/api/swagger/", status: http.StatusMovedPermanently},
		{name: "index", method: http.MethodGet, path: "/api/swagger/index.html", status: http.StatusOK, contentType: "text/html", contains: `docExpansion: "none"`},
		{name: "doc", method: http.MethodGet, path: "/api/swagger/doc.json", status: http.StatusOK, contentType: "application/json", contains: `"swagger":"2.0"`},
		{name: "bundle", method: http.MethodGet, path: "/api/swagger/swagger-ui-bundle.js", status: http.StatusOK, contentType: "javascript"},
		{name: "preset", method: http.MethodGet, path: "/api/swagger/swagger-ui-standalone-preset.js", status: http.StatusOK, contentType: "javascript"},
		{name: "css", method: http.MethodGet, path: "/api/swagger/swagger-ui.css", status: http.StatusOK, contentType: "text/css"},
		{name: "favicon", method: http.MethodGet, path: "/api/swagger/favicon-32x32.png", status: http.StatusOK, contentType: "image/png"},
		{name: "oauth2 redirect", method: http.MethodGet, path: "/api/swagger/oauth2-redirect.html", status: http.StatusOK, contentType: "text/html"},
		{name: "source map removed", method: http.MethodGet, path: "/api/swagger/swagger-ui-bundle.js.map", status: http.StatusNotFound},
		{name: "traversal", method: http.MethodGet, path: "/api/swagger/../../etc/passwd", status: http.StatusNotFound},
		{name: "method", method: http.MethodPost, path: "/api/swagger/index.html", status: http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest(tt.method, tt.path, nil))

			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}

			if tt.status == http.StatusMovedPermanently {
				if loc := rec.Header().Get("Location"); loc != "/api/swagger/index.html" {
					t.Fatalf("location = %q", loc)
				}
			}

			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, tt.contentType) {
				t.Fatalf("content-type = %q, want %q", ct, tt.contentType)
			}

			if !strings.Contains(rec.Body.String(), tt.contains) {
				t.Fatalf("body does not contain %q", tt.contains)
			}
		})
	}
}
