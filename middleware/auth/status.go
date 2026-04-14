package auth

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"text/template"
)

//go:embed files/*
var filesFS embed.FS

// statusHandler renders the status iframe used by the login UI to detect a
// successful sign-in by polling for the success cookie from JS.
type statusHandler struct {
	tmpl *template.Template
}

func newStatusHandler() (*statusHandler, error) {
	sub, err := fs.Sub(filesFS, "files")
	if err != nil {
		return nil, err
	}

	data, err := fs.ReadFile(sub, "status-iframe.html")
	if err != nil {
		return nil, err
	}

	tmpl, err := template.New("status").Parse(string(data))
	if err != nil {
		return nil, err
	}

	return &statusHandler{tmpl: tmpl}, nil
}

func (s *statusHandler) serve(w http.ResponseWriter, _ *http.Request, cookieName string) {
	var buf bytes.Buffer
	if err := s.tmpl.Execute(&buf, map[string]any{"cookie": cookieName}); err != nil {
		http.Error(w, "render error: "+err.Error(), http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}
