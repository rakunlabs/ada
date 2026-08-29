package encoding

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAcceptEncodingNegotiation(t *testing.T) {
	tests := []struct {
		name           string
		acceptEncoding string
		compressed     bool
	}{
		{name: "gzip", acceptEncoding: "gzip", compressed: true},
		{name: "case insensitive", acceptEncoding: "GZip", compressed: true},
		{name: "token not substring", acceptEncoding: "xgzip", compressed: false},
		{name: "zero quality", acceptEncoding: "gzip;q=0", compressed: false},
		{name: "positive quality", acceptEncoding: "br;q=1, gzip; q=0.25", compressed: true},
		{name: "wildcard", acceptEncoding: "br;q=1, *;q=.5", compressed: true},
		{name: "explicit overrides wildcard", acceptEncoding: "gzip;q=0, *;q=1", compressed: false},
		{name: "invalid quality", acceptEncoding: "gzip;q=bogus", compressed: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := serve(t, http.MethodGet, tt.acceptEncoding, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "response body")
			})

			if got := recorder.Header().Get("Content-Encoding"); (got == "gzip") != tt.compressed {
				t.Fatalf("Content-Encoding = %q, compressed = %v", got, tt.compressed)
			}
			if got := responseBody(t, recorder); got != "response body" {
				t.Fatalf("body = %q", got)
			}
		})
	}
}

func TestNoAcceptableEncoding(t *testing.T) {
	recorder := serve(t, http.MethodGet, "gzip;q=0, identity;q=0", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "must not run")
	})

	if recorder.Code != http.StatusNotAcceptable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotAcceptable)
	}
}

func TestVaryAcceptEncoding(t *testing.T) {
	recorder := httptest.NewRecorder()
	recorder.Header().Add("Vary", "Origin")
	recorder.Header().Add("Vary", "accept-encoding")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, req)

	if got := recorder.Header().Values("Vary"); strings.Join(got, ",") != "Origin,accept-encoding" {
		t.Fatalf("Vary = %q", got)
	}
}

func TestCompressionBypassesIneligibleResponses(t *testing.T) {
	tests := []struct {
		name   string
		method string
		status int
		header func(http.Header)
	}{
		{name: "HEAD", method: http.MethodHead, status: http.StatusOK},
		{name: "informational", method: http.MethodGet, status: http.StatusEarlyHints},
		{name: "no content", method: http.MethodGet, status: http.StatusNoContent},
		{name: "not modified", method: http.MethodGet, status: http.StatusNotModified},
		{name: "existing encoding", method: http.MethodGet, status: http.StatusOK, header: func(h http.Header) { h.Set("Content-Encoding", "br") }},
		{name: "no transform", method: http.MethodGet, status: http.StatusOK, header: func(h http.Header) { h.Set("Cache-Control", "public, No-Transform") }},
		{name: "partial content", method: http.MethodGet, status: http.StatusPartialContent},
		{name: "content range", method: http.MethodGet, status: http.StatusOK, header: func(h http.Header) { h.Set("Content-Range", "bytes 0-3/10") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := serve(t, tt.method, "gzip", func(w http.ResponseWriter, _ *http.Request) {
				if tt.header != nil {
					tt.header(w.Header())
				}
				w.WriteHeader(tt.status)
				if tt.status != http.StatusNoContent && tt.status != http.StatusNotModified && tt.status >= 200 {
					_, _ = io.WriteString(w, "body")
				}
			})

			if got := recorder.Header().Get("Content-Encoding"); got == "gzip" {
				t.Fatalf("unexpected gzip Content-Encoding for status %d", tt.status)
			}
		})
	}
}

func TestContentEncodingIsDeferred(t *testing.T) {
	recorder := serve(t, http.MethodGet, "gzip", func(w http.ResponseWriter, _ *http.Request) {
		if got := w.Header().Get("Content-Encoding"); got != "" {
			t.Fatalf("Content-Encoding before write = %q", got)
		}
		w.Header().Set("Content-Length", "4")
		_, _ = io.WriteString(w, "body")
	})

	if got := recorder.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q", got)
	}
	if got := recorder.Header().Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length = %q", got)
	}
}

func TestFlushAndResponseController(t *testing.T) {
	underlying := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler := Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		controller := http.NewResponseController(w)
		if err := controller.EnableFullDuplex(); err != nil {
			t.Fatalf("EnableFullDuplex: %v", err)
		}
		if err := controller.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		_, _ = io.WriteString(w, "body")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	handler.ServeHTTP(underlying, req)

	if !underlying.flushed {
		t.Fatal("underlying writer was not flushed")
	}
	if !underlying.fullDuplex {
		t.Fatal("underlying writer did not enable full duplex")
	}
	if got := responseBody(t, underlying.ResponseRecorder); got != "body" {
		t.Fatalf("body = %q", got)
	}
}

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed    bool
	fullDuplex bool
}

func (r *flushRecorder) Flush() {
	r.flushed = true
	r.ResponseRecorder.Flush()
}

func (r *flushRecorder) EnableFullDuplex() error {
	r.fullDuplex = true
	return nil
}

func serve(t *testing.T, method, acceptEncoding string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(method, "/", nil)
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	Middleware()(handler).ServeHTTP(recorder, req)
	return recorder
}

func responseBody(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	if recorder.Header().Get("Content-Encoding") != "gzip" {
		return recorder.Body.String()
	}
	reader, err := gzip.NewReader(recorder.Body)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer reader.Close()
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read gzip body: %v", err)
	}
	return string(body)
}
