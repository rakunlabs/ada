package encoding

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

var bigBody = strings.Repeat("hello ada ", 500)

func intPtr(v int) *int { return &v }

func decode(t *testing.T, enc string, body []byte) string {
	t.Helper()

	var r io.Reader
	switch enc {
	case EncodingGzip:
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("gzip reader: %v", err)
		}
		r = gr
	case EncodingBrotli:
		r = brotli.NewReader(bytes.NewReader(body))
	case EncodingZstd:
		zr, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("zstd reader: %v", err)
		}
		defer zr.Close()
		r = zr
	default:
		return string(body)
	}

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decode %s: %v", enc, err)
	}
	return string(out)
}

func textHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, body)
	})
}

func do(h http.Handler, method, acceptEncoding string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/", nil)
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMultiEncodingNegotiation(t *testing.T) {
	tests := []struct {
		accept string
		want   string
	}{
		{"gzip", EncodingGzip},
		{"br", EncodingBrotli},
		{"zstd", EncodingZstd},
		{"gzip, deflate, br, zstd", EncodingZstd},
		{"gzip, br", EncodingBrotli},
		{"gzip;q=1, br;q=0.5", EncodingGzip},
		{"*", EncodingZstd},
		{"zstd;q=0, *", EncodingBrotli},
		{"zstd;q=0, br;q=0, gzip;q=0", ""},
		{"identity", ""},
		{"", ""},
	}

	h := Middleware()(textHandler(bigBody))

	for _, tt := range tests {
		t.Run(tt.accept, func(t *testing.T) {
			rec := do(h, http.MethodGet, tt.accept)

			if got := rec.Header().Get("Content-Encoding"); got != tt.want {
				t.Fatalf("Content-Encoding = %q, want %q", got, tt.want)
			}
			if got := decode(t, tt.want, rec.Body.Bytes()); got != bigBody {
				t.Fatalf("body mismatch, len %d", len(got))
			}
			if got := rec.Header().Get("Vary"); got != "Accept-Encoding" {
				t.Fatalf("Vary = %q", got)
			}
		})
	}
}

func TestServerPreference(t *testing.T) {
	h := Middleware(WithConfig(Config{Encoding: []string{"gzip", "br"}}))(textHandler(bigBody))

	if got := do(h, http.MethodGet, "br, gzip, zstd").Header().Get("Content-Encoding"); got != EncodingGzip {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
}

func TestMinLength(t *testing.T) {
	h := Middleware()(textHandler("small"))

	rec := do(h, http.MethodGet, "gzip")
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none", got)
	}
	if rec.Body.String() != "small" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestDeclaredSmallContentLengthIsNotBuffered(t *testing.T) {
	h := Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "5")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "small")
	}))

	rec := do(h, http.MethodGet, "gzip")
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none", got)
	}
	if got := rec.Header().Get("Content-Length"); got != "5" {
		t.Fatalf("Content-Length = %q, want 5", got)
	}
}

func TestContentTypeFilter(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		contentType string
		compressed  bool
	}{
		{name: "text", contentType: "text/html; charset=utf-8", compressed: true},
		{name: "default excluded png", contentType: "image/png"},
		{name: "default excluded case insensitive", contentType: "Image/PNG"},
		{name: "default allows svg", contentType: "image/svg+xml", compressed: true},
		{name: "custom exclusion drops default", config: Config{ExcludedContentTypes: []string{"text/*"}}, contentType: "image/png", compressed: true},
		{name: "custom exclusion", config: Config{ExcludedContentTypes: []string{"text/*"}}, contentType: "text/plain"},
		{name: "custom exclusion has no svg allowance", config: Config{ExcludedContentTypes: []string{"image/*"}}, contentType: "image/svg+xml"},
		{name: "empty exclusion", config: Config{ExcludedContentTypes: []string{}}, contentType: "application/zip", compressed: true},
		{name: "included", config: Config{IncludedContentTypes: []string{"application/json"}}, contentType: "application/json", compressed: true},
		{name: "not included", config: Config{IncludedContentTypes: []string{"application/json"}}, contentType: "text/plain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := Middleware(WithConfig(tt.config))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				_, _ = io.WriteString(w, bigBody)
			}))

			rec := do(h, http.MethodGet, "gzip")
			if got := rec.Header().Get("Content-Encoding"); (got != "") != tt.compressed {
				t.Fatalf("Content-Encoding = %q, compressed = %v", got, tt.compressed)
			}
			if got := decode(t, rec.Header().Get("Content-Encoding"), rec.Body.Bytes()); got != bigBody {
				t.Fatalf("body mismatch, len %d", len(got))
			}
		})
	}
}

func TestSniffedContentTypeIsFiltered(t *testing.T) {
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 2048)...)
	h := Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(png)
	}))

	rec := do(h, http.MethodGet, "gzip")
	if got := rec.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want none", got)
	}
}

func TestETagIsWeakened(t *testing.T) {
	h := Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "5000")
		w.Header().Set("ETag", `"abc"`)
		_, _ = io.WriteString(w, bigBody)
	}))

	rec := do(h, http.MethodGet, "gzip")
	if rec.Header().Get("Content-Length") != "" {
		t.Fatal("Content-Length must be removed")
	}
	if got := rec.Header().Get("ETag"); got != `W/"abc"` {
		t.Fatalf("ETag = %q", got)
	}
}

func TestUpgradeBypassesCompression(t *testing.T) {
	var gotWriter http.ResponseWriter
	h := Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		gotWriter = w
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Connection", "keep-alive, Upgrade")
	req.Header.Set("Upgrade", "websocket")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if gotWriter != rec {
		t.Fatalf("handler received wrapped writer %T", gotWriter)
	}
	if got := rec.Header().Get("Vary"); got != "" {
		t.Fatalf("Vary = %q, want empty", got)
	}
}

func TestEmptyResponse(t *testing.T) {
	h := Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	rec := do(h, http.MethodGet, "gzip")
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Content-Encoding") != "" {
		t.Fatalf("code = %d, body len = %d, encoding = %q", rec.Code, rec.Body.Len(), rec.Header().Get("Content-Encoding"))
	}
}

func TestFlushStreams(t *testing.T) {
	for _, enc := range defaultEncodings {
		t.Run(enc, func(t *testing.T) {
			flushed := make(chan struct{})
			done := make(chan struct{})

			h := Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: one\n\n")
				w.(http.Flusher).Flush()
				close(flushed)
				<-done
			}))

			srv := httptest.NewServer(h)
			defer srv.Close()
			defer close(done)

			req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
			req.Header.Set("Accept-Encoding", enc)

			resp, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()

			<-flushed

			if got := resp.Header.Get("Content-Encoding"); got != enc {
				t.Fatalf("Content-Encoding = %q", got)
			}

			var r io.Reader
			switch enc {
			case EncodingGzip:
				r, err = gzip.NewReader(resp.Body)
			case EncodingBrotli:
				r = brotli.NewReader(resp.Body)
			case EncodingZstd:
				var zr *zstd.Decoder
				zr, err = zstd.NewReader(resp.Body)
				r = zr
			}
			if err != nil {
				t.Fatal(err)
			}

			buf := make([]byte, len("data: one\n\n"))
			if _, err := io.ReadFull(r, buf); err != nil {
				t.Fatalf("read flushed data: %v", err)
			}
			if string(buf) != "data: one\n\n" {
				t.Fatalf("got %q", buf)
			}
		})
	}
}

func TestPooledEncodersAreReusedSafely(t *testing.T) {
	for _, enc := range defaultEncodings {
		t.Run(enc, func(t *testing.T) {
			h := Middleware()(textHandler(bigBody))
			for range 5 {
				rec := do(h, http.MethodGet, enc)
				if got := decode(t, enc, rec.Body.Bytes()); got != bigBody {
					t.Fatalf("body mismatch, len %d", len(got))
				}
			}
		})
	}
}
