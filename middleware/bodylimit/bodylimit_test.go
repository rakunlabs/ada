package bodylimit_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/bodylimit"
)

// limit is the byte budget used by most tests. Small on purpose so payloads
// stay readable.
const limit int64 = 16

// trackedReader counts how often the middleware touched the request body, so
// tests can prove the up-front rejection never reads it.
type trackedReader struct {
	r      io.Reader
	reads  atomic.Int64
	closes atomic.Int64
}

func (t *trackedReader) Read(p []byte) (int, error) {
	t.reads.Add(1)

	return t.r.Read(p)
}

func (t *trackedReader) Close() error {
	t.closes.Add(1)

	return nil
}

func newRequest(target, body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
}

func serve(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return rec
}

func tooLargeBody(limit int64) string {
	return `{"error":"body_too_large","message":"request body exceeds limit of ` +
		strconv.FormatInt(limit, 10) + ` bytes"}`
}

func assertTooLarge(t *testing.T, rec *httptest.ResponseRecorder, limit int64) {
	t.Helper()

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/json")
	}
	if got, want := rec.Body.String(), tooLargeBody(limit); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestWithinLimitReachesHandlerWithFullBody(t *testing.T) {
	tests := []struct {
		name string
		size int64
	}{
		{name: "empty body", size: 0},
		{name: "single byte", size: 1},
		{name: "one below limit", size: limit - 1},
		{name: "exactly at limit", size: limit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := strings.Repeat("a", int(tt.size))
			var got []byte
			var readErr error
			handler := bodylimit.Middleware(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, readErr = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusAccepted)
			}))

			rec := serve(handler, newRequest("/upload", payload))

			if readErr != nil {
				t.Fatalf("handler read body: %v", readErr)
			}
			if string(got) != payload {
				t.Fatalf("handler saw %q, want %q", got, payload)
			}
			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
			}
		})
	}
}

func TestOversizedContentLengthIsRejectedWithoutReadingBody(t *testing.T) {
	body := &trackedReader{r: strings.NewReader(strings.Repeat("a", int(limit)+1))}
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.ContentLength = limit + 1

	handler := bodylimit.Middleware(limit)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler ran for an oversized Content-Length")
	}))

	rec := serve(handler, req)

	assertTooLarge(t, rec, limit)
	if got := body.reads.Load(); got != 0 {
		t.Fatalf("body was read %d times, want 0", got)
	}
	// Closing the body is net/http's job, not the middleware's.
	if got := body.closes.Load(); got != 0 {
		t.Fatalf("body was closed %d times, want 0", got)
	}
}

func TestRejectionBodyIsWellFormedJSON(t *testing.T) {
	req := newRequest("/upload", strings.Repeat("a", int(limit)+1))
	handler := bodylimit.Middleware(limit)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler ran for an oversized Content-Length")
	}))

	rec := serve(handler, req)

	var got struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal rejection body %q: %v", rec.Body.String(), err)
	}
	if got.Error != "body_too_large" {
		t.Fatalf("error = %q, want %q", got.Error, "body_too_large")
	}
	if want := "request body exceeds limit of 16 bytes"; got.Message != want {
		t.Fatalf("message = %q, want %q", got.Message, want)
	}
}

func TestRejectionReportsTheConfiguredLimit(t *testing.T) {
	for _, configured := range []int64{1, 1024, 1 << 20, math.MaxInt64 - 1} {
		t.Run(strconv.FormatInt(configured, 10), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("x"))
			req.ContentLength = configured + 1

			rec := serve(bodylimit.Middleware(configured)(http.HandlerFunc(
				func(http.ResponseWriter, *http.Request) {
					t.Error("handler ran for an oversized Content-Length")
				},
			)), req)

			assertTooLarge(t, rec, configured)
		})
	}
}

func TestUnverifiedLengthIsCaughtAtReadTime(t *testing.T) {
	tests := []struct {
		name          string
		contentLength int64
	}{
		{name: "unknown length", contentLength: -1},
		{name: "lying content length", contentLength: 4},
		{name: "content length exactly at limit", contentLength: limit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := strings.Repeat("a", int(limit)*4)
			req := httptest.NewRequest(http.MethodPost, "/upload", io.NopCloser(strings.NewReader(payload)))
			req.ContentLength = tt.contentLength

			var read []byte
			var readErr error
			called := false
			handler := bodylimit.Middleware(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				read, readErr = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusAccepted)
			}))

			rec := serve(handler, req)

			if !called {
				t.Fatal("handler did not run; the limit must be enforced at read time here")
			}
			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want %d: the handler owns the response", rec.Code, http.StatusAccepted)
			}
			var maxErr *http.MaxBytesError
			if !errors.As(readErr, &maxErr) {
				t.Fatalf("read error = %v, want *http.MaxBytesError", readErr)
			}
			if maxErr.Limit != limit {
				t.Fatalf("MaxBytesError.Limit = %d, want %d", maxErr.Limit, limit)
			}
			if int64(len(read)) > limit {
				t.Fatalf("handler read %d bytes, more than the %d byte limit", len(read), limit)
			}
		})
	}
}

func TestSkipperLeavesRequestUntouched(t *testing.T) {
	payload := strings.Repeat("a", int(limit)*4)
	var seenPaths []string

	mw := bodylimit.Middleware(limit, bodylimit.WithSkipper(func(r *http.Request) bool {
		seenPaths = append(seenPaths, r.URL.Path)

		return r.URL.Path == "/raw"
	}))

	t.Run("skipped request is neither rejected nor wrapped", func(t *testing.T) {
		var got []byte
		var readErr error
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, readErr = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusAccepted)
		}))

		rec := serve(handler, newRequest("/raw", payload))

		if readErr != nil {
			t.Fatalf("handler read body: %v", readErr)
		}
		if string(got) != payload {
			t.Fatalf("handler read %d bytes, want the full %d byte payload", len(got), len(payload))
		}
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
		}
	})

	t.Run("non skipped request is still limited", func(t *testing.T) {
		handler := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("handler ran for an oversized Content-Length")
		}))

		assertTooLarge(t, serve(handler, newRequest("/guarded", payload)), limit)
	})

	if want := []string{"/raw", "/guarded"}; len(seenPaths) != len(want) {
		t.Fatalf("skipper saw %v, want %v", seenPaths, want)
	}
}

func TestNilSkipperLimitsEveryRequest(t *testing.T) {
	handler := bodylimit.Middleware(limit, bodylimit.WithSkipper(nil))(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			t.Error("handler ran for an oversized Content-Length")
		},
	))

	assertTooLarge(t, serve(handler, newRequest("/upload", strings.Repeat("a", int(limit)+1))), limit)
}

func TestNonPositiveLimitPanics(t *testing.T) {
	tests := []struct {
		name  string
		limit int64
	}{
		{name: "zero", limit: 0},
		{name: "negative", limit: -1},
		{name: "min int64", limit: math.MinInt64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				recovered := recover()
				if recovered == nil {
					t.Fatalf("Middleware(%d) did not panic", tt.limit)
				}
				want := "bodylimit: limit must be greater than zero"
				if got, ok := recovered.(string); !ok || got != want {
					t.Fatalf("panic = %v, want %q", recovered, want)
				}
			}()

			_ = bodylimit.Middleware(tt.limit)
		})
	}
}

func TestNilBodyIsLeftAlone(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/upload", nil)
	req.Body = nil

	called := false
	handler := bodylimit.Middleware(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Body != nil {
			t.Error("nil body was wrapped")
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	rec := serve(handler, req)

	if !called {
		t.Fatal("handler did not run")
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
}

func multipartBody(t *testing.T, field, filename, content string) (string, string) {
	t.Helper()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := io.WriteString(part, content); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	return buf.String(), writer.FormDataContentType()
}

func TestParseMultipartFormWorksThroughWrappedBody(t *testing.T) {
	const want = "hello wrapped body"
	payload, contentType := multipartBody(t, "file", "note.txt", want)

	var got string
	var handlerErr error
	// The limit is exactly the payload size, so this also covers the
	// boundary case for a multipart upload.
	handler := bodylimit.Middleware(int64(len(payload)))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handlerErr = r.ParseMultipartForm(1 << 20); handlerErr != nil {
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			handlerErr = err

			return
		}
		defer func() { _ = file.Close() }()

		content, err := io.ReadAll(file)
		if err != nil {
			handlerErr = err

			return
		}
		got = string(content)
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(payload))
	req.Header.Set("Content-Type", contentType)

	rec := serve(handler, req)

	if handlerErr != nil {
		t.Fatalf("multipart handling: %v", handlerErr)
	}
	if got != want {
		t.Fatalf("uploaded content = %q, want %q", got, want)
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
	}
}

func TestParseMultipartFormFailsOnceTheLimitIsExceeded(t *testing.T) {
	payload, contentType := multipartBody(t, "file", "note.txt", strings.Repeat("a", 512))

	var handlerErr error
	handler := bodylimit.Middleware(limit)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		handlerErr = r.ParseMultipartForm(1 << 20)
	}))

	req := httptest.NewRequest(http.MethodPost, "/upload", io.NopCloser(strings.NewReader(payload)))
	req.Header.Set("Content-Type", contentType)
	// Unknown length, so the up-front check cannot fire and the wrapped body
	// has to catch it.
	req.ContentLength = -1

	serve(handler, req)

	var maxErr *http.MaxBytesError
	if !errors.As(handlerErr, &maxErr) {
		t.Fatalf("ParseMultipartForm error = %v, want *http.MaxBytesError", handlerErr)
	}
	if maxErr.Limit != limit {
		t.Fatalf("MaxBytesError.Limit = %d, want %d", maxErr.Limit, limit)
	}
}

func TestConnectionCloseOnlyOnHTTP1Rejection(t *testing.T) {
	tests := []struct {
		name           string
		proto          string
		major          int
		minor          int
		wantConnection string
	}{
		{name: "http/1.1", proto: "HTTP/1.1", major: 1, minor: 1, wantConnection: "close"},
		{name: "http/1.0", proto: "HTTP/1.0", major: 1, minor: 0, wantConnection: "close"},
		// Connection-specific headers are illegal in HTTP/2 and Go's HTTP/2
		// server turns "Connection: close" into a GOAWAY for the whole
		// connection, which would punish unrelated streams.
		{name: "http/2", proto: "HTTP/2.0", major: 2, minor: 0, wantConnection: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newRequest("/upload", strings.Repeat("a", int(limit)+1))
			req.Proto, req.ProtoMajor, req.ProtoMinor = tt.proto, tt.major, tt.minor

			rec := serve(bodylimit.Middleware(limit)(http.HandlerFunc(
				func(http.ResponseWriter, *http.Request) {
					t.Error("handler ran for an oversized Content-Length")
				},
			)), req)

			assertTooLarge(t, rec, limit)
			if got := rec.Header().Get("Connection"); got != tt.wantConnection {
				t.Fatalf("Connection = %q, want %q", got, tt.wantConnection)
			}
		})
	}
}

// TestRejectsBeforeClientSendsBody drives a real server over a raw socket. The
// request announces a body far larger than the limit and never sends a byte of
// it, so the response can only arrive if the middleware rejects up front.
func TestRejectsBeforeClientSendsBody(t *testing.T) {
	var handlerCalls atomic.Int64
	server := httptest.NewServer(bodylimit.Middleware(limit)(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			handlerCalls.Add(1)
		},
	)))
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	request := "POST /upload HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 1048576\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write request head: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/json")
	}
	if got, want := string(body), tooLargeBody(limit); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
	if !resp.Close {
		t.Fatalf("Connection = %q, want the server to close the connection", resp.Header.Get("Connection"))
	}
	if got := handlerCalls.Load(); got != 0 {
		t.Fatalf("handler ran %d times, want 0", got)
	}

	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("read after response = %v, want EOF from a closed connection", err)
	}
}
