package forwardauth_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/forwardauth"
)

type capturedAuthRequest struct {
	headers http.Header
	method  string
}

// newAuthServer spins up a test auth service that captures the request it
// receives and answers with the given status/headers/body.
func newAuthServer(t *testing.T, status int, respHeaders http.Header, body string) (*httptest.Server, *capturedAuthRequest) {
	t.Helper()

	captured := &capturedAuthRequest{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.headers = r.Header.Clone()
		captured.method = r.Method

		for name, values := range respHeaders {
			for _, v := range values {
				w.Header().Add(name, v)
			}
		}

		w.WriteHeader(status)

		if body != "" {
			_, _ = io.WriteString(w, body)
		}
	}))

	t.Cleanup(srv.Close)

	return srv, captured
}

// recordingHandler returns an http.Handler that copies the request's headers
// so tests can assert the shape of the request seen by the backend.
func recordingHandler() (http.Handler, *http.Header) {
	var seen http.Header

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})

	return h, &seen
}

// --- Fix #1: X-Forwarded-For chain append -----------------------------------

func TestXForwardedFor_AppendedWhenTrusted(t *testing.T) {
	srv, captured := newAuthServer(t, http.StatusOK, nil, "")

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithTrustForwardHeader(true),
	)

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "1.1.1.1")
	req.RemoteAddr = "2.2.2.2:1234"

	h.ServeHTTP(httptest.NewRecorder(), req)

	got := captured.headers.Get("X-Forwarded-For")
	want := "1.1.1.1, 2.2.2.2"

	if got != want {
		t.Errorf("X-Forwarded-For = %q, want %q", got, want)
	}
}

func TestXForwardedFor_UsesClientIPWhenNoExistingChainTrusted(t *testing.T) {
	srv, captured := newAuthServer(t, http.StatusOK, nil, "")

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithTrustForwardHeader(true),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "2.2.2.2:1234"

	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

	if got := captured.headers.Get("X-Forwarded-For"); got != "2.2.2.2" {
		t.Errorf("X-Forwarded-For = %q, want 2.2.2.2", got)
	}
}

// --- Fix #2: buildRedirectTarget uses XF-Host/Uri when trusted --------------

func TestRedirect_UsesForwardedHeadersWhenTrusted(t *testing.T) {
	srv, _ := newAuthServer(t, http.StatusUnauthorized, nil, "")

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithTrustForwardHeader(true),
		forwardauth.WithRedirectURL("https://login.example.com?rd={url}&u={uri}&h={host}"),
	)

	req := httptest.NewRequest(http.MethodGet, "/inner/path", nil)
	req.Host = "internal.local"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("X-Forwarded-Uri", "/dashboard?tab=1")

	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}

	loc := rec.Header().Get("Location")

	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}

	q := parsed.Query()

	if got, want := q.Get("rd"), "https://app.example.com/dashboard?tab=1"; got != want {
		t.Errorf("rd = %q, want %q", got, want)
	}

	if got, want := q.Get("u"), "/dashboard?tab=1"; got != want {
		t.Errorf("u = %q, want %q", got, want)
	}

	if got, want := q.Get("h"), "app.example.com"; got != want {
		t.Errorf("h = %q, want %q", got, want)
	}
}

// --- Fix #3: multi-value headers preserved ----------------------------------

func TestMultiValueRequestHeaders_AllowlistPreservesAll(t *testing.T) {
	srv, captured := newAuthServer(t, http.StatusOK, nil, "")

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithAuthRequestHeaders("X-Custom"),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Add("X-Custom", "one")
	req.Header.Add("X-Custom", "two")
	req.Header.Add("X-Custom", "three")

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

	got := captured.headers.Values("X-Custom")
	want := []string{"one", "two", "three"}

	if !equalSlices(got, want) {
		t.Errorf("X-Custom values = %v, want %v", got, want)
	}
}

func TestMultiValueAuthResponseHeaders_CopiedToOriginalRequest(t *testing.T) {
	respHeaders := http.Header{}
	respHeaders.Add("X-Auth-Roles", "admin")
	respHeaders.Add("X-Auth-Roles", "editor")

	srv, _ := newAuthServer(t, http.StatusOK, respHeaders, "")

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithAuthResponseHeaders("X-Auth-Roles"),
	)

	backend, seen := recordingHandler()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	mw(backend).ServeHTTP(httptest.NewRecorder(), req)

	got := seen.Values("X-Auth-Roles")
	want := []string{"admin", "editor"}

	if !equalSlices(got, want) {
		t.Errorf("X-Auth-Roles values = %v, want %v", got, want)
	}
}

// --- Fix #4: body-shape headers are not forwarded to the auth service -------

func TestBodyHeaders_StrippedFromAuthRequest(t *testing.T) {
	srv, captured := newAuthServer(t, http.StatusOK, nil, "")

	mw := forwardauth.Middleware(forwardauth.WithAddress(srv.URL))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"x":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "7")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Transfer-Encoding", "chunked")

	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(httptest.NewRecorder(), req)

	for _, h := range []string{"Content-Type", "Content-Length", "Content-Encoding", "Transfer-Encoding"} {
		if v := captured.headers.Get(h); v != "" {
			t.Errorf("auth service received %s = %q, want stripped", h, v)
		}
	}
}

// --- Fix #5: Connection-listed hop-by-hop headers stripped ------------------

func TestConnectionListedHeaders_Stripped(t *testing.T) {
	srv, captured := newAuthServer(t, http.StatusOK, nil, "")

	mw := forwardauth.Middleware(forwardauth.WithAddress(srv.URL))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Connection", "X-Private-Hop, X-Another-Hop")
	req.Header.Set("X-Private-Hop", "should-be-dropped")
	req.Header.Set("X-Another-Hop", "also-dropped")
	req.Header.Set("X-Keep", "keep-me")

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

	if v := captured.headers.Get("X-Private-Hop"); v != "" {
		t.Errorf("X-Private-Hop leaked = %q", v)
	}

	if v := captured.headers.Get("X-Another-Hop"); v != "" {
		t.Errorf("X-Another-Hop leaked = %q", v)
	}

	if v := captured.headers.Get("X-Keep"); v != "keep-me" {
		t.Errorf("X-Keep = %q, want keep-me", v)
	}
}

// --- Fix #6: auth response body drained in 2xx path -------------------------

// drainTracker wraps a ReadCloser and records how much was read and whether
// Close was called. Used to verify that the 2xx path drains before handing off
// to the backend so the keep-alive connection can be reused.
type drainTracker struct {
	body   io.Reader
	read   atomic.Int64
	closed atomic.Bool
}

func (d *drainTracker) Read(p []byte) (int, error) {
	n, err := d.body.Read(p)
	d.read.Add(int64(n))

	return n, err
}

func (d *drainTracker) Close() error {
	d.closed.Store(true)

	return nil
}

type fixedTransport struct {
	body *drainTracker
}

func (ft *fixedTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Length": []string{"10"}},
		Body:       ft.body,
	}, nil
}

func TestAuthResponseBody_DrainedOn2xx(t *testing.T) {
	body := &drainTracker{body: strings.NewReader("0123456789")}

	mw := forwardauth.Middleware(
		forwardauth.WithAddress("http://placeholder"),
		forwardauth.WithTransport(&fixedTransport{body: body}),
	)

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", nil),
	)

	if body.read.Load() != 10 {
		t.Errorf("drained bytes = %d, want 10", body.read.Load())
	}

	if !body.closed.Load() {
		t.Errorf("auth response body was not closed")
	}
}

// --- Fix #7: custom Client / Transport injection ---------------------------

type markerTransport struct {
	inner http.RoundTripper
	seen  atomic.Bool
}

func (m *markerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	m.seen.Store(true)

	return m.inner.RoundTrip(r)
}

func TestCustomTransport_IsUsed(t *testing.T) {
	srv, _ := newAuthServer(t, http.StatusOK, nil, "")

	marker := &markerTransport{inner: http.DefaultTransport}

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithTransport(marker),
	)

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", nil),
	)

	if !marker.seen.Load() {
		t.Errorf("custom transport was not invoked")
	}
}

// --- Fix #8: OnError observability hook -------------------------------------

type errTransport struct{ err error }

func (e *errTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, e.err }

func TestOnError_CalledOnAuthFailure(t *testing.T) {
	sentinel := errors.New("boom")

	var gotErr error

	var gotReq *http.Request

	mw := forwardauth.Middleware(
		forwardauth.WithAddress("http://placeholder"),
		forwardauth.WithTransport(&errTransport{err: sentinel}),
		forwardauth.WithOnError(func(err error, r *http.Request) {
			gotErr = err
			gotReq = r
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}

	if gotErr == nil || !strings.Contains(gotErr.Error(), "boom") {
		t.Errorf("OnError got err = %v, want containing %q", gotErr, sentinel.Error())
	}

	if gotReq != req {
		t.Errorf("OnError got request = %p, want %p", gotReq, req)
	}
}

// --- Fix #9: allowlist drops hop-by-hop entries -----------------------------

func TestAllowlist_StripsHopByHop(t *testing.T) {
	srv, captured := newAuthServer(t, http.StatusOK, nil, "")

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithAuthRequestHeaders("Authorization", "Connection", "Keep-Alive"),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "timeout=5")

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

	if v := captured.headers.Get("Authorization"); v != "Bearer tok" {
		t.Errorf("Authorization = %q, want %q", v, "Bearer tok")
	}

	if v := captured.headers.Get("Keep-Alive"); v != "" {
		t.Errorf("Keep-Alive leaked = %q", v)
	}
}

// --- Fix #10: Validate surfaces config problems -----------------------------

func TestValidate_RejectsMissingAddress(t *testing.T) {
	f := forwardauth.New()
	if err := f.Validate(); err == nil {
		t.Fatalf("expected error for empty Address")
	}
}

func TestValidate_RejectsNon3xxRedirectCode(t *testing.T) {
	f := forwardauth.New(
		forwardauth.WithAddress("http://auth"),
		forwardauth.WithRedirectCode(200),
	)
	if err := f.Validate(); err == nil {
		t.Fatalf("expected error for non-3xx RedirectCode")
	}
}

func TestValidate_RejectsBadRegex(t *testing.T) {
	f := forwardauth.New(
		forwardauth.WithAddress("http://auth"),
		forwardauth.WithAuthResponseHeadersRegex("["),
	)
	if err := f.Validate(); err == nil {
		t.Fatalf("expected error for invalid regex")
	}
}

func TestMiddleware_PanicsOnInvalidConfig(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on invalid config")
		}
	}()

	forwardauth.Middleware() // empty Address
}

// --- Fix #11: regex compiled once, matches valid regex ---------------------

func TestAuthResponseHeadersRegex_Matches(t *testing.T) {
	respHeaders := http.Header{}
	respHeaders.Add("X-Auth-User", "alice")
	respHeaders.Add("X-Auth-Role", "admin")
	respHeaders.Add("X-Other", "ignored")

	srv, _ := newAuthServer(t, http.StatusOK, respHeaders, "")

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithAuthResponseHeadersRegex("^X-Auth-.*"),
	)

	backend, seen := recordingHandler()
	mw(backend).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", nil),
	)

	if seen.Get("X-Auth-User") != "alice" {
		t.Errorf("X-Auth-User missing")
	}

	if seen.Get("X-Auth-Role") != "admin" {
		t.Errorf("X-Auth-Role missing")
	}

	if seen.Get("X-Other") != "" {
		t.Errorf("X-Other leaked = %q", seen.Get("X-Other"))
	}
}

// --- Behavioural sanity: redirect only fires on GET/HEAD --------------------

func TestRedirect_NotAppliedOnPOST(t *testing.T) {
	srv, _ := newAuthServer(t, http.StatusUnauthorized, nil, "denied")

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithRedirectURL("https://login.example.com"),
	)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("x"))
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// --- Behavioural sanity: DeleteRequestHeaders runs before copy -------------

func TestDeleteRequestHeaders(t *testing.T) {
	respHeaders := http.Header{}
	respHeaders.Add("X-Set-Me", "fresh")

	srv, _ := newAuthServer(t, http.StatusOK, respHeaders, "")

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithDeleteRequestHeaders("X-Stale"),
		forwardauth.WithAuthResponseHeaders("X-Set-Me"),
	)

	backend, seen := recordingHandler()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Stale", "leftover")

	mw(backend).ServeHTTP(httptest.NewRecorder(), req)

	if v := seen.Get("X-Stale"); v != "" {
		t.Errorf("X-Stale leaked = %q", v)
	}

	if v := seen.Get("X-Set-Me"); v != "fresh" {
		t.Errorf("X-Set-Me = %q, want fresh", v)
	}
}

// --- Timeout sanity --------------------------------------------------------

func TestTimeout_YieldsBadGateway(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithTimeout(50*time.Millisecond),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

// --- Extractor: called on 2xx with auth response + request ----------------

func TestExtractor_Called(t *testing.T) {
	srv, _ := newAuthServer(t, http.StatusOK, nil, `{"subject":"alice"}`)

	var gotReq *http.Request

	var gotStatus int

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithExtractor(func(r *http.Request, resp *http.Response) (*http.Request, error) {
			gotReq = r
			gotStatus = resp.StatusCode

			return r, nil
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

	if gotReq == nil {
		t.Fatalf("extractor not invoked")
	}

	if gotStatus != http.StatusOK {
		t.Errorf("extractor got status = %d, want 200", gotStatus)
	}
}

type ctxKey struct{}

func TestExtractor_ContextPropagation(t *testing.T) {
	srv, _ := newAuthServer(t, http.StatusOK, nil, "")

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithExtractor(func(r *http.Request, _ *http.Response) (*http.Request, error) {
			return r.WithContext(context.WithValue(r.Context(), ctxKey{}, "alice")), nil
		}),
	)

	var seen string

	backend := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if v, ok := r.Context().Value(ctxKey{}).(string); ok {
			seen = v
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(backend).ServeHTTP(httptest.NewRecorder(), req)

	if seen != "alice" {
		t.Errorf("context value = %q, want %q", seen, "alice")
	}
}

func TestExtractor_NotCalledOnNon2xx(t *testing.T) {
	srv, _ := newAuthServer(t, http.StatusUnauthorized, nil, "denied")

	var called atomic.Bool

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithExtractor(func(r *http.Request, _ *http.Response) (*http.Request, error) {
			called.Store(true)

			return r, nil
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

	if called.Load() {
		t.Errorf("extractor invoked on non-2xx response")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestExtractor_ErrorFailsClosed(t *testing.T) {
	srv, _ := newAuthServer(t, http.StatusOK, nil, "{}")

	sentinel := errors.New("boom")

	var gotErr error

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithExtractor(func(*http.Request, *http.Response) (*http.Request, error) {
			return nil, sentinel
		}),
		forwardauth.WithOnError(func(err error, _ *http.Request) {
			gotErr = err
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	var nextCalled atomic.Bool

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled.Store(true)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}

	if !errors.Is(gotErr, sentinel) {
		t.Errorf("OnError got err = %v, want wrapping %v", gotErr, sentinel)
	}

	if nextCalled.Load() {
		t.Errorf("next handler invoked after extractor error")
	}
}

func TestExtractor_RunsAfterHeaderCopy(t *testing.T) {
	respHeaders := http.Header{}
	respHeaders.Set("X-Auth-User", "alice")

	srv, _ := newAuthServer(t, http.StatusOK, respHeaders, "")

	var seenHeader string

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithAuthResponseHeaders("X-Auth-User"),
		forwardauth.WithExtractor(func(r *http.Request, _ *http.Response) (*http.Request, error) {
			seenHeader = r.Header.Get("X-Auth-User")

			return r, nil
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

	if seenHeader != "alice" {
		t.Errorf("extractor saw X-Auth-User = %q, want alice (ran before header copy)", seenHeader)
	}
}

// --- MaxBodySize: cap auth response body ----------------------------------

func TestMaxBodySize_ExceededFailsClosed(t *testing.T) {
	body := strings.Repeat("x", 64)
	srv, _ := newAuthServer(t, http.StatusOK, nil, body)

	var gotErr error

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithMaxBodySize(16),
		forwardauth.WithExtractor(func(r *http.Request, resp *http.Response) (*http.Request, error) {
			if _, err := io.ReadAll(resp.Body); err != nil {
				return nil, fmt.Errorf("read: %w", err)
			}

			return r, nil
		}),
		forwardauth.WithOnError(func(err error, _ *http.Request) {
			gotErr = err
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}

	if gotErr == nil {
		t.Fatalf("OnError not called on oversize body")
	}

	var maxErr *http.MaxBytesError
	if !errors.As(gotErr, &maxErr) {
		t.Errorf("err = %v, want wrapping *http.MaxBytesError", gotErr)
	}
}

func TestMaxBodySize_DefaultAllowsSmall(t *testing.T) {
	body := strings.Repeat("x", 10*1024) // 10 KiB, well under 1 MiB default
	srv, _ := newAuthServer(t, http.StatusOK, nil, body)

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithExtractor(func(r *http.Request, resp *http.Response) (*http.Request, error) {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}

			if len(b) != 10*1024 {
				return nil, fmt.Errorf("read %d bytes, want %d", len(b), 10*1024)
			}

			return r, nil
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// --- IdentityExtractor: batteries-included JSON → identity.Identity -------

func TestIdentityExtractor_Decodes(t *testing.T) {
	body := `{"subject":"alice","email":"a@x","roles":["admin","editor"]}`
	srv, _ := newAuthServer(t, http.StatusOK, nil, body)

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithExtractor(forwardauth.IdentityExtractor),
	)

	var got *identity.Identity

	backend := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = identity.FromContext(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(backend).ServeHTTP(httptest.NewRecorder(), req)

	if got == nil {
		t.Fatalf("identity not in context")
	}

	if got.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", got.Subject)
	}

	if got.Email != "a@x" {
		t.Errorf("Email = %q, want a@x", got.Email)
	}

	if len(got.Roles) != 2 || got.Roles[0] != "admin" || got.Roles[1] != "editor" {
		t.Errorf("Roles = %v, want [admin editor]", got.Roles)
	}
}

func TestIdentityExtractor_EmptyBody(t *testing.T) {
	srv, _ := newAuthServer(t, http.StatusOK, nil, "")

	var gotErr error

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithExtractor(forwardauth.IdentityExtractor),
		forwardauth.WithOnError(func(err error, _ *http.Request) {
			gotErr = err
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}

	if gotErr == nil {
		t.Fatalf("OnError not called on empty body")
	}
}

func TestIdentityExtractor_MalformedJSON(t *testing.T) {
	srv, _ := newAuthServer(t, http.StatusOK, nil, "{")

	var gotErr error

	mw := forwardauth.Middleware(
		forwardauth.WithAddress(srv.URL),
		forwardauth.WithExtractor(forwardauth.IdentityExtractor),
		forwardauth.WithOnError(func(err error, _ *http.Request) {
			gotErr = err
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}

	if gotErr == nil {
		t.Fatalf("OnError not called on malformed JSON")
	}
}

// --- helpers ---------------------------------------------------------------

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
