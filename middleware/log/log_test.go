package log_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mlog "github.com/rakunlabs/ada/middleware/log"
)

func request(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://internal.example/", nil)
	r.RemoteAddr = remote
	for name, value := range headers {
		r.Header.Set(name, value)
	}

	return r
}

func TestRealIPIgnoresSpoofedHeaders(t *testing.T) {
	r := request("[2001:db8::1]:1234", map[string]string{
		"True-Client-IP":  "192.0.2.1",
		"X-Forwarded-For": "192.0.2.2",
		"X-Real-IP":       "192.0.2.3",
	})
	if got := mlog.RealIP(r); got != "2001:db8::1" {
		t.Fatalf("RealIP = %q", got)
	}
}

func TestRealIPUnmaps4in6(t *testing.T) {
	if got := mlog.RealIP(request("[::ffff:192.0.2.7]:443", nil)); got != "192.0.2.7" {
		t.Fatalf("RealIP = %q, want the unmapped form", got)
	}
}

// A non-IP peer must still produce a usable, bounded value rather than an
// unbounded socket path echoed into every log line.
func TestRealIPBoundsNonIPPeers(t *testing.T) {
	first := mlog.RealIP(request("/run/ada.sock", nil))
	second := mlog.RealIP(request("/run/ada.sock", nil))
	if first == "" || first != second {
		t.Fatalf("unix peer keys = %q and %q, want equal and non-empty", first, second)
	}

	if got := mlog.RealIP(request(strings.Repeat("x", 4096), nil)); len(got) > 80 {
		t.Fatalf("fallback length = %d, want at most 80", len(got))
	}
}

// The logger carries no proxy policy of its own; resolving forwarding headers
// is delegated to whatever resolver the caller injects.
func TestWithRealIPOverridesDefaultLogger(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))

	logger := mlog.New(mlog.WithRealIP(func(r *http.Request) string {
		return r.Header.Get("X-Real-IP")
	}))
	logger.PostFunc(request("10.0.0.2:443", map[string]string{"X-Real-IP": "198.51.100.8"}), &mlog.Response{})

	if !strings.Contains(output.String(), "remote_ip=198.51.100.8") {
		t.Fatalf("log output did not use the injected resolver: %s", output.String())
	}
}

func TestDefaultLoggerUsesImmediatePeer(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))

	logger := mlog.New()
	logger.PostFunc(request("10.0.0.2:443", map[string]string{"X-Real-IP": "198.51.100.8"}), &mlog.Response{})

	if !strings.Contains(output.String(), "remote_ip=10.0.0.2") {
		t.Fatalf("default logger honoured a forwarding header: %s", output.String())
	}
}

func TestWithRealIPNilRestoresDefault(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))

	logger := mlog.New(mlog.WithRealIP(nil))
	logger.PostFunc(request("10.0.0.2:443", map[string]string{"X-Real-IP": "198.51.100.8"}), &mlog.Response{})

	if !strings.Contains(output.String(), "remote_ip=10.0.0.2") {
		t.Fatalf("nil resolver did not fall back to the immediate peer: %s", output.String())
	}
}
