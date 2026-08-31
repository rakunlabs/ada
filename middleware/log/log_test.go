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

func TestTrustedAndUnsafeRealIPHelpers(t *testing.T) {
	r := request("10.0.0.3:443", map[string]string{
		"X-Forwarded-For": "192.0.2.99, 198.51.100.8, 10.0.0.2",
	})
	trusted := mlog.TrustedRealIP("10.0.0.0/8")
	if got := trusted(r); got != "198.51.100.8" {
		t.Fatalf("trusted RealIP = %q", got)
	}
	if got := mlog.UnsafeRealIP(r); got != "192.0.2.99" {
		t.Fatalf("unsafe RealIP = %q", got)
	}

	r.Header.Set("X-Forwarded-For", "malformed, 10.0.0.2")
	if got := trusted(r); got != "10.0.0.3" {
		t.Fatalf("malformed RealIP = %q, want immediate peer", got)
	}
}

func TestWithTrustedProxiesConfiguresDefaultLogger(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))

	logger := mlog.New(mlog.WithTrustedProxies("10.0.0.0/8"))
	r := request("10.0.0.2:443", map[string]string{"X-Real-IP": "198.51.100.8"})
	logger.PostFunc(r, &mlog.Response{})

	if !strings.Contains(output.String(), "remote_ip=198.51.100.8") {
		t.Fatalf("log output did not use trusted IP: %s", output.String())
	}
}

func TestTrustedProxyCIDRsValidateAtSetup(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("invalid trusted CIDR did not panic")
		}
	}()

	_ = mlog.WithTrustedProxies("invalid")
}
