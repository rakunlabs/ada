package ratelimit_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rakunlabs/tummy"

	"github.com/rakunlabs/ada/middleware/ratelimit"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func sendFrom(handler http.Handler, remoteAddr string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestLimitAllAllowsExactlyN verifies that N requests pass and the (N+1)th is
// rejected with 429, matching httprate.LimitAll semantics.
func TestLimitAllAllowsExactlyN(t *testing.T) {
	useTummy(t)

	h := ratelimit.LimitAll(3, time.Minute)(okHandler())

	for i := 0; i < 3; i++ {
		if rec := sendFrom(h, "1.2.3.4:111", nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, rec.Code)
		}
	}
	rec := sendFrom(h, "1.2.3.4:111", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request: got %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header on reject")
	}
}

func TestSimpleLimiterPanicsOnNonPositiveConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limit  int
		window time.Duration
	}{
		{name: "zero limit", limit: 0, window: time.Minute},
		{name: "negative limit", limit: -1, window: time.Minute},
		{name: "zero window", limit: 1, window: 0},
		{name: "negative window", limit: 1, window: -time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("LimitAll accepted non-positive configuration")
				}
			}()
			_ = ratelimit.LimitAll(tc.limit, tc.window)
		})
	}
}

// TestLimitByIPIsPerClient verifies that distinct client IPs have independent
// budgets.
func TestLimitByIPIsPerClient(t *testing.T) {
	useTummy(t)

	h := ratelimit.LimitByIP(2, time.Minute)(okHandler())

	// IP A exhausts its budget.
	sendFrom(h, "10.0.0.1:5000", nil)
	sendFrom(h, "10.0.0.1:5000", nil)
	if rec := sendFrom(h, "10.0.0.1:5000", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("IP A 3rd: got %d, want 429", rec.Code)
	}

	// IP B is unaffected.
	if rec := sendFrom(h, "10.0.0.2:5000", nil); rec.Code != http.StatusOK {
		t.Fatalf("IP B 1st: got %d, want 200", rec.Code)
	}
}

func TestLimitByIPAccountsForNonIPPeers(t *testing.T) {
	useTummy(t)

	h := ratelimit.LimitByIP(1, time.Minute)(okHandler())
	if rec := sendFrom(h, "/run/ada.sock", nil); rec.Code != http.StatusOK {
		t.Fatalf("first Unix-peer request: got %d, want 200", rec.Code)
	}
	if rec := sendFrom(h, "/run/ada.sock", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second Unix-peer request: got %d, want 429", rec.Code)
	}
}

func TestKeyByIPCanonicalizesBoundedPeerFallback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[fe80:0:0::1%eth0]:1000"
	first := ratelimit.KeyByIP(req)

	req.RemoteAddr = "[fe80::1%eth0]:2000"
	second := ratelimit.KeyByIP(req)
	if first == "" || first != second {
		t.Fatalf("scoped IPv6 keys = %q and %q, want same non-empty key", first, second)
	}

	req.RemoteAddr = strings.Repeat("x", 4096)
	if got := ratelimit.KeyByIP(req); got == "" || len(got) > 80 {
		t.Fatalf("fallback key length = %d, want non-empty and at most 80", len(got))
	}
}

// TestWindowRollover verifies the budget refills after the window passes.
func TestWindowRollover(t *testing.T) {
	useTummy(t)

	h := ratelimit.LimitByIP(1, time.Minute)(okHandler())

	if rec := sendFrom(h, "9.9.9.9:1", nil); rec.Code != http.StatusOK {
		t.Fatalf("1st: got %d, want 200", rec.Code)
	}
	if rec := sendFrom(h, "9.9.9.9:1", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("2nd: got %d, want 429", rec.Code)
	}

	// Advance two full windows so both current and previous windows clear.
	tummy.AddDuration(2 * time.Minute)

	if rec := sendFrom(h, "9.9.9.9:1", nil); rec.Code != http.StatusOK {
		t.Fatalf("after rollover: got %d, want 200", rec.Code)
	}
}

func TestSimpleLimiterSaturatesWindowExpiry(t *testing.T) {
	useTummy(t)
	const maxDuration = time.Duration(1<<63 - 1)

	h := ratelimit.LimitAll(1, maxDuration)(okHandler())
	if rec := sendFrom(h, "1.2.3.4:111", nil); rec.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", rec.Code)
	}
	if rec := sendFrom(h, "1.2.3.4:111", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: got %d, want 429", rec.Code)
	}
}

func TestSimpleLimiterFormatsLargeRetryAfterWithoutIntOverflow(t *testing.T) {
	useTummy(t)
	const maxDuration = time.Duration(1<<63 - 1)

	h := ratelimit.LimitAll(1, maxDuration)(okHandler())
	_ = sendFrom(h, "1.2.3.4:111", nil)
	rec := sendFrom(h, "1.2.3.4:111", nil)
	if got := rec.Header().Get("Retry-After"); got != "9223372037" {
		t.Fatalf("Retry-After = %q, want int64-safe rounded value", got)
	}
}

func TestLimitByKeyDefaultsToImmediatePeer(t *testing.T) {
	useTummy(t)

	h := ratelimit.LimitByKey(1, time.Minute, nil)(okHandler())

	if rec := sendFrom(h, "192.168.0.1:80", map[string]string{"X-Real-IP": "1.1.1.1"}); rec.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", rec.Code)
	}
	if rec := sendFrom(h, "192.168.0.1:80", map[string]string{"X-Real-IP": "2.2.2.2"}); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed second identity got %d, want shared peer budget", rec.Code)
	}
}

// The proxy boundary is the caller's to define. LimitByKey must limit by
// whatever the injected resolver returns, without inspecting headers itself.
func TestLimitByKeyUsesInjectedResolver(t *testing.T) {
	useTummy(t)

	h := ratelimit.LimitByKey(1, time.Minute, func(r *http.Request) string {
		return r.Header.Get("X-Client")
	})(okHandler())

	if rec := sendFrom(h, "10.0.0.3:80", map[string]string{"X-Client": "a"}); rec.Code != http.StatusOK {
		t.Fatalf("client a: got %d, want 200", rec.Code)
	}
	if rec := sendFrom(h, "10.0.0.9:80", map[string]string{"X-Client": "a"}); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("client a from another peer: got %d, want 429", rec.Code)
	}
	if rec := sendFrom(h, "10.0.0.3:80", map[string]string{"X-Client": "b"}); rec.Code != http.StatusOK {
		t.Fatalf("client b: got %d, want 200", rec.Code)
	}
}

func TestKeyByIPIgnoresForwardingHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[2001:db8::10]:1234"
	r.Header.Set("X-Real-IP", "192.0.2.1")
	r.Header.Set("True-Client-IP", "192.0.2.2")
	r.Header.Set("X-Forwarded-For", "192.0.2.3")

	if got := ratelimit.KeyByIP(r); got != "2001:db8::10" {
		t.Fatalf("key = %q, want the immediate peer", got)
	}
}

func TestKeyByIPUnmaps4in6(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[::ffff:192.0.2.7]:443"

	if got := ratelimit.KeyByIP(r); got != "192.0.2.7" {
		t.Fatalf("key = %q, want one identity per client", got)
	}
}

// TestSimpleLimiterDoesNotSerialize ensures the simple limiter does not hold a
// lock across the handler (unlike the brute-force Middleware). A blocked
// handler for one in-flight request must not block a second request.
func TestSimpleLimiterDoesNotSerialize(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 2)

	blocking := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	})

	h := ratelimit.LimitAll(100, time.Minute)(blocking)

	go func() { sendFrom(h, "1.1.1.1:1", nil) }()
	go func() { sendFrom(h, "1.1.1.1:1", nil) }()

	// Both handlers must enter concurrently; if the limiter serialized on the
	// shared "*" key, only one would enter and this would time out.
	timeout := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-timeout:
			t.Fatalf("only %d handler(s) entered; limiter serialized requests", i)
		}
	}
	close(release)
}
