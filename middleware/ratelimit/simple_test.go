package ratelimit_test

import (
	"net/http"
	"net/http/httptest"
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

// TestLimitByRealIPPrefersHeaders verifies real-IP keying uses proxy headers.
func TestLimitByRealIPPrefersHeaders(t *testing.T) {
	useTummy(t)

	h := ratelimit.LimitByRealIP(1, time.Minute)(okHandler())

	// Same RemoteAddr (the proxy), different X-Real-IP → independent budgets.
	if rec := sendFrom(h, "192.168.0.1:80", map[string]string{"X-Real-IP": "1.1.1.1"}); rec.Code != http.StatusOK {
		t.Fatalf("client 1: got %d, want 200", rec.Code)
	}
	if rec := sendFrom(h, "192.168.0.1:80", map[string]string{"X-Real-IP": "1.1.1.1"}); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("client 1 repeat: got %d, want 429", rec.Code)
	}
	if rec := sendFrom(h, "192.168.0.1:80", map[string]string{"X-Real-IP": "2.2.2.2"}); rec.Code != http.StatusOK {
		t.Fatalf("client 2: got %d, want 200", rec.Code)
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
