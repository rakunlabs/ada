package ratelimit

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rakunlabs/tummy"
)

// This file provides a lightweight, general-purpose request rate limiter that
// mirrors the ergonomics of github.com/go-chi/httprate: "allow at most N
// requests per window, keyed by IP / real IP / globally".
//
// It is deliberately separate from the Config/Middleware brute-force limiter
// in ratelimit.go:
//
//   - The brute-force limiter counts only selected responses (ShouldCount),
//     runs AFTER the handler, and holds a per-key lock across the handler so
//     concurrent attempts for the same key serialize. That is correct for
//     guarding login/auth endpoints but wrong for a general traffic limiter.
//
//   - This simple limiter counts EVERY request, rejects BEFORE the handler
//     runs, and never holds a lock across the handler — so it does not
//     serialize traffic. It uses a sliding-window-counter approximation
//     (current + time-weighted previous window), which is accurate and O(1)
//     in memory per active key.
//
// All time is read through tummy.Now() so tests can advance the clock.

// LimitAll limits every request through a single shared counter, regardless
// of client. Equivalent to httprate.LimitAll.
func LimitAll(requestLimit int, windowLength time.Duration) func(http.Handler) http.Handler {
	return newSimpleLimiter(requestLimit, windowLength, func(*http.Request) string {
		return "*"
	}).handler
}

// LimitByIP limits requests per client IP, taken from r.RemoteAddr.
// Equivalent to httprate.LimitByIP.
func LimitByIP(requestLimit int, windowLength time.Duration) func(http.Handler) http.Handler {
	return newSimpleLimiter(requestLimit, windowLength, KeyByIP).handler
}

// LimitByRealIP limits requests per client IP, preferring the proxy-supplied
// real IP headers (True-Client-IP, X-Real-IP, X-Forwarded-For) and falling
// back to r.RemoteAddr. Equivalent to httprate.LimitByRealIP.
func LimitByRealIP(requestLimit int, windowLength time.Duration) func(http.Handler) http.Handler {
	return newSimpleLimiter(requestLimit, windowLength, KeyByRealIP).handler
}

// KeyByIP returns the canonical client IP from r.RemoteAddr (port stripped).
func KeyByIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = strings.TrimSpace(r.RemoteAddr)
	}
	return canonicalIP(ip)
}

// KeyByRealIP returns the client IP, trusting common proxy headers first.
//   - True-Client-IP / X-Real-IP are used verbatim (single IP).
//   - X-Forwarded-For uses the first (left-most) entry.
//   - Falls back to r.RemoteAddr when no header is present.
func KeyByRealIP(r *http.Request) string {
	if tcip := r.Header.Get("True-Client-IP"); tcip != "" {
		return canonicalIP(tcip)
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return canonicalIP(xrip)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		return canonicalIP(strings.TrimSpace(xff))
	}
	return KeyByIP(r)
}

func canonicalIP(ip string) string {
	if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
		return parsed.String()
	}
	return strings.TrimSpace(ip)
}

// simpleLimiter is a sliding-window-counter rate limiter. It is safe for
// concurrent use and prunes stale windows lazily under its own lock.
type simpleLimiter struct {
	limit  int
	window time.Duration
	keyFn  func(*http.Request) string

	mu      sync.Mutex
	windows map[string]*counterWindow
	lastGC  time.Time
}

type counterWindow struct {
	start time.Time // start of the current window
	curr  int       // count in the current window
	prev  int       // count in the previous window
}

func newSimpleLimiter(limit int, window time.Duration, keyFn func(*http.Request) string) *simpleLimiter {
	if window <= 0 {
		window = time.Minute
	}
	return &simpleLimiter{
		limit:   limit,
		window:  window,
		keyFn:   keyFn,
		windows: make(map[string]*counterWindow),
		lastGC:  tummy.Now(),
	}
}

func (l *simpleLimiter) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A non-positive limit disables limiting (pass everything through).
		if l.limit <= 0 {
			next.ServeHTTP(w, r)
			return
		}

		key := l.keyFn(r)
		if key == "" {
			next.ServeHTTP(w, r)
			return
		}

		allowed, retryAfter := l.allow(key)
		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// allow records one hit for key and reports whether it is within the limit.
// When rejected it also returns the suggested Retry-After duration.
func (l *simpleLimiter) allow(key string) (bool, time.Duration) {
	now := tummy.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.gcLocked(now)

	win, ok := l.windows[key]
	if !ok {
		win = &counterWindow{start: now}
		l.windows[key] = win
	}

	elapsed := now.Sub(win.start)
	switch {
	case elapsed >= 2*l.window:
		// Both windows are stale.
		win.prev = 0
		win.curr = 0
		win.start = now
		elapsed = 0
	case elapsed >= l.window:
		// Roll the current window into previous.
		win.prev = win.curr
		win.curr = 0
		win.start = win.start.Add(l.window)
		elapsed -= l.window
	}

	// Sliding-window estimate: weighted carry-over from the previous window
	// plus the current window count.
	weight := float64(l.window-elapsed) / float64(l.window)
	rate := float64(win.prev)*weight + float64(win.curr)

	if rate+1 > float64(l.limit) {
		// Rejected: suggest retrying after the current window rolls over.
		retryAfter := l.window - elapsed
		if retryAfter < time.Second {
			retryAfter = time.Second
		}
		return false, retryAfter
	}

	win.curr++
	return true, 0
}

// gcLocked drops windows that have been idle for at least two window lengths.
// Called under l.mu. Runs at most once per window length to keep it cheap.
func (l *simpleLimiter) gcLocked(now time.Time) {
	if now.Sub(l.lastGC) < l.window {
		return
	}
	l.lastGC = now

	cutoff := 2 * l.window
	for k, win := range l.windows {
		if now.Sub(win.start) >= cutoff {
			delete(l.windows, k)
		}
	}
}
