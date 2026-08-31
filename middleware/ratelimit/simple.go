package ratelimit

import (
	"net/http"
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

// LimitByKey limits requests per key returned by keyFn.
//
// This is the seam for trusted-proxy handling: this package holds no proxy
// policy of its own, because deriving a client IP across a proxy boundary is a
// deployment decision, not a rate-limiting one. Behind a proxy, pass a resolver
// that knows the boundary, for example proxy.TrustedRealIP("10.0.0.0/8") from
// github.com/rakunlabs/ada/middleware/auth/proxy.
//
// A nil keyFn limits by the immediate peer, the same as LimitByIP.
func LimitByKey(requestLimit int, windowLength time.Duration, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	if keyFn == nil {
		keyFn = KeyByIP
	}

	return newSimpleLimiter(requestLimit, windowLength, keyFn).handler
}

// KeyByIP returns the canonical client IP from r.RemoteAddr (port stripped),
// or a stable bounded identity when the immediate peer is not an IP transport.
// Forwarding headers are ignored; see LimitByKey to honour them.
func KeyByIP(r *http.Request) string {
	return clientIP(r)
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

// newSimpleLimiter panics on a non-positive limit or window.
//
// Both are always configuration mistakes and both used to fail silently in the
// most dangerous possible direction: requestLimit <= 0 disabled limiting
// entirely, and windowLength <= 0 was quietly rewritten to one minute, so a
// caller who meant "1 request per second" and passed a bad duration got a limit
// 60x looser than intended. Neither is detectable at runtime — the middleware
// simply lets traffic through — so the mistake surfaces as a missing control in
// production rather than an error.
//
// Panicking at construction matches the rest of the repository:
// bodylimit.Middleware, ratelimit.Middleware, cors, forwardauth and the router
// all refuse to build a misconfigured value. Construction happens once at
// startup, so this fails immediately and loudly instead of per request. Callers
// who genuinely want no limit must omit the middleware rather than neuter it.
func newSimpleLimiter(limit int, window time.Duration, keyFn func(*http.Request) string) *simpleLimiter {
	if limit <= 0 {
		panic("ratelimit: requestLimit must be greater than zero")
	}
	if window <= 0 {
		panic("ratelimit: windowLength must be greater than zero")
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
		key := l.keyFn(r)
		if key == "" {
			next.ServeHTTP(w, r)
			return
		}

		allowed, retryAfter := l.allow(key)
		if !allowed {
			w.Header().Set("Retry-After", formatRetryAfter(retryAfter))
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
	expiry := saturatedDurationMultiply(l.window, 2)
	switch {
	case elapsed >= expiry:
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

	cutoff := saturatedDurationMultiply(l.window, 2)
	for k, win := range l.windows {
		if now.Sub(win.start) >= cutoff {
			delete(l.windows, k)
		}
	}
}
