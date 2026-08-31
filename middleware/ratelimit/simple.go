package ratelimit

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rakunlabs/ada/utils/proxy"
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

// RealIPOption configures trusted-proxy handling for LimitByRealIP.
type RealIPOption func(*realIPConfig)

type realIPConfig struct {
	policy proxy.Policy
	unsafe bool
}

// WithTrustedProxies permits matching immediate peers to supply client IP
// forwarding headers. CIDRs are validated when this option is created; bare
// IPs are accepted as single-address prefixes.
func WithTrustedProxies(cidrs ...string) RealIPOption {
	policy, err := proxy.New(cidrs...)
	if err != nil {
		panic(fmt.Errorf("ratelimit: trusted proxies: %w", err))
	}

	return func(cfg *realIPConfig) {
		cfg.policy = policy
		cfg.unsafe = false
	}
}

// WithUnsafeProxyHeaders trusts client IP forwarding headers from every peer.
// It preserves legacy behavior for deployments with an external trust
// boundary. Prefer WithTrustedProxies.
func WithUnsafeProxyHeaders() RealIPOption {
	return func(cfg *realIPConfig) { cfg.unsafe = true }
}

// LimitByRealIP limits requests by the canonical immediate peer address. It
// ignores forwarding headers unless WithTrustedProxies or the explicitly
// unsafe compatibility option is supplied.
func LimitByRealIP(requestLimit int, windowLength time.Duration, opts ...RealIPOption) func(http.Handler) http.Handler {
	cfg := realIPConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	return newSimpleLimiter(requestLimit, windowLength, realIPKey(cfg)).handler
}

// KeyByIP returns the canonical client IP from r.RemoteAddr (port stripped),
// or a stable bounded identity when the immediate peer is not an IP transport.
func KeyByIP(r *http.Request) string {
	ip, _ := proxy.ClientIP(r)
	return ip
}

// KeyByRealIP returns the canonical immediate peer address and safely ignores
// forwarding headers. Use KeyByRealIPWithTrustedProxies to configure a proxy
// boundary.
func KeyByRealIP(r *http.Request) string {
	return KeyByIP(r)
}

// KeyByRealIPWithTrustedProxies returns a key function backed by a validated
// trusted-proxy policy.
func KeyByRealIPWithTrustedProxies(cidrs ...string) func(*http.Request) string {
	policy, err := proxy.New(cidrs...)
	if err != nil {
		panic(fmt.Errorf("ratelimit: trusted proxies: %w", err))
	}

	return realIPKey(realIPConfig{policy: policy})
}

// KeyByRealIPUnsafe trusts common client IP forwarding headers from every
// peer. Prefer KeyByRealIPWithTrustedProxies.
func KeyByRealIPUnsafe(r *http.Request) string {
	return realIPKey(realIPConfig{unsafe: true})(r)
}

// LimitByRealIPUnsafe preserves the legacy trust-all forwarding-header
// behavior under an explicit name.
func LimitByRealIPUnsafe(requestLimit int, windowLength time.Duration) func(http.Handler) http.Handler {
	return LimitByRealIP(requestLimit, windowLength, WithUnsafeProxyHeaders())
}

func realIPKey(cfg realIPConfig) func(*http.Request) string {
	return func(r *http.Request) string {
		var (
			ip  string
			err error
		)
		if cfg.unsafe {
			ip, err = proxy.UnsafeClientIP(r)
		} else {
			ip, err = cfg.policy.ClientIP(r)
		}
		if err == nil {
			return ip
		}

		// A malformed forwarded value must not become a new limiter key or
		// disable limiting. Group it under the canonical immediate peer.
		ip, _ = proxy.ClientIP(r)
		return ip
	}
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
