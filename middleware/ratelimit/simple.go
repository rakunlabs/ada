package ratelimit

import (
	"container/list"
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

// DefaultMaxKeys is the number of distinct keys a simple limiter tracks
// unless WithMaxKeys says otherwise.
const DefaultMaxKeys = 100_000

type option struct {
	ipv6Prefix int
	maxKeys    int
}

// Option configures LimitAll, LimitByIP and LimitByKey.
type Option func(*option)

// WithIPv6Prefix sets the prefix length IPv6 clients are aggregated to.
//   - Default is DefaultIPv6Prefix (/64), the smallest block a subscriber is
//     normally delegated. 128 keys on the full address.
//   - Applies to the immediate peer and to any key returned by a LimitByKey
//     resolver that is a bare IP address. IPv4 and 4-in-6 addresses are always
//     keyed whole.
//   - Values outside 1..128 panic at construction.
func WithIPv6Prefix(bits int) Option {
	return func(o *option) {
		o.ipv6Prefix = bits
	}
}

// WithMaxKeys caps the number of distinct keys tracked at once.
//   - Default is DefaultMaxKeys. Values below 1 panic at construction.
//   - Keys idle for two windows are dropped first. When the cap is still
//     reached, a request for an untracked key is rejected with 429 until an
//     entry ages out. Live entries are never evicted to make room, because
//     dropping one resets that client's budget.
func WithMaxKeys(n int) Option {
	return func(o *option) {
		o.maxKeys = n
	}
}

// LimitAll limits every request through a single shared counter, regardless
// of client. Equivalent to httprate.LimitAll.
func LimitAll(requestLimit int, windowLength time.Duration, opts ...Option) func(http.Handler) http.Handler {
	return newSimpleLimiter(requestLimit, windowLength, func(*http.Request) string {
		return "*"
	}, opts).handler
}

// LimitByIP limits requests per client IP, taken from r.RemoteAddr. IPv6
// clients are aggregated to their /64 by default; see WithIPv6Prefix.
// Equivalent to httprate.LimitByIP.
func LimitByIP(requestLimit int, windowLength time.Duration, opts ...Option) func(http.Handler) http.Handler {
	return newSimpleLimiter(requestLimit, windowLength, nil, opts).handler
}

// LimitByKey limits requests per key returned by keyFn.
//
// This is the seam for trusted-proxy handling: this package holds no proxy
// policy of its own, because deriving a client IP across a proxy boundary is a
// deployment decision, not a rate-limiting one. Behind a proxy, pass a resolver
// that knows the boundary, for example proxy.TrustedRealIP("10.0.0.0/8") from
// github.com/rakunlabs/ada/middleware/auth/proxy.
//
// A key that is a bare IPv6 address is masked to the configured prefix, the
// same as LimitByIP; any other key is used verbatim.
//
// A nil keyFn limits by the immediate peer, the same as LimitByIP.
func LimitByKey(requestLimit int, windowLength time.Duration, keyFn func(*http.Request) string, opts ...Option) func(http.Handler) http.Handler {
	return newSimpleLimiter(requestLimit, windowLength, keyFn, opts).handler
}

// KeyByIP returns the canonical client IP from r.RemoteAddr (port stripped),
// or a stable bounded identity when the immediate peer is not an IP transport.
// IPv6 peers are masked to DefaultIPv6Prefix and returned in CIDR form.
// Forwarding headers are ignored; see LimitByKey to honour them.
func KeyByIP(r *http.Request) string {
	return clientKey(r, DefaultIPv6Prefix)
}

// simpleLimiter is a sliding-window-counter rate limiter. It is safe for
// concurrent use and prunes stale windows lazily under its own lock.
type simpleLimiter struct {
	limit   int
	window  time.Duration
	expiry  time.Duration
	maxKeys int
	keyFn   func(*http.Request) string

	mu      sync.Mutex
	windows map[string]*list.Element
	// lru orders windows by last access, most recent at the front, so stale
	// entries are found at the back without scanning the map.
	lru *list.List
}

type counterWindow struct {
	key   string
	start time.Time // start of the current window
	seen  time.Time // last access
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
func newSimpleLimiter(limit int, window time.Duration, keyFn func(*http.Request) string, opts []Option) *simpleLimiter {
	if limit <= 0 {
		panic("ratelimit: requestLimit must be greater than zero")
	}
	if window <= 0 {
		panic("ratelimit: windowLength must be greater than zero")
	}

	o := option{
		ipv6Prefix: DefaultIPv6Prefix,
		maxKeys:    DefaultMaxKeys,
	}
	for _, opt := range opts {
		opt(&o)
	}
	if o.ipv6Prefix < 1 || o.ipv6Prefix > 128 {
		panic("ratelimit: IPv6 prefix must be between 1 and 128")
	}
	if o.maxKeys <= 0 {
		panic("ratelimit: max keys must be greater than zero")
	}

	prefix := o.ipv6Prefix
	if keyFn == nil {
		keyFn = func(r *http.Request) string {
			return clientKey(r, prefix)
		}
	} else {
		resolve := keyFn
		keyFn = func(r *http.Request) string {
			return maskIPKey(resolve(r), prefix)
		}
	}

	return &simpleLimiter{
		limit:   limit,
		window:  window,
		expiry:  saturatedDurationMultiply(window, 2),
		maxKeys: o.maxKeys,
		keyFn:   keyFn,
		windows: make(map[string]*list.Element),
		lru:     list.New(),
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

	l.pruneLocked(now)

	var win *counterWindow
	if element, ok := l.windows[key]; ok {
		win = element.Value.(*counterWindow)
		l.lru.MoveToFront(element)
	} else {
		if len(l.windows) >= l.maxKeys {
			// Every tracked key is still live. Retry once the least
			// recently seen one ages out.
			oldest := l.lru.Back().Value.(*counterWindow)
			return false, max(l.expiry-now.Sub(oldest.seen), time.Second)
		}
		win = &counterWindow{key: key, start: now}
		l.windows[key] = l.lru.PushFront(win)
	}
	win.seen = now

	elapsed := now.Sub(win.start)
	switch {
	case elapsed >= l.expiry:
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

// pruneLocked drops windows that have been idle for at least two window
// lengths. Such a window is fully stale, so dropping it cannot change a
// decision. Called under l.mu; it walks the LRU from the back and stops at the
// first live entry, so the cost is proportional to what it removes.
func (l *simpleLimiter) pruneLocked(now time.Time) {
	for element := l.lru.Back(); element != nil; {
		win := element.Value.(*counterWindow)
		if now.Sub(win.seen) < l.expiry {
			return
		}
		prev := element.Prev()
		l.lru.Remove(element)
		delete(l.windows, win.key)
		element = prev
	}
}
