// Package ratelimit provides a generic, sliding-window HTTP rate-limit
// middleware suitable for guarding sensitive endpoints (login, signup,
// password reset, etc.).
//
// The middleware is storage-agnostic via the Store interface. Use
// NewMemoryStore for the common single-node case or NewCacheStore to
// wrap a github.com/rakunlabs/cache instance (e.g. redis-backed) for
// cluster-wide limits. The cache TTL/capacity invariants are encapsulated
// in those constructors so callers cannot accidentally weaken the defense
// by misconfiguring the cache.
//
// All time-related logic uses tummy.Now() so tests can advance the clock
// deterministically.
//
// Typical usage:
//
//	store, _ := ratelimit.NewMemoryStore(10_000)
//	mw := ratelimit.Middleware(ratelimit.Config{
//	    Window: 15 * time.Minute,
//	    SoftThreshold: 3, HardThreshold: 30,
//	    BackoffBase: time.Second, BackoffMax: 15 * time.Second,
//	    KeyFunc: func(r *http.Request) []string {
//	        return []string{"ip:" + clientIP(r)}
//	    },
//	    ShouldCount: func(_ *http.Request, status int) bool {
//	        return status == http.StatusUnauthorized
//	    },
//	    Store: store,
//	})
package ratelimit

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/rakunlabs/tummy"
)

// RejectReason describes why a request was rejected.
type RejectReason string

const (
	// ReasonHardThreshold means the per-key counter exceeded HardThreshold
	// within Window. The middleware responded with 429 Too Many Requests
	// and a Retry-After header.
	ReasonHardThreshold RejectReason = "hard_threshold"
)

// Decision is the limiter's per-key evaluation outcome. It is passed to
// OnAttempt for observability after the wrapped handler runs.
type Decision struct {
	// Key is the limiter key (Config.KeyFunc output) this decision is for.
	Key string
	// Count is the number of counted hits within the current window AFTER
	// this attempt is recorded.
	Count int
	// Delay is the backoff applied before the wrapped handler ran.
	Delay time.Duration
	// Rejected is true when the request was rejected with 429 (handler did
	// not run).
	Rejected bool
	// RetryAfter is the Retry-After value sent on a reject.
	RetryAfter time.Duration
}

// Bucket holds the per-key attempt history for one window. The package
// stores instances in the configured cache. Exported so callers can inspect
// state in tests; instances must be treated as immutable outside of the
// limiter (the limiter takes a fresh copy on every Set).
type Bucket struct {
	// Attempts is the timestamps of counted attempts within the window,
	// oldest first. Stale entries (older than Window) are pruned on every
	// read.
	Attempts []time.Time
}

// Config controls the middleware. Window, SoftThreshold, HardThreshold,
// KeyFunc, ShouldCount and Store are required; the rest are optional.
type Config struct {
	// Window is the sliding-window length. Attempts older than this are
	// dropped from the bucket on every observation.
	Window time.Duration `cfg:"window"`

	// SoftThreshold is the count at or above which the middleware sleeps
	// before invoking the handler. Set to 0 to disable backoff.
	SoftThreshold int `cfg:"soft_threshold"`

	// HardThreshold is the count at or above which the middleware rejects
	// the request with 429 and never invokes the handler. Set to 0 to
	// disable hard rejection.
	HardThreshold int `cfg:"hard_threshold"`

	// BackoffBase is the base of the exponential delay. The delay applied
	// at count = SoftThreshold + n is min(BackoffBase * 2^n, BackoffMax).
	// A zero BackoffBase disables the delay even when SoftThreshold trips.
	BackoffBase time.Duration `cfg:"backoff_base"`

	// BackoffMax caps the per-request delay. Zero means uncapped, which is
	// almost certainly wrong for production — set this to bound how long a
	// single request can hold a goroutine.
	BackoffMax time.Duration `cfg:"backoff_max"`

	// KeyFunc returns one or more keys to count this request under. Return
	// nil or empty to skip the limiter for this request (useful for
	// non-applicable paths). Each key is independently counted and any one
	// of them tripping HardThreshold rejects the request.
	KeyFunc func(*http.Request) []string

	// ShouldCount is invoked AFTER the wrapped handler runs with the
	// captured response status. Return true to count this request against
	// every key. Typical: status == 401 || status == 400.
	ShouldCount func(r *http.Request, status int) bool

	// OnReject is called when a key trips HardThreshold and the request is
	// blocked. Useful for audit logging. Optional.
	OnReject func(r *http.Request, key string, reason RejectReason, retryAfter time.Duration)

	// OnAttempt is called for every counted attempt with the post-handler
	// decision (one call per key). Optional.
	OnAttempt func(r *http.Request, decision Decision, status int)

	// Store is the backing storage for attempt buckets. Use
	// NewMemoryStore for single-node pika or NewCacheStore to plug in a
	// redis-backed cache for cluster-wide limits. Required.
	Store Store
}

// Middleware returns the http middleware enforcing cfg. Per-request flow:
//
//  1. KeyFunc(r) → if empty, pass through unmodified.
//  2. For each key:
//     a. Read bucket; drop entries older than Window.
//     b. If len(attempts) >= HardThreshold, write 429 + OnReject and stop.
//     c. Else compute backoff for the highest current count across keys.
//  3. Sleep for the computed backoff (if > 0).
//  4. Invoke next with a status-capturing ResponseWriter.
//  5. If ShouldCount(r, status), append tummy.Now() to every key's bucket,
//     persist, and call OnAttempt once per key.
//
// Concurrency: bucket reads/writes are atomic per key via an internal mutex
// pool. Two requests for the same key will serialize their read-update-write
// cycle; requests for different keys run in parallel.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	if cfg.Store == nil {
		// Fail loud: a misconfigured limiter that silently passes
		// every request would defeat the security intent.
		panic("ratelimit: Config.Store is required")
	}
	if cfg.KeyFunc == nil {
		panic("ratelimit: Config.KeyFunc is required")
	}
	if cfg.ShouldCount == nil {
		panic("ratelimit: Config.ShouldCount is required")
	}

	locks := newKeyLocks()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			keys := cfg.KeyFunc(r)
			if len(keys) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()

			// Per-key lock the read+evaluate phase so two concurrent
			// requests for the same key can't both squeak past the
			// hard threshold.
			holders := lockAll(locks, keys)
			defer holders.unlock()

			var maxCount int
			for _, key := range keys {
				bucket := loadBucket(ctx, cfg.Store, key, cfg.Window)
				count := len(bucket.Attempts)

				if cfg.HardThreshold > 0 && count >= cfg.HardThreshold {
					retryAfter := computeRetryAfter(bucket, cfg.Window)
					if retryAfter < time.Second {
						retryAfter = time.Second
					}
					if cfg.OnReject != nil {
						cfg.OnReject(r, key, ReasonHardThreshold, retryAfter)
					}
					w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(`{"error":"rate_limited","message":"too many attempts; try again later"}`))
					return
				}
				if count > maxCount {
					maxCount = count
				}
			}

			delay := computeBackoff(cfg, maxCount)
			if delay > 0 {
				// We hold the per-key locks during the sleep on purpose: a
				// burst of concurrent attempts shouldn't all stampede past
				// the soft threshold simultaneously. The mutex naturally
				// serializes them, which is the intended behavior for a
				// brute-force defense.
				time.Sleep(delay)
			}

			capW := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(capW, r)

			if !cfg.ShouldCount(r, capW.status) {
				return
			}

			now := tummy.Now()
			for _, key := range keys {
				bucket := loadBucket(ctx, cfg.Store, key, cfg.Window)
				bucket.Attempts = append(bucket.Attempts, now)
				_ = cfg.Store.Set(ctx, key, bucket)

				if cfg.OnAttempt != nil {
					cfg.OnAttempt(r, Decision{
						Key:      key,
						Count:    len(bucket.Attempts),
						Delay:    delay,
						Rejected: false,
					}, capW.status)
				}
			}
		})
	}
}

// loadBucket fetches the bucket for key, dropping entries older than window.
// Always returns a non-nil bucket (empty when nothing was stored or all
// entries were stale). The pruned bucket is NOT persisted here — it is
// persisted only when an attempt is actually counted, to avoid spurious
// writes on read-only checks.
func loadBucket(ctx context.Context, s Store, key string, window time.Duration) *Bucket {
	got, ok, err := s.Get(ctx, key)
	if err != nil || !ok || got == nil {
		return &Bucket{}
	}
	cutoff := tummy.Now().Add(-window)
	pruned := got.Attempts[:0:0]
	for _, t := range got.Attempts {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	return &Bucket{Attempts: pruned}
}

// computeRetryAfter returns the time until the oldest in-window attempt
// rolls off, which is when the requester would be unblocked.
func computeRetryAfter(b *Bucket, window time.Duration) time.Duration {
	if len(b.Attempts) == 0 {
		return 0
	}
	oldest := b.Attempts[0]
	until := oldest.Add(window).Sub(tummy.Now())
	if until < 0 {
		return 0
	}
	return until
}

// computeBackoff returns the delay to apply for the given attempt count.
// At count < SoftThreshold the result is 0. At count >= SoftThreshold the
// result is BackoffBase * 2^(count-SoftThreshold), capped at BackoffMax.
func computeBackoff(cfg Config, count int) time.Duration {
	if cfg.SoftThreshold <= 0 || count < cfg.SoftThreshold || cfg.BackoffBase <= 0 {
		return 0
	}
	shift := count - cfg.SoftThreshold
	// Cap shift to prevent overflow: 2^62 ns is already centuries.
	if shift > 62 {
		shift = 62
	}
	delay := cfg.BackoffBase << shift
	if delay <= 0 {
		// Overflow guard.
		delay = cfg.BackoffMax
	}
	if cfg.BackoffMax > 0 && delay > cfg.BackoffMax {
		delay = cfg.BackoffMax
	}
	return delay
}

// statusRecorder captures the response status code for ShouldCount.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	s.status = code
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		// Implicit 200 — Go's http package does this for us, but we
		// also need to record it.
		s.status = http.StatusOK
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

// keyLocks provides a string-keyed mutex pool. Per-key locking ensures that
// concurrent requests for the same key serialize their read-evaluate-write
// cycle, which prevents thundering-herd evasion of the hard threshold.
type keyLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func newKeyLocks() *keyLocks {
	return &keyLocks{locks: make(map[string]*sync.Mutex)}
}

func (k *keyLocks) get(key string) *sync.Mutex {
	k.mu.Lock()
	defer k.mu.Unlock()
	m, ok := k.locks[key]
	if !ok {
		m = &sync.Mutex{}
		k.locks[key] = m
	}
	return m
}

// lockAll acquires locks for the given keys in deterministic order to
// prevent deadlocks when two requests share overlapping key sets.
func lockAll(k *keyLocks, keys []string) heldLocks {
	// Deduplicate and sort to enforce a global lock order.
	seen := make(map[string]struct{}, len(keys))
	uniq := make([]string, 0, len(keys))
	for _, key := range keys {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		uniq = append(uniq, key)
	}
	sortStrings(uniq)

	held := heldLocks{locks: make([]*sync.Mutex, 0, len(uniq))}
	for _, key := range uniq {
		l := k.get(key)
		l.Lock()
		held.locks = append(held.locks, l)
	}
	return held
}

type heldLocks struct {
	locks []*sync.Mutex
}

func (h heldLocks) unlock() {
	// Unlock in reverse order for symmetry with acquisition.
	for i := len(h.locks) - 1; i >= 0; i-- {
		h.locks[i].Unlock()
	}
}

// sortStrings sorts a small slice in place; using a private helper avoids
// importing sort solely for this single call site.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
