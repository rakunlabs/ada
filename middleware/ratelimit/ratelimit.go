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
	"bytes"
	"context"
	"errors"
	"fmt"
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

const DefaultResponseBufferLimit int64 = 1 << 20 // 1 MiB

var ErrResponseTooLarge = errors.New("ratelimit: downstream response exceeds buffer limit")

// ErrorPolicy controls what the middleware does when its Store fails.
type ErrorPolicy uint8

const (
	// ErrorPolicyFailClosed rejects the request with 503. This is the default
	// because silently bypassing a security control is unsafe.
	ErrorPolicyFailClosed ErrorPolicy = iota
	// ErrorPolicyFailOpen lets the request continue without rate limiting.
	ErrorPolicyFailOpen
)

// StoreOperation identifies the Store operation that failed.
type StoreOperation string

const (
	StoreOperationGet StoreOperation = "get"
	StoreOperationSet StoreOperation = "set"
)

// StoreError adds operation and key context to an error returned by Store.
type StoreError struct {
	Operation StoreOperation
	Key       string
	Err       error
}

func (e *StoreError) Error() string {
	return fmt.Sprintf("ratelimit: store %s %q: %v", e.Operation, e.Key, e.Err)
}

func (e *StoreError) Unwrap() error { return e.Err }

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
	// decision (one call per key), but only after all keys were persisted
	// successfully. Optional.
	OnAttempt func(r *http.Request, decision Decision, status int)

	// ErrorPolicy controls handling of Store errors. The zero value is
	// ErrorPolicyFailClosed, which responds with 503 and does not expose the
	// downstream response. ErrorPolicyFailOpen bypasses limiting on Get errors
	// and preserves the downstream response on Set errors.
	ErrorPolicy ErrorPolicy `cfg:"error_policy"`

	// OnError observes Store failures after operation and key context have
	// been attached. Optional. ErrorPolicy still determines request handling.
	OnError func(r *http.Request, err error)

	// ResponseBufferLimit bounds responses buffered by the default fail-closed
	// policy while it waits for post-handler persistence. Zero uses 1 MiB;
	// negative disables the limit. Streaming endpoints should use FailOpen or
	// place this middleware only around their small authentication response.
	ResponseBufferLimit int64 `cfg:"response_buffer_limit"`

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
//  3. Wait for the computed backoff (if > 0), cancellable by the request
//     context and without holding lock shards, then re-evaluate.
//  4. Invoke next with a buffering ResponseWriter.
//  5. If ShouldCount(r, status), append tummy.Now() to every key's bucket,
//     persist, commit the response, and call OnAttempt once per key.
//
// Concurrency: bucket reads/writes are atomic per key via an internal mutex
// pool. Two requests for the same key will serialize their read-update-write
// cycle; keys on different shards run in parallel.
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
	if cfg.ErrorPolicy > ErrorPolicyFailOpen {
		panic("ratelimit: invalid Config.ErrorPolicy")
	}
	if cfg.ResponseBufferLimit == 0 {
		cfg.ResponseBufferLimit = DefaultResponseBufferLimit
	}

	locks := newKeyLocks()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			keys := uniqueStrings(cfg.KeyFunc(r))
			if len(keys) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			ctx := r.Context()

			var delay time.Duration
			var appliedDelay time.Duration
			waitedAtCount := -1
			var holders heldLocks
			// Every normal branch unlocks as soon as possible. This defer is
			// the panic safety net: downstream handlers, callbacks and custom
			// stores are user code and must not permanently poison a shard.
			defer holders.unlock()
			for {
				// Keep the read/evaluate/handler/write cycle atomic for each
				// shard, but release locks while waiting for backoff.
				holders = lockAll(locks, keys)
				maxCount := 0
				for _, key := range keys {
					bucket, err := loadBucket(ctx, cfg.Store, key, cfg.Window)
					if err != nil {
						holders.unlock()
						handleStoreError(w, r, cfg, err, next)
						return
					}
					count := len(bucket.Attempts)

					if cfg.HardThreshold > 0 && count >= cfg.HardThreshold {
						retryAfter := computeRetryAfter(bucket, cfg.Window)
						if retryAfter < time.Second {
							retryAfter = time.Second
						}
						holders.unlock()
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

				delay = computeBackoff(cfg, maxCount)
				if delay <= 0 || waitedAtCount == maxCount {
					break
				}
				holders.unlock()
				if !waitContext(ctx, delay) {
					return
				}
				appliedDelay += delay
				waitedAtCount = maxCount
			}

			status := http.StatusOK
			var responseErr error
			flush := func() {}
			if cfg.ErrorPolicy == ErrorPolicyFailOpen {
				capture := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
				next.ServeHTTP(capture, r)
				status = capture.status
			} else {
				response := newResponseBuffer(cfg.ResponseBufferLimit)
				next.ServeHTTP(response, r)
				status = response.status
				responseErr = response.err
				flush = func() { response.flush(w) }
			}

			if !cfg.ShouldCount(r, status) {
				holders.unlock()
				if responseErr != nil {
					writeStoreUnavailable(w)
				} else {
					flush()
				}
				return
			}

			decisions, err := recordAttempts(ctx, cfg, keys, appliedDelay)
			holders.unlock()
			if err != nil {
				observeStoreError(r, cfg, err)
				if cfg.ErrorPolicy == ErrorPolicyFailClosed {
					writeStoreUnavailable(w)
				}
				return
			}
			if responseErr != nil {
				writeStoreUnavailable(w)
				return
			}
			flush()
			if cfg.OnAttempt != nil {
				for _, decision := range decisions {
					cfg.OnAttempt(r, decision, status)
				}
			}
		})
	}
}

func recordAttempts(ctx context.Context, cfg Config, keys []string, delay time.Duration) ([]Decision, error) {
	now := tummy.Now()
	decisions := make([]Decision, 0, len(keys))
	for _, key := range keys {
		bucket, err := loadBucket(ctx, cfg.Store, key, cfg.Window)
		if err != nil {
			return nil, err
		}
		bucket.Attempts = append(bucket.Attempts, now)
		if err := cfg.Store.Set(ctx, key, bucket); err != nil {
			return nil, newStoreError(StoreOperationSet, key, err)
		}
		decisions = append(decisions, Decision{
			Key:   key,
			Count: len(bucket.Attempts),
			Delay: delay,
		})
	}

	return decisions, nil
}

// loadBucket fetches the bucket for key, dropping entries older than window.
// Always returns a non-nil bucket (empty when nothing was stored or all
// entries were stale). The pruned bucket is NOT persisted here — it is
// persisted only when an attempt is actually counted, to avoid spurious
// writes on read-only checks.
func loadBucket(ctx context.Context, s Store, key string, window time.Duration) (*Bucket, error) {
	got, ok, err := s.Get(ctx, key)
	if err != nil {
		return nil, newStoreError(StoreOperationGet, key, err)
	}
	if !ok || got == nil {
		return &Bucket{}, nil
	}
	cutoff := tummy.Now().Add(-window)
	pruned := got.Attempts[:0:0]
	for _, t := range got.Attempts {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	return &Bucket{Attempts: pruned}, nil
}

func newStoreError(operation StoreOperation, key string, err error) error {
	return &StoreError{Operation: operation, Key: key, Err: err}
}

func handleStoreError(w http.ResponseWriter, r *http.Request, cfg Config, err error, next http.Handler) {
	observeStoreError(r, cfg, err)
	if cfg.ErrorPolicy == ErrorPolicyFailOpen {
		next.ServeHTTP(w, r)
		return
	}
	writeStoreUnavailable(w)
}

func observeStoreError(r *http.Request, cfg Config, err error) {
	if cfg.OnError != nil {
		cfg.OnError(r, err)
	}
}

func writeStoreUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"error":"rate_limit_unavailable","message":"rate limiter temporarily unavailable"}`))
}

func waitContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
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

// responseBuffer delays committing the downstream response until persistence
// succeeds, allowing the default policy to fail closed on Set errors.
type responseBuffer struct {
	header      http.Header
	body        bytes.Buffer
	status      int
	wroteHeader bool
	limit       int64
	err         error
}

func newResponseBuffer(limit int64) *responseBuffer {
	return &responseBuffer{header: make(http.Header), status: http.StatusOK, limit: limit}
}

func (s *responseBuffer) Header() http.Header { return s.header }

func (s *responseBuffer) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		return
	}
	s.status = code
	s.wroteHeader = true
}

func (s *responseBuffer) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		// Implicit 200 — Go's http package does this for us, but we
		// also need to record it.
		s.status = http.StatusOK
		s.wroteHeader = true
	}
	if s.limit >= 0 && int64(s.body.Len()+len(b)) > s.limit {
		s.err = ErrResponseTooLarge
		return 0, s.err
	}
	return s.body.Write(b)
}

// statusRecorder captures status without buffering for fail-open mode, where a
// persistence failure is not allowed to replace the downstream response.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		s.ResponseWriter.WriteHeader(code)
		return
	}
	s.status = code
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *responseBuffer) flush(w http.ResponseWriter) {
	for key, values := range s.header {
		w.Header()[key] = append([]string(nil), values...)
	}
	w.WriteHeader(s.status)
	_, _ = w.Write(s.body.Bytes())
}

// keyLocks retains entries only while a request holds or waits for that exact
// key. It avoids both the historical unbounded key map and hash-shard
// collisions that let an unrelated slow request block another key.
type keyLocks struct {
	mu      sync.Mutex
	entries map[string]*keyLock
}

type keyLock struct {
	mu   sync.Mutex
	refs int
}

func newKeyLocks() *keyLocks {
	return &keyLocks{entries: make(map[string]*keyLock)}
}

// lockAll acquires locks for the given keys in deterministic order to
// prevent deadlocks when two requests share overlapping key sets.
func lockAll(k *keyLocks, keys []string) heldLocks {
	keys = append([]string(nil), keys...)
	sortStrings(keys)
	if len(keys) > 1 {
		unique := keys[:1]
		for _, key := range keys[1:] {
			if key != unique[len(unique)-1] {
				unique = append(unique, key)
			}
		}
		keys = unique
	}

	held := heldLocks{pool: k, entries: make([]heldLock, 0, len(keys))}
	k.mu.Lock()
	for _, key := range keys {
		entry := k.entries[key]
		if entry == nil {
			entry = &keyLock{}
			k.entries[key] = entry
		}
		entry.refs++
		held.entries = append(held.entries, heldLock{key: key, lock: entry})
	}
	k.mu.Unlock()

	for i := range held.entries {
		held.entries[i].lock.mu.Lock()
	}
	return held
}

type heldLock struct {
	key  string
	lock *keyLock
}

type heldLocks struct {
	pool     *keyLocks
	entries  []heldLock
	unlocked bool
}

func (h *heldLocks) unlock() {
	if h.unlocked {
		return
	}
	h.unlocked = true

	// Unlock in reverse order for symmetry with acquisition.
	for i := len(h.entries) - 1; i >= 0; i-- {
		h.entries[i].lock.mu.Unlock()
	}

	if h.pool != nil {
		h.pool.mu.Lock()
		for _, held := range h.entries {
			held.lock.refs--
			if held.lock.refs == 0 {
				delete(h.pool.entries, held.key)
			}
		}
		h.pool.mu.Unlock()
	}
}

// sortStrings sorts a small slice in place without adding another dependency.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func uniqueStrings(keys []string) []string {
	seen := make(map[string]struct{}, len(keys))
	unique := make([]string, 0, len(keys))
	for _, key := range keys {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, key)
	}
	return unique
}
