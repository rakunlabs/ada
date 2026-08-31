// Package ratelimit provides a generic, sliding-window HTTP rate-limit
// middleware suitable for guarding sensitive endpoints (login, signup,
// password reset, etc.).
//
// The middleware is storage-agnostic via Store and AtomicStore. Use
// NewMemoryStore for atomic coordination within one process. Distributed
// enforcement requires a backend-native AtomicStore; NewCacheStore is a
// legacy Get/Set adapter and cannot guarantee cluster-wide correctness.
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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
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

const (
	// DefaultResponseBufferLimit bounds fail-closed response buffering to 1 MiB.
	DefaultResponseBufferLimit int64 = 1 << 20
	// DefaultStoreOperationTimeout bounds each atomic store transaction.
	DefaultStoreOperationTimeout time.Duration = 5 * time.Second
)

var (
	ErrResponseTooLarge                 = errors.New("ratelimit: downstream response exceeds buffer limit")
	errReservationExpired               = errors.New("ratelimit: reservation lease expired")
	errReservationRenewalUnconfirmed    = errors.New("ratelimit: reservation lease renewal could not be confirmed")
	errReservationRenewalWorkerPanicked = errors.New("ratelimit: reservation lease renewal worker panicked")
)

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
	StoreOperationGet         StoreOperation = "get"
	StoreOperationSet         StoreOperation = "set"
	StoreOperationTransaction StoreOperation = "transaction"
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

// Bucket holds the per-key attempt history for one window. The package stores
// instances in the configured Store. Exported so callers can inspect state in
// tests; instances must be treated as immutable outside of Store operations.
type Bucket struct {
	// Attempts is the timestamps of counted attempts within the window,
	// oldest first. Stale entries (older than Window) are pruned on every
	// read.
	Attempts []time.Time

	// Reservations holds the original admission time of each in-flight request
	// by unique ID. AtomicStore-backed middleware reserves every key before
	// invoking the handler, then replaces its reservation with an Attempt or
	// removes it.
	Reservations map[string]time.Time

	// ReservationLeases holds the expiry of each reservation. Leases are
	// renewed while a request is in flight so a handler that outlives Window
	// remains fenced. If its process exits, the lease bounds stale cleanup.
	ReservationLeases map[string]time.Time
}

// Config controls the middleware. Window, KeyFunc, ShouldCount and Store are
// required; zero disables either threshold.
type Config struct {
	// Window is the sliding-window length. Attempts older than this are
	// dropped from the bucket on every observation.
	Window time.Duration `cfg:"window"`

	// SoftThreshold is the count at or above which the middleware sleeps
	// before invoking the handler. Set to 0 to disable backoff. When both
	// thresholds are enabled, SoftThreshold must be less than HardThreshold.
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
	// downstream response. ErrorPolicyFailOpen bypasses limiting on pre-handler
	// store errors and preserves the downstream response on post-handler errors.
	ErrorPolicy ErrorPolicy `cfg:"error_policy"`

	// OnError observes Store failures after operation and key context have
	// been attached. Optional. ErrorPolicy still determines request handling.
	OnError func(r *http.Request, err error)

	// ResponseBufferLimit bounds responses buffered by the default fail-closed
	// policy while it waits for post-handler persistence. Zero uses 1 MiB;
	// negative disables the limit. Streaming endpoints should use FailOpen or
	// place this middleware only around their small authentication response.
	ResponseBufferLimit int64 `cfg:"response_buffer_limit"`

	// StoreOperationTimeout bounds each AtomicStore transaction. Initial
	// reservations preserve request cancellation; finalization, lease renewal,
	// and rollback ignore it so accounting and cleanup are still attempted.
	// Zero uses DefaultStoreOperationTimeout; negative is invalid.
	StoreOperationTimeout time.Duration `cfg:"store_operation_timeout"`

	// RequireAtomicStore rejects configuration at construction time unless
	// Store implements AtomicStore. Enable this for distributed or
	// security-sensitive deployments that must not fall back to process-local
	// coordination.
	RequireAtomicStore bool `cfg:"require_atomic_store"`

	// Store is the backing storage for attempt buckets. NewMemoryStore also
	// implements AtomicStore for coordination within one process. A plain Store,
	// including NewCacheStore, is protected only by locks local to a single
	// Middleware value and cannot guarantee distributed correctness. Required.
	Store Store
}

// Middleware returns the http middleware enforcing cfg. With AtomicStore, the
// per-request flow is:
//
//  1. KeyFunc(r) → if empty, pass through unmodified.
//  2. Atomically prune, evaluate and provisionally reserve every key under a
//     renewable, crash-bounded lease.
//  3. Wait for the computed backoff (if > 0), cancellable by the request.
//  4. Invoke next with a buffering ResponseWriter under fail-closed policy.
//  5. Atomically replace all reservations with attempts when ShouldCount is
//     true, or remove all reservations otherwise.
//
// A legacy Store follows the same observable policy but serializes the handler
// and per-key Get/Set operations with locks owned by this Middleware value.
// Those locks cannot coordinate separate Middleware values or processes, and
// legacy multi-key writes can partially persist on a Store error.
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
	if cfg.Window <= 0 {
		panic("ratelimit: Config.Window must be greater than zero")
	}
	if cfg.SoftThreshold < 0 {
		panic("ratelimit: Config.SoftThreshold must not be negative")
	}
	if cfg.HardThreshold < 0 {
		panic("ratelimit: Config.HardThreshold must not be negative")
	}
	if cfg.SoftThreshold > 0 && cfg.HardThreshold > 0 && cfg.SoftThreshold >= cfg.HardThreshold {
		panic("ratelimit: Config.SoftThreshold must be less than Config.HardThreshold")
	}
	if cfg.BackoffBase < 0 {
		panic("ratelimit: Config.BackoffBase must not be negative")
	}
	if cfg.BackoffMax < 0 {
		panic("ratelimit: Config.BackoffMax must not be negative")
	}
	if cfg.StoreOperationTimeout < 0 {
		panic("ratelimit: Config.StoreOperationTimeout must not be negative")
	}
	if cfg.ErrorPolicy > ErrorPolicyFailOpen {
		panic("ratelimit: invalid Config.ErrorPolicy")
	}
	atomicStore, hasAtomicStore := cfg.Store.(AtomicStore)
	if cfg.RequireAtomicStore && !hasAtomicStore {
		panic("ratelimit: Config.RequireAtomicStore requires Config.Store to implement AtomicStore")
	}
	if cfg.ResponseBufferLimit == 0 {
		cfg.ResponseBufferLimit = DefaultResponseBufferLimit
	}
	if cfg.StoreOperationTimeout == 0 {
		cfg.StoreOperationTimeout = DefaultStoreOperationTimeout
	}

	locks := newKeyLocks()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			keys := uniqueStrings(cfg.KeyFunc(r))
			if len(keys) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			if hasAtomicStore {
				serveAtomic(w, r, next, cfg, atomicStore, keys)
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
						w.Header().Set("Retry-After", formatRetryAfter(retryAfter))
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

type reservationResult struct {
	delay      time.Duration
	rejected   bool
	key        string
	retryAfter time.Duration
	leaseUntil time.Time
}

func serveAtomic(w http.ResponseWriter, r *http.Request, next http.Handler, cfg Config, store AtomicStore, keys []string) {
	reservationID, err := newReservationID()
	if err != nil {
		handleStoreError(w, r, cfg, fmt.Errorf("ratelimit: create reservation ID: %w", err), next)
		return
	}

	reserveCtx, cancel := initialAtomicStoreOperationContext(r.Context(), cfg.StoreOperationTimeout)
	result, err := reserveAtomic(reserveCtx, store, keys, reservationID, cfg)
	cancel()
	if err != nil {
		handleStoreError(w, r, cfg, err, next)
		return
	}
	if result.rejected {
		if cfg.OnReject != nil {
			cfg.OnReject(r, result.key, ReasonHardThreshold, result.retryAfter)
		}
		w.Header().Set("Retry-After", formatRetryAfter(result.retryAfter))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate_limited","message":"too many attempts; try again later"}`))
		return
	}

	reserved := true
	lease := startReservationLease(r, cfg, store, keys, reservationID, result.leaseUntil)
	defer func() {
		_ = lease.stop()
		if !reserved {
			return
		}
		cleanupCtx, cancel := atomicStoreOperationContext(r.Context(), cfg.StoreOperationTimeout)
		defer cancel()
		if err := rollbackAtomic(cleanupCtx, store, keys, reservationID, cfg.Window); err != nil {
			observeStoreError(r, cfg, err)
		}
	}()
	handleLeaseFailure := func() {
		cleanupCtx, cancel := atomicStoreOperationContext(r.Context(), cfg.StoreOperationTimeout)
		err := rollbackAtomic(cleanupCtx, store, keys, reservationID, cfg.Window)
		cancel()
		if err == nil {
			reserved = false
		} else {
			observeStoreError(r, cfg, err)
		}
		handleAtomicLeaseFailureBeforeHandler(w, r, next, cfg)
	}

	if result.delay > 0 {
		waited, leaseErr := lease.waitBackoff(r.Context(), result.delay)
		if leaseErr != nil {
			handleLeaseFailure()
			return
		}
		if !waited {
			return
		}
	}
	if _, failed := lease.failure(); failed {
		handleLeaseFailure()
		return
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
	if leaseErr := lease.stop(); leaseErr != nil {
		// Fail-open responses are written directly and must be preserved. A
		// fail-closed response is still buffered and must never be released
		// after the reservation fence becomes uncertain.
		if cfg.ErrorPolicy == ErrorPolicyFailClosed {
			writeStoreUnavailable(w)
		}
		return
	}

	if !cfg.ShouldCount(r, status) {
		cleanupCtx, cancel := atomicStoreOperationContext(r.Context(), cfg.StoreOperationTimeout)
		err := rollbackAtomic(cleanupCtx, store, keys, reservationID, cfg.Window)
		cancel()
		if err == nil {
			reserved = false
		} else {
			observeStoreError(r, cfg, err)
			if cfg.ErrorPolicy == ErrorPolicyFailClosed {
				writeStoreUnavailable(w)
			}
			return
		}
		if responseErr != nil {
			writeStoreUnavailable(w)
		} else {
			flush()
		}
		return
	}

	finalizeCtx, cancel := atomicStoreOperationContext(r.Context(), cfg.StoreOperationTimeout)
	decisions, err := finalizeAtomic(finalizeCtx, store, keys, reservationID, cfg, result.delay)
	cancel()
	if err != nil {
		observeStoreError(r, cfg, err)
		if cfg.ErrorPolicy == ErrorPolicyFailClosed {
			writeStoreUnavailable(w)
		}
		return
	}
	reserved = false
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
}

func handleAtomicLeaseFailureBeforeHandler(w http.ResponseWriter, r *http.Request, next http.Handler, cfg Config) {
	if r.Context().Err() != nil {
		return
	}
	if cfg.ErrorPolicy == ErrorPolicyFailOpen {
		next.ServeHTTP(w, r)
		return
	}
	writeStoreUnavailable(w)
}

func initialAtomicStoreOperationContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

func atomicStoreOperationContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), timeout)
}

type reservationLeaseGuard struct {
	stopOnce    sync.Once
	cancel      context.CancelFunc
	done        chan struct{}
	terminalErr error
}

func startReservationLease(r *http.Request, cfg Config, store AtomicStore, keys []string, reservationID string, leaseUntil time.Time) *reservationLeaseGuard {
	workerCtx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
	guard := &reservationLeaseGuard{
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				err := newTransactionStoreError(keys, fmt.Errorf("%w: %v", errReservationRenewalWorkerPanicked, recovered))
				if observerErr := observeReservationRenewalError(r, cfg, err); observerErr != nil {
					err = errors.Join(err, observerErr)
				}
				guard.terminalErr = err
			}
			close(guard.done)
		}()
		guard.terminalErr = runReservationLease(workerCtx, r, cfg, store, keys, reservationID, leaseUntil)
	}()
	return guard
}

func (g *reservationLeaseGuard) stop() error {
	g.stopOnce.Do(g.cancel)
	<-g.done
	return g.terminalErr
}

func (g *reservationLeaseGuard) failure() (error, bool) {
	select {
	case <-g.done:
		return g.terminalErr, g.terminalErr != nil
	default:
		return nil, false
	}
}

func (g *reservationLeaseGuard) waitBackoff(ctx context.Context, delay time.Duration) (bool, error) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true, nil
	case <-ctx.Done():
		return false, nil
	case <-g.done:
		if g.terminalErr == nil {
			return false, errReservationRenewalUnconfirmed
		}
		return false, g.terminalErr
	}
}

func runReservationLease(ctx context.Context, r *http.Request, cfg Config, store AtomicStore, keys []string, reservationID string, leaseUntil time.Time) error {
	interval := reservationLeaseDuration(cfg) / 2
	if interval <= 0 {
		interval = time.Nanosecond
	}

	for {
		if !waitContext(ctx, interval) {
			return nil
		}

		var lastErr error
		for failures := 0; ; failures++ {
			remaining := leaseUntil.Sub(tummy.Now())
			if remaining <= 0 {
				return finishReservationLeaseDeadlineFailure(r, cfg, leaseUntil, lastErr)
			}

			operationTimeout := cfg.StoreOperationTimeout
			if remaining < operationTimeout {
				operationTimeout = remaining
			}
			renewCtx, cancel := context.WithTimeout(ctx, operationTimeout)
			renewedUntil, err := renewReservationAtomic(renewCtx, store, keys, reservationID, cfg)
			cancel()
			if err == nil {
				leaseUntil = renewedUntil
				break
			}
			if ctx.Err() != nil {
				return nil
			}
			if observerErr := observeReservationRenewalError(r, cfg, err); observerErr != nil {
				return errors.Join(err, observerErr)
			}
			if errors.Is(err, errReservationExpired) || errors.Is(err, errReservationRenewalWorkerPanicked) {
				return err
			}

			lastErr = err
			remaining = leaseUntil.Sub(tummy.Now())
			if remaining <= 0 {
				return finishReservationLeaseDeadlineFailure(r, cfg, leaseUntil, lastErr)
			}
			if !waitContext(ctx, reservationLeaseRetryBackoff(failures, remaining)) {
				return nil
			}
		}
	}
}

func finishReservationLeaseDeadlineFailure(r *http.Request, cfg Config, leaseUntil time.Time, cause error) error {
	err := fmt.Errorf("%w before %s", errReservationRenewalUnconfirmed, leaseUntil.Format(time.RFC3339Nano))
	if cause != nil {
		err = errors.Join(err, cause)
	}
	if observerErr := observeReservationRenewalError(r, cfg, err); observerErr != nil {
		return errors.Join(err, observerErr)
	}
	return err
}

func observeReservationRenewalError(r *http.Request, cfg Config, storeErr error) (panicErr error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			panicErr = fmt.Errorf("%w in Config.OnError: %v", errReservationRenewalWorkerPanicked, recovered)
		}
	}()
	observeStoreError(r, cfg, storeErr)
	return nil
}

func reservationLeaseRetryBackoff(failures int, remaining time.Duration) time.Duration {
	const maxBackoff = 100 * time.Millisecond

	backoff := time.Millisecond
	if failures < 63 && backoff <= time.Duration(1<<63-1)>>uint(failures) {
		backoff <<= uint(failures)
	} else {
		backoff = maxBackoff
	}
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	if backoff >= remaining {
		backoff = remaining / 2
		if backoff <= 0 {
			backoff = time.Nanosecond
		}
	}
	return backoff
}

func reservationLeaseDuration(cfg Config) time.Duration {
	operationGrace := saturatedDurationMultiply(cfg.StoreOperationTimeout, 2)
	grace := cfg.Window
	if operationGrace > grace {
		grace = operationGrace
	}
	return saturatedDurationAdd(cfg.Window, grace)
}

func saturatedDurationMultiply(value time.Duration, multiplier int64) time.Duration {
	const maxDuration = time.Duration(1<<63 - 1)
	if value > maxDuration/time.Duration(multiplier) {
		return maxDuration
	}
	return value * time.Duration(multiplier)
}

func saturatedDurationAdd(left, right time.Duration) time.Duration {
	const maxDuration = time.Duration(1<<63 - 1)
	if left > maxDuration-right {
		return maxDuration
	}
	return left + right
}

func reserveAtomic(ctx context.Context, store AtomicStore, keys []string, reservationID string, cfg Config) (reservationResult, error) {
	var result reservationResult
	err := store.Transaction(ctx, keys, func(buckets map[string]*Bucket) error {
		// Optimistic stores may retry fn, so discard the previous evaluation.
		result = reservationResult{}
		now := tummy.Now()
		leaseUntil := now.Add(reservationLeaseDuration(cfg))
		maxCount := 0
		for _, key := range keys {
			bucket := pruneBucket(buckets[key], cfg.Window, now)
			buckets[key] = bucket
			count := len(bucket.Attempts) + len(bucket.Reservations)
			if cfg.HardThreshold > 0 && count >= cfg.HardThreshold {
				retryAfter := computeRetryAfterAt(bucket, cfg.Window, now)
				if retryAfter < time.Second {
					retryAfter = time.Second
				}
				if !result.rejected {
					result.rejected = true
					result.key = key
				}
				if retryAfter > result.retryAfter {
					result.retryAfter = retryAfter
				}
			}
			if count > maxCount {
				maxCount = count
			}
		}

		if result.rejected {
			for _, key := range keys {
				if bucketEmpty(buckets[key]) {
					buckets[key] = nil
				}
			}
			return nil
		}

		result.delay = computeBackoff(cfg, maxCount)
		result.leaseUntil = leaseUntil
		for _, key := range keys {
			bucket := buckets[key]
			if bucket.Reservations == nil {
				bucket.Reservations = make(map[string]time.Time)
			}
			if bucket.ReservationLeases == nil {
				bucket.ReservationLeases = make(map[string]time.Time)
			}
			bucket.Reservations[reservationID] = now
			bucket.ReservationLeases[reservationID] = leaseUntil
		}
		return nil
	})
	if err != nil {
		return reservationResult{}, newTransactionStoreError(keys, err)
	}
	return result, nil
}

func renewReservationAtomic(ctx context.Context, store AtomicStore, keys []string, reservationID string, cfg Config) (leaseUntil time.Time, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			leaseUntil = time.Time{}
			err = newTransactionStoreError(keys, fmt.Errorf("%w in AtomicStore.Transaction: %v", errReservationRenewalWorkerPanicked, recovered))
		}
	}()

	err = store.Transaction(ctx, keys, func(buckets map[string]*Bucket) error {
		now := tummy.Now()
		leaseUntil = now.Add(reservationLeaseDuration(cfg))
		for _, key := range keys {
			bucket := pruneBucket(buckets[key], cfg.Window, now)
			if _, ok := bucket.Reservations[reservationID]; !ok {
				return fmt.Errorf("%w for key %q", errReservationExpired, key)
			}
			if bucket.ReservationLeases == nil {
				bucket.ReservationLeases = make(map[string]time.Time)
			}
			bucket.ReservationLeases[reservationID] = leaseUntil
			buckets[key] = bucket
		}
		return nil
	})
	if err != nil {
		return time.Time{}, newTransactionStoreError(keys, err)
	}
	return leaseUntil, nil
}

func finalizeAtomic(ctx context.Context, store AtomicStore, keys []string, reservationID string, cfg Config, delay time.Duration) ([]Decision, error) {
	var decisions []Decision
	err := store.Transaction(ctx, keys, func(buckets map[string]*Bucket) error {
		decisions = make([]Decision, 0, len(keys))
		now := tummy.Now()
		for _, key := range keys {
			bucket := pruneBucket(buckets[key], cfg.Window, now)
			reservedAt, ok := bucket.Reservations[reservationID]
			if !ok {
				return fmt.Errorf("%w for key %q", errReservationExpired, key)
			}
			delete(bucket.Reservations, reservationID)
			delete(bucket.ReservationLeases, reservationID)
			if reservedAt.After(now.Add(-cfg.Window)) {
				bucket.Attempts = append(bucket.Attempts, reservedAt)
			}
			sort.Slice(bucket.Attempts, func(i, j int) bool {
				return bucket.Attempts[i].Before(bucket.Attempts[j])
			})
			if bucketEmpty(bucket) {
				buckets[key] = nil
			} else {
				buckets[key] = bucket
			}
			decisions = append(decisions, Decision{
				Key:   key,
				Count: len(bucket.Attempts),
				Delay: delay,
			})
		}
		return nil
	})
	if err != nil {
		return nil, newTransactionStoreError(keys, err)
	}
	return decisions, nil
}

func rollbackAtomic(ctx context.Context, store AtomicStore, keys []string, reservationID string, window time.Duration) error {
	err := store.Transaction(ctx, keys, func(buckets map[string]*Bucket) error {
		now := tummy.Now()
		for _, key := range keys {
			bucket := pruneBucket(buckets[key], window, now)
			delete(bucket.Reservations, reservationID)
			delete(bucket.ReservationLeases, reservationID)
			if bucketEmpty(bucket) {
				buckets[key] = nil
			} else {
				buckets[key] = bucket
			}
		}
		return nil
	})
	if err != nil {
		return newTransactionStoreError(keys, err)
	}
	return nil
}

func newReservationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
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
	return pruneBucket(got, window, tummy.Now()), nil
}

func pruneBucket(bucket *Bucket, window time.Duration, now time.Time) *Bucket {
	if bucket == nil {
		return &Bucket{}
	}
	cutoff := now.Add(-window)
	pruned := &Bucket{Attempts: make([]time.Time, 0, len(bucket.Attempts))}
	for _, attempt := range bucket.Attempts {
		if attempt.After(cutoff) {
			pruned.Attempts = append(pruned.Attempts, attempt)
		}
	}
	for id, reservedAt := range bucket.Reservations {
		if reservationExpiry(bucket, id, reservedAt, window).After(now) {
			if pruned.Reservations == nil {
				pruned.Reservations = make(map[string]time.Time)
				pruned.ReservationLeases = make(map[string]time.Time)
			}
			pruned.Reservations[id] = reservedAt
			if leaseUntil, ok := bucket.ReservationLeases[id]; ok {
				pruned.ReservationLeases[id] = leaseUntil
			}
		}
	}
	return pruned
}

func reservationExpiry(bucket *Bucket, id string, reservedAt time.Time, window time.Duration) time.Time {
	if leaseUntil, ok := bucket.ReservationLeases[id]; ok {
		return leaseUntil
	}
	// Buckets persisted before leases were introduced keep their original
	// window-bounded cleanup behavior.
	return reservedAt.Add(window)
}

func cloneBucket(bucket *Bucket) *Bucket {
	if bucket == nil {
		return nil
	}
	cloned := &Bucket{Attempts: append([]time.Time(nil), bucket.Attempts...)}
	if len(bucket.Reservations) > 0 {
		cloned.Reservations = make(map[string]time.Time, len(bucket.Reservations))
		for id, reservedAt := range bucket.Reservations {
			cloned.Reservations[id] = reservedAt
		}
	}
	if len(bucket.ReservationLeases) > 0 {
		cloned.ReservationLeases = make(map[string]time.Time, len(bucket.ReservationLeases))
		for id, leaseUntil := range bucket.ReservationLeases {
			cloned.ReservationLeases[id] = leaseUntil
		}
	}
	return cloned
}

func bucketEmpty(bucket *Bucket) bool {
	return bucket == nil || len(bucket.Attempts) == 0 && len(bucket.Reservations) == 0
}

func newStoreError(operation StoreOperation, key string, err error) error {
	return &StoreError{Operation: operation, Key: key, Err: err}
}

func newTransactionStoreError(keys []string, err error) error {
	return &StoreError{
		Operation: StoreOperationTransaction,
		Key:       fmt.Sprint(keys),
		Err:       err,
	}
}

func handleStoreError(w http.ResponseWriter, r *http.Request, cfg Config, err error, next http.Handler) {
	observeStoreError(r, cfg, err)
	if r.Context().Err() != nil {
		return
	}
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

func formatRetryAfter(delay time.Duration) string {
	seconds := delay / time.Second
	if delay%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	return strconv.FormatInt(int64(seconds), 10)
}

// computeRetryAfter returns the time until the earliest attempt or reservation
// expires, which is when the requester would be unblocked.
func computeRetryAfter(b *Bucket, window time.Duration) time.Duration {
	return computeRetryAfterAt(b, window, tummy.Now())
}

func computeRetryAfterAt(b *Bucket, window time.Duration, now time.Time) time.Duration {
	if bucketEmpty(b) {
		return 0
	}
	var earliestExpiry time.Time
	for _, attempt := range b.Attempts {
		expiresAt := attempt.Add(window)
		if earliestExpiry.IsZero() || expiresAt.Before(earliestExpiry) {
			earliestExpiry = expiresAt
		}
	}
	for id, reservedAt := range b.Reservations {
		expiresAt := reservationExpiry(b, id, reservedAt, window)
		if earliestExpiry.IsZero() || expiresAt.Before(earliestExpiry) {
			earliestExpiry = expiresAt
		}
	}
	until := earliestExpiry.Sub(now)
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
	const maxDuration = time.Duration(1<<63 - 1)
	delay := maxDuration
	if shift < 63 && cfg.BackoffBase <= maxDuration>>uint(shift) {
		delay = cfg.BackoffBase << uint(shift)
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
