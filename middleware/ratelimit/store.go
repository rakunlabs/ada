package ratelimit

import "context"

// Store is the legacy backing storage contract for the rate-limit middleware.
// It is intentionally minimal: the limiter only needs to fetch the current
// attempt bucket for a key and write an updated one back.
//
// Contract:
//   - Get returns (nil, false, nil) when the key is absent. Absence is not
//     an error; only IO/serialization failures are.
//   - Set replaces any existing value for key. There is no delete — stale
//     buckets are either pruned in-place by the limiter on next read or
//     evicted by the store under memory pressure.
//   - Implementations may evict keys under a documented capacity policy. A
//     missing key looks like "no attempts yet", so eviction weakens enforcement
//     rather than falsely blocking a legitimate user. Security-sensitive
//     deployments must size or configure their store to retain active state.
//
// Typical implementations:
//   - NewMemoryStore — in-process, LRU-bounded, for single-node pika
//   - NewCacheStore  — legacy adapter for github.com/rakunlabs/cache
//
// Custom implementations (mock, database-backed, etc.) are encouraged;
// the interface is small by design.
//
// Get followed by Set is not an atomic read-modify-write operation. The
// middleware protects this legacy path with locks local to one Middleware
// instance, so Store alone cannot enforce a shared limit across middleware
// instances or processes. Implement AtomicStore for that guarantee.
type Store interface {
	// Get returns the bucket for key. A non-existent key yields (nil, false, nil).
	Get(ctx context.Context, key string) (*Bucket, bool, error)

	// Set persists the bucket for key, replacing any prior value.
	Set(ctx context.Context, key string, b *Bucket) error
}

// AtomicStore adds a serializable, multi-key transaction to Store. Middleware
// uses this contract when available to reserve capacity before invoking the
// downstream handler, preventing concurrent middleware instances or processes
// from passing the same pre-check.
//
// Transaction must satisfy all of the following:
//   - It reads and updates every distinct requested key as one indivisible
//     operation, serialized against every overlapping Transaction call made
//     through any client or process.
//   - fn receives a detached snapshot containing every requested key. A nil
//     bucket means the key is absent. On return, a nil bucket (or a deleted map
//     entry) means the key must be deleted. fn must not add unrequested keys.
//   - If fn returns nil, all requested updates become visible together. If fn
//     or Transaction returns an error, none of them become visible. Partial
//     persistence is never permitted.
//   - fn may be retried by optimistic implementations and therefore must not
//     perform external side effects. It must not call methods on the same
//     store.
//
// Implementations backed only by independent Get and Set operations do not
// satisfy this contract, even if those individual operations are concurrency
// safe.
type AtomicStore interface {
	Store

	Transaction(ctx context.Context, keys []string, fn func(buckets map[string]*Bucket) error) error
}
