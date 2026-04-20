package ratelimit

import "context"

// Store is the backing storage contract for the rate-limit middleware. It
// is intentionally minimal: the limiter only needs to fetch the current
// attempt bucket for a key and write an updated one back.
//
// Contract:
//   - Get returns (nil, false, nil) when the key is absent. Absence is not
//     an error; only IO/serialization failures are.
//   - Set replaces any existing value for key. There is no delete — stale
//     buckets are either pruned in-place by the limiter on next read or
//     evicted by the store under memory pressure.
//   - Implementations are allowed to evict keys at any time (LRU, capacity
//     limit, etc.). The limiter is correctness-preserving under eviction:
//     a missing key simply looks like "no attempts yet", which cannot
//     falsely block a legitimate user.
//
// Typical implementations:
//   - NewMemoryStore — in-process, LRU-bounded, for single-node pika
//   - NewCacheStore  — adapter for github.com/rakunlabs/cache (redis etc.)
//
// Custom implementations (mock, database-backed, etc.) are encouraged;
// the interface is small by design.
type Store interface {
	// Get returns the bucket for key. A non-existent key yields (nil, false, nil).
	Get(ctx context.Context, key string) (*Bucket, bool, error)

	// Set persists the bucket for key, replacing any prior value.
	Set(ctx context.Context, key string, b *Bucket) error
}
