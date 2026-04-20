package ratelimit

import (
	"context"
	"fmt"

	"github.com/rakunlabs/cache"
	"github.com/rakunlabs/cache/store/memory"
)

// DefaultMemoryCapacity is the LRU cap applied by NewMemoryStore when the
// caller passes a non-positive capacity. 10_000 entries is enough to hold
// independent buckets for a sustained attack while staying well under 5 MB.
const DefaultMemoryCapacity = 10_000

// NewMemoryStore returns an in-process Store backed by rakunlabs/cache's
// LRU memory backend. Capacity is the LRU cap; when reached, the least-
// recently-used bucket is dropped. Pass 0 (or negative) for the default.
//
// The cache is intentionally constructed with TTL=0 (no automatic
// expiration). The limiter prunes per-attempt timestamps inside each
// Bucket on every read, so authoritative window expiry is handled at the
// limiter level. A TTL here would add a second, coarser expiry that could
// drop an active bucket mid-window — silently weakening the defense.
// Memory pressure is bounded by the LRU cap instead.
//
// The returned Store is safe for concurrent use.
func NewMemoryStore(capacity int) (Store, error) {
	if capacity <= 0 {
		capacity = DefaultMemoryCapacity
	}
	c, err := cache.New(
		context.Background(),
		memory.Store[string, *Bucket],
		cache.WithStoreConfig(&memory.Config{
			TTL:      0, // invariant: limiter manages expiry, not the cache
			MaxItems: capacity,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("ratelimit: build memory store: %w", err)
	}
	return &cacheStore{c: c}, nil
}
