package ratelimit

import (
	"context"

	"github.com/rakunlabs/cache"
)

// NewCacheStore adapts an existing *cache.Cache into the ratelimit Store
// interface. This adapter is useful for legacy or best-effort deployments
// that already use a github.com/rakunlabs/cache backend.
//
// The caller is responsible for configuring the underlying cache with
// TTL=0: the limiter prunes per-attempt timestamps authoritatively on
// every read, and a TTL on the cache would risk dropping an active bucket
// mid-window, silently weakening the defense. Eviction under memory
// pressure (LRU cap or redis key expiry driven by external policy) resets the
// affected limit because a missing bucket looks like "no attempts yet". Size
// and configure the backend accordingly.
//
// NewCacheStore deliberately does not implement AtomicStore. Even with a
// redis-backed cache, separate Get and Set calls cannot provide an atomic
// multi-key read-modify-write, so this adapter does not guarantee cluster-wide
// enforcement. Distributed deployments should provide a backend-native
// AtomicStore and set Config.RequireAtomicStore.
//
// For the common case (single-node in-memory), prefer NewMemoryStore,
// which applies the right config for you.
func NewCacheStore(c *cache.Cache[string, *Bucket]) Store {
	return &cacheStore{c: c}
}

// cacheStore stays unexported so callers use NewCacheStore and encounter its
// non-atomic and TTL requirements in the API documentation.
type cacheStore struct {
	c *cache.Cache[string, *Bucket]
}

func (s *cacheStore) Get(ctx context.Context, key string) (*Bucket, bool, error) {
	v, ok, err := s.c.Get(ctx, key)
	if err != nil {
		return nil, false, err
	}
	if !ok || v == nil {
		return nil, false, nil
	}
	return v, true, nil
}

func (s *cacheStore) Set(ctx context.Context, key string, b *Bucket) error {
	return s.c.Set(ctx, key, b)
}
