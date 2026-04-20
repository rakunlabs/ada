package ratelimit

import (
	"context"

	"github.com/rakunlabs/cache"
)

// NewCacheStore adapts an existing *cache.Cache into the ratelimit Store
// interface. Use this when you need a non-default backend (for example
// github.com/rakunlabs/cache/store/redis for cross-process limits across
// several pika instances).
//
// The caller is responsible for configuring the underlying cache with
// TTL=0: the limiter prunes per-attempt timestamps authoritatively on
// every read, and a TTL on the cache would risk dropping an active bucket
// mid-window, silently weakening the defense. Eviction under memory
// pressure (LRU cap or redis key expiry driven by external policy) is
// fine — a missing bucket just looks like "no attempts yet" to the
// limiter, which is strictly safer than falsely blocking a user.
//
// For the common case (single-node in-memory), prefer NewMemoryStore,
// which applies the right config for you.
func NewCacheStore(c *cache.Cache[string, *Bucket]) Store {
	return &cacheStore{c: c}
}

// cacheStore is the shared adapter used by both NewMemoryStore and
// NewCacheStore. Kept unexported so callers go through the named
// constructors and can't accidentally bypass the TTL invariant
// documented on each.
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
