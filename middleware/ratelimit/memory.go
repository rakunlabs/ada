package ratelimit

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rakunlabs/tummy"
)

// DefaultMemoryCapacity is the LRU cap applied by NewMemoryStore when the
// caller passes a non-positive capacity. 10_000 entries is enough to hold
// independent buckets for a sustained attack while staying well under 5 MB.
const DefaultMemoryCapacity = 10_000

// NewMemoryStore returns an in-process Store that also implements AtomicStore.
// Capacity is the LRU cap; when reached, the least-recently-used bucket without
// an active reservation is dropped. An update fails without changing state if
// every possible eviction would discard an in-flight reservation. Pass 0 (or
// negative) for the default.
//
// The store has no automatic TTL. The limiter prunes timestamps inside each
// Bucket, so a second, coarser expiry could drop active state mid-window and
// silently weaken the defense. Memory pressure is bounded by the LRU cap.
//
// The returned Store is safe for concurrent use. Its transactions coordinate
// every Middleware instance that shares this value, but as an in-process store
// it cannot coordinate separate processes.
func NewMemoryStore(capacity int) (Store, error) {
	if capacity <= 0 {
		capacity = DefaultMemoryCapacity
	}
	return &memoryStore{
		capacity: capacity,
		entries:  make(map[string]*list.Element),
		lru:      list.New(),
	}, nil
}

type memoryStore struct {
	mu       sync.Mutex
	capacity int
	entries  map[string]*list.Element
	lru      *list.List
}

type memoryEntry struct {
	key    string
	bucket *Bucket
}

func (s *memoryStore) Get(_ context.Context, key string) (*Bucket, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	element, ok := s.entries[key]
	if !ok {
		return nil, false, nil
	}
	s.lru.MoveToFront(element)
	return cloneBucket(element.Value.(*memoryEntry).bucket), true, nil
}

func (s *memoryStore) Set(_ context.Context, key string, bucket *Bucket) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if bucket == nil {
		s.deleteLocked(key)
		return nil
	}
	if _, ok := s.entries[key]; !ok && len(s.entries) >= s.capacity {
		oldest := s.oldestEvictableLocked(tummy.Now())
		if oldest == nil {
			return fmt.Errorf("ratelimit: memory capacity %d is occupied by active reservations", s.capacity)
		}
		s.deleteLocked(oldest.Value.(*memoryEntry).key)
	}
	s.putLocked(key, cloneBucket(bucket))
	return nil
}

func (s *memoryStore) Transaction(ctx context.Context, keys []string, fn func(map[string]*Bucket) error) error {
	if fn == nil {
		return fmt.Errorf("ratelimit: nil atomic transaction callback")
	}
	keys = uniqueStrings(keys)
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	buckets := make(map[string]*Bucket, len(keys))
	requested := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		requested[key] = struct{}{}
		if element, ok := s.entries[key]; ok {
			buckets[key] = cloneBucket(element.Value.(*memoryEntry).bucket)
		} else {
			buckets[key] = nil
		}
	}

	if err := fn(buckets); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	for key := range buckets {
		if _, ok := requested[key]; !ok {
			return fmt.Errorf("ratelimit: atomic transaction added unrequested key %q", key)
		}
	}
	desired := make(map[string]*Bucket, len(keys))
	for _, key := range keys {
		if bucket := buckets[key]; bucket != nil {
			desired[key] = cloneBucket(bucket)
		}
	}
	now := tummy.Now()
	pinned := 0
	unrequested := 0
	for key, element := range s.entries {
		if _, ok := requested[key]; ok {
			continue
		}
		unrequested++
		if bucketHasActiveReservation(element.Value.(*memoryEntry).bucket, now) {
			pinned++
		}
	}
	if len(desired)+pinned > s.capacity {
		return fmt.Errorf("ratelimit: atomic transaction needs %d buckets plus %d active reservations, memory capacity is %d", len(desired), pinned, s.capacity)
	}
	neededEvictions := len(desired) + unrequested - s.capacity
	if neededEvictions < 0 {
		neededEvictions = 0
	}
	evictions := make([]string, 0, neededEvictions)
	for element := s.lru.Back(); element != nil && len(evictions) < neededEvictions; element = element.Prev() {
		entry := element.Value.(*memoryEntry)
		if _, ok := requested[entry.key]; ok || bucketHasActiveReservation(entry.bucket, now) {
			continue
		}
		evictions = append(evictions, entry.key)
	}

	// No operation below can fail, and the mutex prevents observers from
	// seeing the intermediate representation of this atomic commit.
	for _, key := range keys {
		if _, ok := desired[key]; !ok {
			s.deleteLocked(key)
		}
	}
	for _, key := range evictions {
		s.deleteLocked(key)
	}
	for _, key := range keys {
		if bucket, ok := desired[key]; ok {
			s.putLocked(key, bucket)
		}
	}
	return nil
}

func (s *memoryStore) putLocked(key string, bucket *Bucket) {
	if element, ok := s.entries[key]; ok {
		element.Value.(*memoryEntry).bucket = bucket
		s.lru.MoveToFront(element)
		return
	}

	element := s.lru.PushFront(&memoryEntry{key: key, bucket: bucket})
	s.entries[key] = element
}

func (s *memoryStore) deleteLocked(key string) {
	element, ok := s.entries[key]
	if !ok {
		return
	}
	delete(s.entries, key)
	s.lru.Remove(element)
}

func (s *memoryStore) oldestEvictableLocked(now time.Time) *list.Element {
	for element := s.lru.Back(); element != nil; element = element.Prev() {
		entry := element.Value.(*memoryEntry)
		if bucketHasActiveReservation(entry.bucket, now) {
			continue
		}
		return element
	}
	return nil
}

func bucketHasActiveReservation(bucket *Bucket, now time.Time) bool {
	for id := range bucket.Reservations {
		leaseUntil, hasLease := bucket.ReservationLeases[id]
		if !hasLease || leaseUntil.After(now) {
			return true
		}
	}
	return false
}

var _ AtomicStore = (*memoryStore)(nil)
