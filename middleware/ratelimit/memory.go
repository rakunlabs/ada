package ratelimit

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rakunlabs/tummy"
)

// DefaultMemoryCapacity is the cap applied by NewMemoryStore when the caller
// passes a non-positive capacity. It bounds bucket keys, not the attempt and
// reservation records retained inside each bucket.
const DefaultMemoryCapacity = 10_000

// NewMemoryStore returns an in-process Store that also implements AtomicStore.
// Pass 0 (or negative) for DefaultMemoryCapacity.
//
// # Capacity is enforced, never bypassed
//
// Capacity is a hard bound on the number of buckets, but it is deliberately
// not a plain LRU. Dropping a bucket that is still enforcing a limit is a
// rate-limit bypass: the next request for that key sees "no attempts yet", so
// anyone who controls the key input can reset their own counter by pushing
// enough unrelated keys through the store. Reclamation is therefore restricted
// to buckets that can no longer change a decision:
//
//  1. Empty buckets and buckets holding only expired reservation leases.
//  2. Buckets whose every attempt is older than the observed limiter Window,
//     which the limiter would prune to nothing on its next read anyway.
//     Middleware supplies that window through WindowObserver; a store used
//     without a Middleware never learns it and skips this class.
//  3. Nothing else. A bucket with an in-flight reservation, or with an attempt
//     that still counts, is never discarded to make room.
//
// When capacity pressure leaves nothing reclaimable, the write fails with an
// error instead of silently weakening the limiter. Config.ErrorPolicy then
// decides: the default ErrorPolicyFailClosed rejects the request with 503,
// ErrorPolicyFailOpen lets it through. That is the tradeoff — under sustained
// pressure from more distinct live keys than capacity, this store degrades
// availability rather than enforcement, and the fix is to raise capacity or
// move to a shared backend.
//
// Capacity does not bound total memory. Each counted attempt in Window needs a
// timestamp, and each in-flight atomic request needs reservation and lease
// records. HardThreshold bounds the combined live attempts and reservations for
// a key under a fixed limiter configuration. With only SoftThreshold enabled,
// exact sliding-window backoff decisions require retaining every attempt still
// in Window; BackoffMax caps delay, not retained state.
//
// The store has no automatic TTL. The limiter prunes timestamps inside each
// Bucket, so a second, coarser expiry could drop active state mid-window and
// silently weaken the defense.
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
	// window is the longest Config.Window observed through ObserveWindow.
	// Zero means unknown, in which case no bucket holding an attempt is
	// considered reclaimable.
	window time.Duration
}

// ObserveWindow implements windowObserver. It keeps the longest window seen so
// that a store shared by limiters with different windows never reclaims a
// bucket the slowest of them still needs.
func (s *memoryStore) ObserveWindow(window time.Duration) {
	if window <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if window > s.window {
		s.window = window
	}
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
		oldest := s.oldestReclaimableLocked(tummy.Now())
		if oldest == nil {
			return s.capacityError(1)
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
		if !s.reclaimableLocked(element.Value.(*memoryEntry).bucket, now) {
			pinned++
		}
	}
	if len(desired)+pinned > s.capacity {
		return s.capacityError(len(desired) + pinned - s.capacity)
	}
	neededEvictions := len(desired) + unrequested - s.capacity
	if neededEvictions < 0 {
		neededEvictions = 0
	}
	evictions := make([]string, 0, neededEvictions)
	for element := s.lru.Back(); element != nil && len(evictions) < neededEvictions; element = element.Prev() {
		entry := element.Value.(*memoryEntry)
		if _, ok := requested[entry.key]; ok || !s.reclaimableLocked(entry.bucket, now) {
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

func (s *memoryStore) oldestReclaimableLocked(now time.Time) *list.Element {
	for element := s.lru.Back(); element != nil; element = element.Prev() {
		if s.reclaimableLocked(element.Value.(*memoryEntry).bucket, now) {
			return element
		}
	}
	return nil
}

// reclaimableLocked reports whether dropping bucket is guaranteed not to change
// any future limiter decision. Anything else is live state, and discarding it
// would hand the key owner a free reset of their own limit.
func (s *memoryStore) reclaimableLocked(bucket *Bucket, now time.Time) bool {
	if bucket == nil {
		return true
	}
	if bucketHasActiveReservation(bucket, now) {
		return false
	}
	if len(bucket.Attempts) == 0 {
		return true
	}
	if s.window <= 0 {
		// No limiter has told us its Window, so we cannot prove that these
		// attempts have aged out. Assume they still count.
		return false
	}
	cutoff := now.Add(-s.window)
	for _, attempt := range bucket.Attempts {
		if attempt.After(cutoff) {
			return false
		}
	}
	return true
}

func (s *memoryStore) capacityError(short int) error {
	return fmt.Errorf("ratelimit: memory store at capacity %d, %d more bucket(s) needed and none are reclaimable "+
		"(evicting a bucket that is still enforcing a limit would reset it); raise NewMemoryStore capacity", s.capacity, short)
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
