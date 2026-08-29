package passkey

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

func TestMemoryChallengeStoreConcurrentConsumeIsAtomic(t *testing.T) {
	store := newMemoryChallengeStore()
	t.Cleanup(func() { _ = store.Close() })

	const requests = 32
	if err := store.Save(context.Background(), "session", &SessionData{Expires: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("save: %v", err)
	}

	start := make(chan struct{})
	results := make(chan bool, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			data, err := store.Consume(context.Background(), "session")
			results <- err == nil && data != nil
		}()
	}

	close(start)
	wg.Wait()
	close(results)

	succeeded := 0
	for ok := range results {
		if ok {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful concurrent consumes = %d, want 1", succeeded)
	}
}

type trackingChallengeStore struct {
	closes int
}

func (*trackingChallengeStore) Save(context.Context, string, *SessionData) error { return nil }
func (*trackingChallengeStore) Consume(context.Context, string) (*SessionData, error) {
	return nil, errors.New("not found")
}
func (s *trackingChallengeStore) Close() error {
	s.closes++
	return nil
}

func TestStrategyStoreLifecycle(t *testing.T) {
	wa, err := New(newTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(context.Context, []byte) (*Credential, *identity.Identity, error) {
		return nil, nil, ErrCredentialNotFound
	}

	custom := &trackingChallengeStore{}
	s, err := NewStrategy("custom", wa, lookup, WithChallengeStore(custom))
	if err != nil {
		t.Fatal(err)
	}
	if s.store != custom || s.ownedStore {
		t.Fatal("custom store was not installed as caller-owned")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if custom.closes != 0 {
		t.Fatalf("custom store closed %d times, want 0", custom.closes)
	}

	owned, err := NewStrategy("owned", wa, lookup)
	if err != nil {
		t.Fatal(err)
	}
	store, ok := owned.store.(*memoryChallengeStore)
	if !ok || !owned.ownedStore {
		t.Fatal("default store was not marked as strategy-owned")
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-store.doneCh:
	default:
		t.Fatal("default store GC did not stop before Close returned")
	}
	if err := owned.Close(); err != nil {
		t.Fatal(err)
	}
}
