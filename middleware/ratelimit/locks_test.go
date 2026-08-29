package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type notifyingStore struct {
	Store
	key  string
	once sync.Once
	got  chan struct{}
}

func (s *notifyingStore) Get(ctx context.Context, key string) (*Bucket, bool, error) {
	bucket, ok, err := s.Store.Get(ctx, key)
	if key == s.key {
		s.once.Do(func() { close(s.got) })
	}
	return bucket, ok, err
}

func TestKeyLocksReleaseHighCardinalityEntries(t *testing.T) {
	locks := newKeyLocks()

	for i := 0; i < 100_000; i++ {
		held := lockAll(locks, []string{fmt.Sprintf("attacker-key-%d", i)})
		held.unlock()
	}
	if got := len(locks.entries); got != 0 {
		t.Fatalf("lock pool retained %d entries after requests completed", got)
	}
}

func TestBackoffDoesNotHoldUnrelatedKeyLock(t *testing.T) {
	store, err := NewMemoryStore(16)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	keyA := "delayed"
	keyB := "unrelated"
	if err := store.Set(t.Context(), keyA, &Bucket{Attempts: []time.Time{time.Now()}}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	enteredB := make(chan struct{})
	notifiedStore := &notifyingStore{Store: store, key: keyA, got: make(chan struct{})}
	cfg := Config{
		Window:        time.Hour,
		SoftThreshold: 1,
		BackoffBase:   200 * time.Millisecond,
		BackoffMax:    200 * time.Millisecond,
		KeyFunc: func(r *http.Request) []string {
			return []string{r.Header.Get("X-Key")}
		},
		ShouldCount: func(*http.Request, int) bool { return false },
		Store:       notifiedStore,
	}
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Key") == keyB {
			close(enteredB)
		}
		w.WriteHeader(http.StatusOK)
	}))

	doneA := make(chan struct{})
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctxA)
		req.Header.Set("X-Key", keyA)
		handler.ServeHTTP(httptest.NewRecorder(), req)
		close(doneA)
	}()
	select {
	case <-notifiedStore.got:
	case <-time.After(time.Second):
		t.Fatal("delayed request did not read its bucket")
	}

	reqB := httptest.NewRequest(http.MethodGet, "/", nil)
	reqB.Header.Set("X-Key", keyB)
	doneB := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), reqB)
		close(doneB)
	}()
	select {
	case <-enteredB:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("unrelated key was blocked while another request slept")
	}
	<-doneB
	cancelA()
	<-doneA
}
