package issuer_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/issuer"
	"github.com/rakunlabs/ada/middleware/auth/issuer/backend"
)

func newTestIssuer(t *testing.T) (*issuer.Default, *backend.Memory) {
	t.Helper()

	mem := backend.NewMemory()
	iss := issuer.NewDefault(mem, issuer.Config{
		AccessTTL:  50 * time.Millisecond,
		RefreshTTL: 500 * time.Millisecond,
	})

	return iss, mem
}

func TestIssueAndResolve(t *testing.T) {
	iss, _ := newTestIssuer(t)
	ctx := context.Background()

	pair, err := iss.Issue(ctx, &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if pair.SessionID == "" || pair.Access.Value == "" || pair.Refresh.Value == "" {
		t.Fatalf("empty token in pair: %+v", pair)
	}
	if pair.Access.ExpiresAt.IsZero() || pair.Refresh.ExpiresAt.IsZero() {
		t.Fatalf("zero expiry: %+v", pair)
	}

	got, err := iss.Resolve(ctx, pair.SessionID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Identity.Subject != "alice" {
		t.Fatalf("got identity %+v", got.Identity)
	}
}

func TestResolveNotFound(t *testing.T) {
	iss, _ := newTestIssuer(t)

	_, err := iss.Resolve(context.Background(), "ghost")
	if !errors.Is(err, issuer.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestRefreshRotates(t *testing.T) {
	iss, _ := newTestIssuer(t)
	ctx := context.Background()

	pair, _ := iss.Issue(ctx, &identity.Identity{Subject: "alice"})

	time.Sleep(60 * time.Millisecond) // access expired

	newPair, err := iss.Refresh(ctx, pair.SessionID, pair.Refresh.Value)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if newPair.SessionID != pair.SessionID {
		t.Fatalf("session id changed")
	}
	if newPair.Access.Value == pair.Access.Value {
		t.Fatalf("access not rotated")
	}
	if newPair.Refresh.Value == pair.Refresh.Value {
		t.Fatalf("refresh not rotated")
	}
}

func TestRefreshWithBadToken(t *testing.T) {
	iss, _ := newTestIssuer(t)
	ctx := context.Background()

	pair, _ := iss.Issue(ctx, &identity.Identity{Subject: "alice"})

	_, err := iss.Refresh(ctx, pair.SessionID, "wrong")
	if !errors.Is(err, issuer.ErrRefreshInvalid) {
		t.Fatalf("expected ErrRefreshInvalid, got %v", err)
	}
}

func TestRefreshExpired(t *testing.T) {
	iss, _ := newTestIssuer(t)
	ctx := context.Background()

	pair, _ := iss.Issue(ctx, &identity.Identity{Subject: "alice"})

	time.Sleep(550 * time.Millisecond) // refresh expired

	_, err := iss.Refresh(ctx, pair.SessionID, pair.Refresh.Value)
	if !errors.Is(err, issuer.ErrRefreshExpired) {
		t.Fatalf("expected ErrRefreshExpired, got %v", err)
	}

	if _, err := iss.Resolve(ctx, pair.SessionID); !errors.Is(err, issuer.ErrNotFound) {
		t.Fatalf("expected pair removed after expired refresh")
	}
}

func TestRevoke(t *testing.T) {
	iss, _ := newTestIssuer(t)
	ctx := context.Background()

	pair, _ := iss.Issue(ctx, &identity.Identity{Subject: "alice"})

	if err := iss.Revoke(ctx, pair.SessionID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if _, err := iss.Resolve(ctx, pair.SessionID); !errors.Is(err, issuer.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after revoke, got %v", err)
	}
}

// slowBackend wraps Memory and blocks SavePair on the first save AFTER it is
// armed, giving the single-flight test a deterministic window where all N
// goroutines are guaranteed to be inside Refresh together.
type slowBackend struct {
	*backend.Memory
	mu      sync.Mutex
	armed   bool
	release chan struct{}
}

func newSlowBackend() *slowBackend {
	return &slowBackend{Memory: backend.NewMemory(), release: make(chan struct{})}
}

// arm enables the block-on-next-save behavior. Call after warm-up.
func (s *slowBackend) arm() {
	s.mu.Lock()
	s.armed = true
	s.mu.Unlock()
}

func (s *slowBackend) SavePair(ctx context.Context, p *issuer.Pair, ttl time.Duration) error {
	s.mu.Lock()
	if s.armed {
		s.armed = false // block only the first save after arming
		s.mu.Unlock()
		<-s.release
	} else {
		s.mu.Unlock()
	}

	return s.Memory.SavePair(ctx, p, ttl)
}

func TestRefreshSingleFlight(t *testing.T) {
	slow := newSlowBackend()

	iss := issuer.NewDefault(slow, issuer.Config{
		AccessTTL:  50 * time.Millisecond,
		RefreshTTL: 500 * time.Millisecond,
	})
	ctx := context.Background()

	pair, err := iss.Issue(ctx, &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	time.Sleep(60 * time.Millisecond) // access expired

	// Now arm: the first refresh's SavePair will block, holding the in-flight
	// open while the rest of the goroutines arrive.
	slow.arm()

	const N = 8
	var wg sync.WaitGroup
	results := make([]*issuer.Pair, N)
	errs := make([]error, N)

	for i := range N {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = iss.Refresh(ctx, pair.SessionID, pair.Refresh.Value)
		}(i)
	}

	// Give all goroutines time to either start the rotation (one) or wait on
	// the in-flight done channel (the rest).
	time.Sleep(50 * time.Millisecond)

	// Release the rotating goroutine; the rest are waiting on its result.
	close(slow.release)

	wg.Wait()

	for i, p := range results {
		if errs[i] != nil {
			t.Fatalf("refresh %d failed: %v", i, errs[i])
		}
		if p == nil {
			t.Fatalf("result %d nil", i)
		}
		if p.Access.Value != results[0].Access.Value {
			t.Errorf("result %d access differs: %q vs %q", i, p.Access.Value, results[0].Access.Value)
		}
	}
}
