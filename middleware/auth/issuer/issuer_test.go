package issuer_test

import (
	"context"
	"errors"
	"fmt"
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
	started chan struct{}
	release chan struct{}
}

func newSlowBackend() *slowBackend {
	return &slowBackend{
		Memory:  backend.NewMemory(),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
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
		close(s.started)
		<-s.release
	} else {
		s.mu.Unlock()
	}

	return s.Memory.SavePair(ctx, p, ttl)
}

func (s *slowBackend) AtomicTransactionsSupported() bool { return false }

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

func TestRefreshSingleFlightSeparatesDifferentTokens(t *testing.T) {
	slow := newSlowBackend()
	iss := issuer.NewDefault(slow, issuer.Config{})
	pair, err := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	slow.arm()

	validDone := make(chan error, 1)
	go func() {
		_, err := iss.Refresh(context.Background(), pair.SessionID, pair.Refresh.Value)
		validDone <- err
	}()
	select {
	case <-slow.started:
	case <-time.After(time.Second):
		t.Fatal("valid refresh did not reach SavePair")
	}

	invalidDone := make(chan error, 1)
	go func() {
		_, err := iss.Refresh(context.Background(), pair.SessionID, "invalid-token")
		invalidDone <- err
	}()

	close(slow.release)
	if err := <-validDone; err != nil {
		t.Fatalf("valid refresh: %v", err)
	}
	if err := <-invalidDone; !errors.Is(err, issuer.ErrRefreshInvalid) {
		t.Fatalf("invalid refresh shared valid result: %v", err)
	}
}

func TestAtomicMemorySerializesIssuers(t *testing.T) {
	memory := backend.NewMemory()
	first := issuer.NewDefault(memory, issuer.Config{})
	second := issuer.NewDefault(memory, issuer.Config{})
	if !first.AtomicUpdates() || !second.AtomicUpdates() {
		t.Fatal("Memory-backed issuers must advertise atomic updates")
	}

	pair, err := first.Issue(context.Background(), &identity.Identity{
		Subject: "alice",
		Claims:  map[string]any{"updates": 0},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	const updates = 100
	var wg sync.WaitGroup
	errs := make(chan error, updates)
	for i := range updates {
		current := first
		if i%2 != 0 {
			current = second
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := current.Update(context.Background(), pair.SessionID, func(id *identity.Identity) error {
				id.Claims["updates"] = id.Claims["updates"].(int) + 1

				return nil
			})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("update: %v", err)
		}
	}

	stored, err := first.Resolve(context.Background(), pair.SessionID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := stored.Identity.Claims["updates"]; got != updates {
		t.Fatalf("updates = %v, want %d", got, updates)
	}
}

func TestAtomicMemoryRefreshAcrossIssuers(t *testing.T) {
	memory := backend.NewMemory()
	first := issuer.NewDefault(memory, issuer.Config{})
	second := issuer.NewDefault(memory, issuer.Config{})
	pair, err := first.Issue(context.Background(), &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, current := range []*issuer.Default{first, second} {
		go func() {
			<-start
			_, err := current.Refresh(context.Background(), pair.SessionID, pair.Refresh.Value)
			errs <- err
		}()
	}
	close(start)

	succeeded := 0
	rejected := 0
	for range 2 {
		err := <-errs
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, issuer.ErrRefreshInvalid):
			rejected++
		default:
			t.Fatalf("refresh error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("successes = %d, invalid = %d", succeeded, rejected)
	}
}

type legacyBackend struct{ issuer.Backend }

func TestLegacyBackendUsesProcessLocalFallback(t *testing.T) {
	iss := issuer.NewDefault(legacyBackend{Backend: backend.NewMemory()}, issuer.Config{})
	if iss.AtomicUpdates() {
		t.Fatal("legacy backend must not advertise cross-replica atomic updates")
	}

	pair, err := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := iss.Update(context.Background(), pair.SessionID, func(*identity.Identity) error { return nil }); err != nil {
		t.Fatalf("fallback update: %v", err)
	}
}

type atomicAuditBackend struct {
	*backend.Memory
	mu            sync.Mutex
	transactions  int
	directDeletes int
}

type ttlAuditBackend struct {
	*backend.Memory
	mu     sync.Mutex
	atomic bool
	ttls   []time.Duration
	loads  int
}

func (b *ttlAuditBackend) LoadPair(ctx context.Context, sessionID string) (*issuer.Pair, error) {
	b.mu.Lock()
	b.loads++
	b.mu.Unlock()

	return b.Memory.LoadPair(ctx, sessionID)
}

func (b *ttlAuditBackend) SavePair(ctx context.Context, pair *issuer.Pair, ttl time.Duration) error {
	b.recordTTL(ttl)

	return b.Memory.SavePair(ctx, pair, ttl)
}

func (b *ttlAuditBackend) AtomicTransactionsSupported() bool { return b.atomic }

func (b *ttlAuditBackend) TransactPair(
	ctx context.Context,
	sessionID string,
	ttl time.Duration,
	fn issuer.PairTransaction,
) (*issuer.Pair, error) {
	b.recordTTL(ttl)

	return b.Memory.TransactPair(ctx, sessionID, ttl, fn)
}

func (b *ttlAuditBackend) recordTTL(ttl time.Duration) {
	b.mu.Lock()
	b.ttls = append(b.ttls, ttl)
	b.mu.Unlock()
}

func (b *ttlAuditBackend) resetTTLs() {
	b.mu.Lock()
	b.ttls = nil
	b.loads = 0
	b.mu.Unlock()
}

func (b *ttlAuditBackend) onlyTTL(t *testing.T) time.Duration {
	t.Helper()

	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.ttls) != 1 {
		t.Fatalf("recorded TTLs = %v, want exactly one", b.ttls)
	}

	return b.ttls[0]
}

func (b *ttlAuditBackend) loadCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.loads
}

func TestUpdatePreservesRefreshStorageDeadline(t *testing.T) {
	for _, atomic := range []bool{false, true} {
		t.Run(fmt.Sprintf("atomic=%t", atomic), func(t *testing.T) {
			now := time.Now().UTC()
			b := &ttlAuditBackend{Memory: backend.NewMemory(), atomic: atomic}
			iss := issuer.NewDefault(b, issuer.Config{
				RefreshTTL: 24 * time.Hour,
				Now:        func() time.Time { return now },
			})
			pair, err := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			refreshExpiry := pair.Refresh.ExpiresAt
			b.resetTTLs()
			now = now.Add(6 * time.Hour)

			calls := 0
			updated, err := iss.Update(context.Background(), pair.SessionID, func(id *identity.Identity) error {
				calls++
				id.Subject = "updated"

				return nil
			})
			if err != nil {
				t.Fatalf("update: %v", err)
			}
			if calls != 1 {
				t.Fatalf("callback calls = %d, want 1", calls)
			}
			if !updated.Refresh.ExpiresAt.Equal(refreshExpiry) {
				t.Fatalf("refresh expiry = %v, want %v", updated.Refresh.ExpiresAt, refreshExpiry)
			}
			wantTTL := 18*time.Hour + time.Minute
			wantLoads := 1
			if atomic {
				wantTTL = 0
				wantLoads = 0
			}
			if got := b.onlyTTL(t); got != wantTTL {
				t.Fatalf("storage TTL = %v, want %v", got, wantTTL)
			}
			if got := b.loadCount(); got != wantLoads {
				t.Fatalf("pre-transaction loads = %d, want %d", got, wantLoads)
			}
		})
	}
}

func TestRefreshWithoutRotationPreservesStorageDeadline(t *testing.T) {
	for _, atomic := range []bool{false, true} {
		t.Run(fmt.Sprintf("atomic=%t", atomic), func(t *testing.T) {
			now := time.Now().UTC()
			b := &ttlAuditBackend{Memory: backend.NewMemory(), atomic: atomic}
			iss := issuer.NewDefault(b, issuer.Config{
				RefreshTTL:             24 * time.Hour,
				DisableRefreshRotation: true,
				Now:                    func() time.Time { return now },
			})
			pair, err := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			b.resetTTLs()
			now = now.Add(6 * time.Hour)

			refreshed, err := iss.Refresh(context.Background(), pair.SessionID, pair.Refresh.Value)
			if err != nil {
				t.Fatalf("refresh: %v", err)
			}
			if refreshed.Refresh != pair.Refresh {
				t.Fatalf("refresh token changed: got %+v, want %+v", refreshed.Refresh, pair.Refresh)
			}
			wantTTL := 18*time.Hour + time.Minute
			wantLoads := 1
			if atomic {
				wantTTL = 0
				wantLoads = 0
			}
			if got := b.onlyTTL(t); got != wantTTL {
				t.Fatalf("storage TTL = %v, want %v", got, wantTTL)
			}
			if got := b.loadCount(); got != wantLoads {
				t.Fatalf("pre-transaction loads = %d, want %d", got, wantLoads)
			}
		})
	}
}

func TestUpdateClampsPastStorageDeadlineToExpiringTTL(t *testing.T) {
	for _, atomic := range []bool{false, true} {
		t.Run(fmt.Sprintf("atomic=%t", atomic), func(t *testing.T) {
			now := time.Now().UTC()
			b := &ttlAuditBackend{Memory: backend.NewMemory(), atomic: atomic}
			iss := issuer.NewDefault(b, issuer.Config{
				RefreshTTL: time.Hour,
				Now:        func() time.Time { return now },
			})
			pair, err := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			b.resetTTLs()
			now = pair.Refresh.ExpiresAt.Add(2 * time.Minute)

			calls := 0
			if _, err := iss.Update(context.Background(), pair.SessionID, func(*identity.Identity) error {
				calls++

				return nil
			}); err != nil {
				t.Fatalf("update: %v", err)
			}
			if calls != 1 {
				t.Fatalf("callback calls = %d, want 1", calls)
			}
			wantTTL := time.Nanosecond
			wantLoads := 1
			if atomic {
				wantTTL = 0
				wantLoads = 0
			}
			if got := b.onlyTTL(t); got != wantTTL {
				t.Fatalf("storage TTL = %v, want %v", got, wantTTL)
			}
			if got := b.loadCount(); got != wantLoads {
				t.Fatalf("pre-transaction loads = %d, want %d", got, wantLoads)
			}
		})
	}
}

func (b *atomicAuditBackend) TransactPair(
	ctx context.Context,
	sessionID string,
	ttl time.Duration,
	fn issuer.PairTransaction,
) (*issuer.Pair, error) {
	b.mu.Lock()
	b.transactions++
	b.mu.Unlock()

	return b.Memory.TransactPair(ctx, sessionID, ttl, fn)
}

func (b *atomicAuditBackend) DeletePair(ctx context.Context, sessionID string) error {
	b.mu.Lock()
	b.directDeletes++
	b.mu.Unlock()

	return b.Memory.DeletePair(ctx, sessionID)
}

func TestDefaultUsesAtomicTransactionsForEveryMutation(t *testing.T) {
	b := &atomicAuditBackend{Memory: backend.NewMemory()}
	iss := issuer.NewDefault(b, issuer.Config{})
	pair, err := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	refreshed, err := iss.Refresh(context.Background(), pair.SessionID, pair.Refresh.Value)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := iss.Update(context.Background(), pair.SessionID, func(*identity.Identity) error { return nil }); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := iss.Revoke(context.Background(), refreshed.SessionID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	b.mu.Lock()
	transactions := b.transactions
	directDeletes := b.directDeletes
	b.mu.Unlock()
	if transactions != 3 || directDeletes != 0 {
		t.Fatalf("transactions = %d, direct deletes = %d", transactions, directDeletes)
	}
}

type revokeRaceBackend struct {
	*backend.Memory
	mu            sync.Mutex
	armed         bool
	saveStarted   chan struct{}
	releaseSave   chan struct{}
	deleteStarted chan struct{}
	deleteOnce    sync.Once
}

func newRevokeRaceBackend() *revokeRaceBackend {
	return &revokeRaceBackend{
		Memory:        backend.NewMemory(),
		saveStarted:   make(chan struct{}),
		releaseSave:   make(chan struct{}),
		deleteStarted: make(chan struct{}),
	}
}

func (b *revokeRaceBackend) arm() {
	b.mu.Lock()
	b.armed = true
	b.mu.Unlock()
}

func (b *revokeRaceBackend) SavePair(ctx context.Context, pair *issuer.Pair, ttl time.Duration) error {
	b.mu.Lock()
	armed := b.armed
	if armed {
		b.armed = false
	}
	b.mu.Unlock()

	if armed {
		close(b.saveStarted)
		<-b.releaseSave
	}

	return b.Memory.SavePair(ctx, pair, ttl)
}

func (b *revokeRaceBackend) DeletePair(ctx context.Context, sessionID string) error {
	b.deleteOnce.Do(func() { close(b.deleteStarted) })

	return b.Memory.DeletePair(ctx, sessionID)
}

func (b *revokeRaceBackend) AtomicTransactionsSupported() bool { return false }

func TestRevokeWaitsForRefreshSave(t *testing.T) {
	b := newRevokeRaceBackend()
	iss := issuer.NewDefault(b, issuer.Config{})
	pair, err := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	b.arm()

	refreshDone := make(chan error, 1)
	go func() {
		_, err := iss.Refresh(context.Background(), pair.SessionID, pair.Refresh.Value)
		refreshDone <- err
	}()
	select {
	case <-b.saveStarted:
	case <-time.After(time.Second):
		t.Fatal("refresh did not reach SavePair")
	}

	revokeDone := make(chan error, 1)
	go func() { revokeDone <- iss.Revoke(context.Background(), pair.SessionID) }()
	select {
	case <-b.deleteStarted:
		t.Fatal("Revoke deleted while Refresh still had a stale SavePair in flight")
	case <-time.After(50 * time.Millisecond):
	}

	close(b.releaseSave)
	if err := <-refreshDone; err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := <-revokeDone; err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := iss.Resolve(context.Background(), pair.SessionID); !errors.Is(err, issuer.ErrNotFound) {
		t.Fatalf("session was resurrected after revoke: %v", err)
	}
}

func TestIssueClampsAccessAndIdentityToRefreshExpiry(t *testing.T) {
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	iss := issuer.NewDefault(backend.NewMemory(), issuer.Config{
		AccessTTL:  2 * time.Hour,
		RefreshTTL: 30 * time.Minute,
		Now:        func() time.Time { return now },
	})

	pair, err := iss.Issue(context.Background(), &identity.Identity{
		Subject:   "alice",
		ExpiresAt: now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !pair.Access.ExpiresAt.Equal(pair.Refresh.ExpiresAt) {
		t.Fatalf("access expiry = %v, refresh expiry = %v", pair.Access.ExpiresAt, pair.Refresh.ExpiresAt)
	}
	if !pair.Identity.ExpiresAt.Equal(pair.Refresh.ExpiresAt) {
		t.Fatalf("identity expiry = %v, refresh expiry = %v", pair.Identity.ExpiresAt, pair.Refresh.ExpiresAt)
	}
}

func TestRefreshClampsAccessToRefreshExpiry(t *testing.T) {
	for _, disableRotation := range []bool{false, true} {
		t.Run(fmt.Sprintf("disable_rotation=%t", disableRotation), func(t *testing.T) {
			now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
			iss := issuer.NewDefault(backend.NewMemory(), issuer.Config{
				AccessTTL:              2 * time.Hour,
				RefreshTTL:             time.Hour,
				DisableRefreshRotation: disableRotation,
				Now:                    func() time.Time { return now },
			})
			pair, err := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})
			if err != nil {
				t.Fatal(err)
			}
			originalRefreshExpiry := pair.Refresh.ExpiresAt
			now = now.Add(45 * time.Minute)

			refreshed, err := iss.Refresh(context.Background(), pair.SessionID, pair.Refresh.Value)
			if err != nil {
				t.Fatal(err)
			}
			if !refreshed.Access.ExpiresAt.Equal(refreshed.Refresh.ExpiresAt) {
				t.Fatalf("access expiry = %v, refresh expiry = %v", refreshed.Access.ExpiresAt, refreshed.Refresh.ExpiresAt)
			}
			if !refreshed.Identity.ExpiresAt.Equal(refreshed.Refresh.ExpiresAt) {
				t.Fatalf("identity expiry = %v, refresh expiry = %v", refreshed.Identity.ExpiresAt, refreshed.Refresh.ExpiresAt)
			}
			if disableRotation && !refreshed.Refresh.ExpiresAt.Equal(originalRefreshExpiry) {
				t.Fatalf("non-rotating refresh expiry = %v, want %v", refreshed.Refresh.ExpiresAt, originalRefreshExpiry)
			}
		})
	}
}

type conflictingAtomicBackend struct {
	*backend.Memory
	mu           sync.Mutex
	conflicts    int
	transactions int
}

func (b *conflictingAtomicBackend) setConflicts(conflicts int) {
	b.mu.Lock()
	b.conflicts = conflicts
	b.transactions = 0
	b.mu.Unlock()
}

func (b *conflictingAtomicBackend) transactionCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.transactions
}

func (b *conflictingAtomicBackend) TransactPair(
	ctx context.Context,
	sessionID string,
	ttl time.Duration,
	fn issuer.PairTransaction,
) (*issuer.Pair, error) {
	b.mu.Lock()
	b.transactions++
	conflict := b.conflicts > 0
	if conflict {
		b.conflicts--
	}
	b.mu.Unlock()

	if !conflict {
		return b.Memory.TransactPair(ctx, sessionID, ttl, fn)
	}

	current, err := b.LoadPair(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if _, _, err := fn(current); err != nil {
		return nil, err
	}

	return nil, issuer.ErrTransactionConflict
}

func TestUpdateDoesNotRetryCallerCallbackOnConflict(t *testing.T) {
	b := &conflictingAtomicBackend{Memory: backend.NewMemory()}
	iss := issuer.NewDefault(b, issuer.Config{})
	pair, err := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	b.setConflicts(1)

	calls := 0
	_, err = iss.Update(context.Background(), pair.SessionID, func(id *identity.Identity) error {
		calls++
		id.Subject = "changed"

		return nil
	})
	if !errors.Is(err, issuer.ErrTransactionConflict) {
		t.Fatalf("Update() error = %v, want ErrTransactionConflict", err)
	}
	if calls != 1 {
		t.Fatalf("callback calls = %d, want exactly 1", calls)
	}
	stored, err := iss.Resolve(context.Background(), pair.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Identity.Subject != "alice" {
		t.Fatalf("conflicted update was persisted: %+v", stored.Identity)
	}
}

func TestRevokeRetriesConflictsAndFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name          string
		conflicts     int
		wantErr       bool
		wantRemaining bool
	}{
		{name: "eventual success", conflicts: 2},
		{name: "retry exhaustion", conflicts: 3, wantErr: true, wantRemaining: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &conflictingAtomicBackend{Memory: backend.NewMemory()}
			iss := issuer.NewDefault(b, issuer.Config{})
			pair, err := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})
			if err != nil {
				t.Fatal(err)
			}
			b.setConflicts(tc.conflicts)

			err = iss.Revoke(context.Background(), pair.SessionID)
			if errors.Is(err, issuer.ErrTransactionConflict) != tc.wantErr {
				t.Fatalf("Revoke() error = %v, want conflict=%t", err, tc.wantErr)
			}
			if got := b.transactionCount(); got != 3 {
				t.Fatalf("transaction attempts = %d, want 3", got)
			}
			_, resolveErr := iss.Resolve(context.Background(), pair.SessionID)
			if tc.wantRemaining {
				if resolveErr != nil {
					t.Fatalf("session removed after failed revoke: %v", resolveErr)
				}
			} else if !errors.Is(resolveErr, issuer.ErrNotFound) {
				t.Fatalf("session survived successful revoke: %v", resolveErr)
			}
		})
	}
}
