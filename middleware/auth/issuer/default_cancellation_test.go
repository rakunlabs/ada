package issuer

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

type cancellationBackend struct {
	mu sync.Mutex

	pair          *Pair
	blockNextSave bool
	saveStarted   chan struct{}
	releaseSave   chan struct{}
	releaseOnce   sync.Once
	deleteCalls   int
}

func newCancellationBackend() *cancellationBackend {
	return &cancellationBackend{
		saveStarted: make(chan struct{}),
		releaseSave: make(chan struct{}),
	}
}

func (b *cancellationBackend) LoadPair(_ context.Context, sessionID string) (*Pair, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pair == nil || b.pair.SessionID != sessionID {
		return nil, ErrNotFound
	}

	return cloneCancellationPair(b.pair)
}

func (b *cancellationBackend) SavePair(ctx context.Context, pair *Pair, _ time.Duration) error {
	b.mu.Lock()
	block := b.blockNextSave
	b.blockNextSave = false
	b.mu.Unlock()

	if block {
		close(b.saveStarted)
		<-b.releaseSave
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	stored, err := cloneCancellationPair(pair)
	if err != nil {
		return err
	}

	b.mu.Lock()
	b.pair = stored
	b.mu.Unlock()

	return nil
}

func (b *cancellationBackend) DeletePair(_ context.Context, sessionID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.deleteCalls++
	if b.pair != nil && b.pair.SessionID == sessionID {
		b.pair = nil
	}

	return nil
}

func (b *cancellationBackend) armSave() {
	b.mu.Lock()
	b.blockNextSave = true
	b.mu.Unlock()
}

func (b *cancellationBackend) release() {
	b.releaseOnce.Do(func() { close(b.releaseSave) })
}

func (b *cancellationBackend) deletes() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.deleteCalls
}

func cloneCancellationPair(pair *Pair) (*Pair, error) {
	data, err := EncodePair(pair)
	if err != nil {
		return nil, err
	}

	return DecodePair(data)
}

type pairCallResult struct {
	pair *Pair
	err  error
}

type triggeredContext struct {
	context.Context

	mu   sync.Mutex
	done chan struct{}
	err  error
}

func newTriggeredContext() *triggeredContext {
	return &triggeredContext{Context: context.Background(), done: make(chan struct{})}
}

func (c *triggeredContext) Done() <-chan struct{} {
	return c.done
}

func (c *triggeredContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.err
}

func (c *triggeredContext) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.err != nil {
		return
	}
	c.err = err
	close(c.done)
}

type observedDoneContext struct {
	context.Context

	once     sync.Once
	observed chan struct{}
}

func (c *observedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })

	return c.Context.Done()
}

func startBlockedRefresh(t *testing.T) (*Default, *cancellationBackend, *Pair, <-chan error) {
	t.Helper()

	b := newCancellationBackend()
	t.Cleanup(b.release)

	iss := NewDefault(b, Config{})
	pair, err := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	b.armSave()

	done := make(chan error, 1)
	go func() {
		_, err := iss.Refresh(context.Background(), pair.SessionID, pair.Refresh.Value)
		done <- err
	}()

	select {
	case <-b.saveStarted:
	case <-time.After(time.Second):
		t.Fatal("refresh leader did not block in SavePair")
	}
	waitForIssuerMutationState(t, iss, pair.SessionID, 1, 1)

	return iss, b, pair, done
}

func finishBlockedRefresh(
	t *testing.T,
	iss *Default,
	b *cancellationBackend,
	sessionID string,
	done <-chan error,
) {
	t.Helper()

	b.release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("refresh leader error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh leader did not return")
	}
	waitForIssuerMutationState(t, iss, sessionID, 0, 0)
}

func waitForIssuerMutationState(
	t *testing.T,
	iss *Default,
	sessionID string,
	wantRefs int,
	wantFlights int,
) {
	t.Helper()

	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()

	for {
		iss.mu.Lock()
		lock, lockExists := iss.locks[sessionID]
		refs := 0
		if lockExists {
			refs = lock.refs
		}
		flights := 0
		for key := range iss.flights {
			if key.sessionID == sessionID {
				flights++
			}
		}
		iss.mu.Unlock()

		if refs == wantRefs && lockExists == (wantRefs > 0) && flights == wantFlights {
			return
		}

		select {
		case <-deadline.C:
			t.Fatalf(
				"issuer state = refs %d, lock exists %t, flights %d; want refs %d, flights %d",
				refs,
				lockExists,
				flights,
				wantRefs,
				wantFlights,
			)
		default:
			runtime.Gosched()
		}
	}
}

func awaitPairCancellation(t *testing.T, done <-chan pairCallResult) {
	t.Helper()

	select {
	case result := <-done:
		if result.pair != nil || !errors.Is(result.err, context.Canceled) {
			t.Fatalf("result = (%+v, %v), want (nil, context.Canceled)", result.pair, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled call remained blocked")
	}
}

func TestRefreshSameTokenFollowerReturnsOnCancellation(t *testing.T) {
	iss, b, pair, leaderDone := startBlockedRefresh(t)

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan pairCallResult, 1)
	go func() {
		close(started)
		refreshed, err := iss.Refresh(ctx, pair.SessionID, pair.Refresh.Value)
		done <- pairCallResult{pair: refreshed, err: err}
	}()
	<-started
	cancel()

	awaitPairCancellation(t, done)
	waitForIssuerMutationState(t, iss, pair.SessionID, 1, 1)
	finishBlockedRefresh(t, iss, b, pair.SessionID, leaderDone)
}

func TestRefreshCanceledLeaderDoesNotPoisonLiveFollower(t *testing.T) {
	for _, tc := range []struct {
		name      string
		leaderErr error
	}{
		{name: "canceled", leaderErr: context.Canceled},
		{name: "deadline exceeded", leaderErr: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newCancellationBackend()
			t.Cleanup(b.release)

			iss := NewDefault(b, Config{})
			pair, err := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})
			if err != nil {
				t.Fatalf("Issue() error = %v", err)
			}
			b.armSave()

			leaderCtx := newTriggeredContext()
			leaderDone := make(chan pairCallResult, 1)
			go func() {
				refreshed, err := iss.Refresh(leaderCtx, pair.SessionID, pair.Refresh.Value)
				leaderDone <- pairCallResult{pair: refreshed, err: err}
			}()
			select {
			case <-b.saveStarted:
			case <-time.After(time.Second):
				t.Fatal("refresh leader did not block in SavePair")
			}
			waitForIssuerMutationState(t, iss, pair.SessionID, 1, 1)

			followerCtx := &observedDoneContext{
				Context:  context.Background(),
				observed: make(chan struct{}),
			}
			followerDone := make(chan pairCallResult, 1)
			go func() {
				refreshed, err := iss.Refresh(followerCtx, pair.SessionID, pair.Refresh.Value)
				followerDone <- pairCallResult{pair: refreshed, err: err}
			}()
			select {
			case <-followerCtx.observed:
			case <-time.After(time.Second):
				t.Fatal("live follower did not join the leader flight")
			}

			leaderCtx.fail(tc.leaderErr)
			b.release()

			select {
			case result := <-leaderDone:
				if result.pair != nil || !errors.Is(result.err, tc.leaderErr) {
					t.Fatalf("leader result = (%+v, %v), want (nil, %v)", result.pair, result.err, tc.leaderErr)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled refresh leader did not return")
			}

			select {
			case result := <-followerDone:
				if result.err != nil || result.pair == nil {
					t.Fatalf("live follower result = (%+v, %v), want successful refresh", result.pair, result.err)
				}
			case <-time.After(time.Second):
				t.Fatal("live follower did not retry the canceled leader flight")
			}

			waitForIssuerMutationState(t, iss, pair.SessionID, 0, 0)
		})
	}
}

func TestRefreshDifferentTokenLockWaitReturnsOnCancellation(t *testing.T) {
	iss, b, pair, leaderDone := startBlockedRefresh(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan pairCallResult, 1)
	go func() {
		refreshed, err := iss.Refresh(ctx, pair.SessionID, "different-token")
		done <- pairCallResult{pair: refreshed, err: err}
	}()
	waitForIssuerMutationState(t, iss, pair.SessionID, 2, 2)
	cancel()

	awaitPairCancellation(t, done)
	waitForIssuerMutationState(t, iss, pair.SessionID, 1, 1)
	finishBlockedRefresh(t, iss, b, pair.SessionID, leaderDone)
}

func TestUpdateLockWaitReturnsOnCancellation(t *testing.T) {
	iss, b, pair, leaderDone := startBlockedRefresh(t)

	ctx, cancel := context.WithCancel(context.Background())
	callbackCalls := 0
	done := make(chan pairCallResult, 1)
	go func() {
		updated, err := iss.Update(ctx, pair.SessionID, func(*identity.Identity) error {
			callbackCalls++

			return nil
		})
		done <- pairCallResult{pair: updated, err: err}
	}()
	waitForIssuerMutationState(t, iss, pair.SessionID, 2, 1)
	cancel()

	awaitPairCancellation(t, done)
	if callbackCalls != 0 {
		t.Fatalf("update callback calls = %d, want 0", callbackCalls)
	}
	waitForIssuerMutationState(t, iss, pair.SessionID, 1, 1)
	finishBlockedRefresh(t, iss, b, pair.SessionID, leaderDone)
}

func TestRevokeLockWaitReturnsOnCancellation(t *testing.T) {
	iss, b, pair, leaderDone := startBlockedRefresh(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- iss.Revoke(ctx, pair.SessionID)
	}()
	waitForIssuerMutationState(t, iss, pair.SessionID, 2, 1)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Revoke() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled Revoke remained blocked")
	}
	if got := b.deletes(); got != 0 {
		t.Fatalf("DeletePair calls = %d, want 0", got)
	}
	waitForIssuerMutationState(t, iss, pair.SessionID, 1, 1)
	finishBlockedRefresh(t, iss, b, pair.SessionID, leaderDone)

	if _, err := iss.Resolve(context.Background(), pair.SessionID); err != nil {
		t.Fatalf("canceled Revoke removed session: %v", err)
	}
}
