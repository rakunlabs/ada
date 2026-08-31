package backend

import (
	"context"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/issuer"
)

func TestMemoryTransactionPreservesExactExpiry(t *testing.T) {
	now := time.Unix(1_000, 0)
	memory := NewMemory()
	memory.now = func() time.Time { return now }
	pair := &issuer.Pair{SessionID: "session"}

	if err := memory.SavePair(context.Background(), pair, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	wantExpiry := memory.pairs[pair.SessionID].expiresAt
	now = now.Add(30 * time.Minute)

	result, err := memory.TransactPair(context.Background(), pair.SessionID, 0,
		func(current *issuer.Pair) (*issuer.Pair, bool, error) {
			return current, true, nil
		})
	if err != nil || result == nil {
		t.Fatalf("TransactPair() = (%v, %v), want committed replacement", result, err)
	}
	if got := memory.pairs[pair.SessionID].expiresAt; !got.Equal(wantExpiry) {
		t.Fatalf("expiry = %v, want exact preserved expiry %v", got, wantExpiry)
	}
}

func TestMemoryTransactionPreservesNoExpiry(t *testing.T) {
	memory := NewMemory()
	pair := &issuer.Pair{SessionID: "session"}

	if err := memory.SavePair(context.Background(), pair, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := memory.TransactPair(context.Background(), pair.SessionID, -time.Second,
		func(current *issuer.Pair) (*issuer.Pair, bool, error) {
			return current, true, nil
		}); err != nil {
		t.Fatal(err)
	}
	if got := memory.pairs[pair.SessionID].expiresAt; !got.IsZero() {
		t.Fatalf("expiry = %v, want no expiry", got)
	}
}
