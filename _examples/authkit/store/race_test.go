package store_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/oauthserver"
	"github.com/rakunlabs/ada/_examples/authkit/store"
)

// Concurrent exchanges of one code and concurrent rotations of one refresh
// token must each have exactly one winner.
func TestConcurrentSingleUse(t *testing.T) { each(t, testConcurrentSingleUse) }

func testConcurrentSingleUse(t *testing.T, st *store.Store) {
	ctx := context.Background()
	id := &identity.Identity{Subject: "alice"}

	if err := st.SaveCode(ctx, &oauthserver.Code{Hash: "race", ClientID: "c", Identity: id, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}

	tok := &oauthserver.Token{ID: "t", ClientID: "c", Identity: id, AccessHash: "a0", RefreshHash: "r0", CreatedAt: time.Now()}
	if err := st.SaveToken(ctx, tok); err != nil {
		t.Fatal(err)
	}

	const n = 16

	var (
		codes, rotations atomic.Int32
		wg               sync.WaitGroup
	)

	for i := range n {
		wg.Add(2)

		go func() {
			defer wg.Done()

			if _, err := st.TakeCode(ctx, "race"); err == nil {
				codes.Add(1)
			} else if !errors.Is(err, oauthserver.ErrNotFound) {
				t.Errorf("take: %v", err)
			}
		}()

		go func() {
			defer wg.Done()

			next := *tok
			next.AccessHash = "a" + string(rune('a'+i))
			next.RefreshHash = "r" + string(rune('a'+i))

			if err := st.RotateToken(ctx, "r0", &next); err == nil {
				rotations.Add(1)
			} else if !errors.Is(err, oauthserver.ErrConflict) {
				t.Errorf("rotate: %v", err)
			}
		}()
	}

	wg.Wait()

	if codes.Load() != 1 || rotations.Load() != 1 {
		t.Fatalf("winners: codes=%d rotations=%d, want 1 and 1", codes.Load(), rotations.Load())
	}
}
