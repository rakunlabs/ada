//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd

package file

import (
	"context"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
)

func TestExpiredLoadDoesNotDeleteConcurrentSave(t *testing.T) {
	dir := t.TempDir()
	newTestStore := func() *Store {
		store, err := New(Config{
			SessionKey: "0123456789abcdef0123456789abcdef",
			Path:       dir,
			GCInterval: -1,
		}, sessionstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })

		return store
	}

	writer := newTestStore()
	reader := newTestStore()
	now := time.Unix(1_000, 0)
	writer.now = func() time.Time { return now }
	reader.now = func() time.Time { return now }
	if err := writer.SaveByID(context.Background(), "race", map[string]any{"value": "expired"}, time.Second); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)

	unlock, err := writer.lockTransaction(context.Background(), "race")
	if err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()

	type loadResult struct {
		values map[string]any
		err    error
	}
	result := make(chan loadResult, 1)
	go func() {
		values, err := reader.LoadByID(context.Background(), "race")
		result <- loadResult{values: values, err: err}
	}()

	select {
	case got := <-result:
		t.Fatalf("expired load completed before the session lock was released: values=%v err=%v", got.values, got.err)
	case <-time.After(50 * time.Millisecond):
	}

	data, err := writer.marshalRecord(map[string]any{"value": "fresh"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.writeRecord("race", data); err != nil {
		t.Fatal(err)
	}
	unlock()
	locked = false

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("LoadByID() error = %v, want concurrent value", got.err)
		}
		if got.values["value"] != "fresh" {
			t.Fatalf("LoadByID() values = %v, want fresh concurrent value", got.values)
		}
	case <-time.After(time.Second):
		t.Fatal("LoadByID() remained blocked after the session lock was released")
	}
}

func TestTransactionPreservesExactOnDiskExpiry(t *testing.T) {
	store, err := New(Config{
		SessionKey: "0123456789abcdef0123456789abcdef",
		Path:       t.TempDir(),
		GCInterval: -1,
	}, sessionstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Unix(1_000, 0)
	store.now = func() time.Time { return now }
	ctx := context.Background()

	for _, ttl := range []time.Duration{0, -time.Second} {
		id := "preserve-zero"
		if ttl < 0 {
			id = "preserve-negative"
		}
		if err := store.SaveByID(ctx, id, map[string]any{"value": "original"}, 2*time.Hour); err != nil {
			t.Fatal(err)
		}
		before, err := store.readRecord(id)
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(30 * time.Minute)

		_, err = store.TransactByID(ctx, id, ttl, func(current map[string]any) (map[string]any, bool, error) {
			current["value"] = "updated"

			return current, true, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		after, err := store.readRecord(id)
		if err != nil {
			t.Fatal(err)
		}
		if after.ExpiresAt != before.ExpiresAt {
			t.Fatalf("ttl %v changed ExpiresAt from %d to %d", ttl, before.ExpiresAt, after.ExpiresAt)
		}
	}
}
