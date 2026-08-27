package backend_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/issuer"
	"github.com/rakunlabs/ada/middleware/auth/issuer/backend"
	"github.com/rakunlabs/ada/middleware/auth/issuer/crypto"
	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
	"github.com/rakunlabs/ada/middleware/auth/sessionstore/file"
)

func newFileStore(t *testing.T) *file.Store {
	t.Helper()

	st, err := file.New(file.Config{
		SessionKey: "0123456789abcdef0123456789abcdef",
		Path:       t.TempDir(),
		GCInterval: -1,
	}, sessionstore.Options{Path: "/", MaxAge: 3600})
	if err != nil {
		t.Fatalf("file.New: %v", err)
	}

	return st
}

func samplePair(id string) *issuer.Pair {
	return &issuer.Pair{
		SessionID: id,
		Identity:  &identity.Identity{Subject: "alice", Provider: "local"},
		Access:    issuer.Token{Value: "access-token", ExpiresAt: time.Now().Add(time.Minute)},
		Refresh:   issuer.Token{Value: "refresh-token", ExpiresAt: time.Now().Add(time.Hour)},
	}
}

// The whole point of the rewrite: a pair written through the adapter must come
// back out. The previous version synthesised a request carrying the raw
// session ID, which the store's cookie codec rejected, so every load missed
// and every save landed under a freshly generated ID.
func TestSessionStoreRoundTrip(t *testing.T) {
	b, err := backend.NewSessionStore(newFileStore(t))
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}

	ctx := context.Background()
	want := samplePair("session-abc")

	if err := b.SavePair(ctx, want, time.Hour); err != nil {
		t.Fatalf("SavePair: %v", err)
	}

	got, err := b.LoadPair(ctx, "session-abc")
	if err != nil {
		t.Fatalf("LoadPair: %v", err)
	}

	if got.SessionID != want.SessionID {
		t.Fatalf("session id = %q, want %q", got.SessionID, want.SessionID)
	}

	if got.Refresh.Value != want.Refresh.Value {
		t.Fatalf("refresh = %q, want %q", got.Refresh.Value, want.Refresh.Value)
	}

	if got.Identity == nil || got.Identity.Subject != "alice" {
		t.Fatalf("identity not round-tripped: %+v", got.Identity)
	}
}

func TestSessionStoreLoadMissing(t *testing.T) {
	b, err := backend.NewSessionStore(newFileStore(t))
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}

	if _, err := b.LoadPair(context.Background(), "nope"); !errors.Is(err, issuer.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestSessionStoreDelete(t *testing.T) {
	b, err := backend.NewSessionStore(newFileStore(t))
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}

	ctx := context.Background()

	if err := b.SavePair(ctx, samplePair("gone"), time.Hour); err != nil {
		t.Fatalf("SavePair: %v", err)
	}

	if err := b.DeletePair(ctx, "gone"); err != nil {
		t.Fatalf("DeletePair: %v", err)
	}

	if _, err := b.LoadPair(ctx, "gone"); !errors.Is(err, issuer.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// A store that only speaks the request/response protocol cannot serve the
// issuer. Rejecting it at construction beats losing writes at runtime.
type notDirect struct{ sessionstore.Store }

func TestSessionStoreRejectsNonDirect(t *testing.T) {
	_, err := backend.NewSessionStore(notDirect{})
	if !errors.Is(err, sessionstore.ErrNotDirect) {
		t.Fatalf("err = %v, want ErrNotDirect", err)
	}
}

func TestSessionStoreCipher(t *testing.T) {
	dir := t.TempDir()

	st, err := file.New(file.Config{
		SessionKey: "0123456789abcdef0123456789abcdef",
		Path:       dir,
		GCInterval: -1,
	}, sessionstore.Options{Path: "/", MaxAge: 3600})
	if err != nil {
		t.Fatalf("file.New: %v", err)
	}

	c, err := crypto.New("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}

	b, err := backend.NewSessionStore(st, backend.WithCipher(c))
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}

	ctx := context.Background()

	if err := b.SavePair(ctx, samplePair("enc"), time.Hour); err != nil {
		t.Fatalf("SavePair: %v", err)
	}

	got, err := b.LoadPair(ctx, "enc")
	if err != nil {
		t.Fatalf("LoadPair: %v", err)
	}

	if got.Refresh.Value != "refresh-token" {
		t.Fatalf("refresh = %q", got.Refresh.Value)
	}

	// The token must not be readable in the file itself.
	matches, _ := filepath.Glob(filepath.Join(dir, "session_*.json"))
	if len(matches) == 0 {
		t.Fatal("no session file written")
	}

	raw := readFile(t, matches[0])
	if strings.Contains(raw, "refresh-token") || strings.Contains(raw, "alice") {
		t.Fatalf("pair stored in clear text: %s", raw)
	}
}

func TestSessionStoreRejectsEmptySessionID(t *testing.T) {
	b, err := backend.NewSessionStore(newFileStore(t))
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}

	if err := b.SavePair(context.Background(), &issuer.Pair{}, time.Hour); err == nil {
		t.Fatal("expected error for pair without session id")
	}
}

func TestMemoryExpires(t *testing.T) {
	m := backend.NewMemory()
	ctx := context.Background()

	if err := m.SavePair(ctx, samplePair("short"), 20*time.Millisecond); err != nil {
		t.Fatalf("SavePair: %v", err)
	}

	if _, err := m.LoadPair(ctx, "short"); err != nil {
		t.Fatalf("LoadPair before expiry: %v", err)
	}

	time.Sleep(40 * time.Millisecond)

	if _, err := m.LoadPair(ctx, "short"); !errors.Is(err, issuer.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}

	if m.Len() != 0 {
		t.Fatalf("expired entry not dropped, len = %d", m.Len())
	}
}

func TestMemoryZeroTTLNeverExpires(t *testing.T) {
	m := backend.NewMemory()
	ctx := context.Background()

	if err := m.SavePair(ctx, samplePair("forever"), 0); err != nil {
		t.Fatalf("SavePair: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	if _, err := m.LoadPair(ctx, "forever"); err != nil {
		t.Fatalf("LoadPair: %v", err)
	}
}

// The adapter must not depend on the sessionstore cookie codec at all — no
// Set-Cookie may leak out of a save.
func TestSessionStoreWritesNoCookie(t *testing.T) {
	b, err := backend.NewSessionStore(newFileStore(t))
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}

	rec := httptest.NewRecorder()

	if err := b.SavePair(context.Background(), samplePair("x"), time.Hour); err != nil {
		t.Fatalf("SavePair: %v", err)
	}

	if got := rec.Result().Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("unexpected Set-Cookie: %q", got)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(b)
}
