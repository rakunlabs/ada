package backend_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

type atomicDirectStore struct {
	mu                 sync.Mutex
	values             map[string]map[string]any
	lastTransactionTTL time.Duration
}

func newAtomicDirectStore() *atomicDirectStore {
	return &atomicDirectStore{values: make(map[string]map[string]any)}
}

func (*atomicDirectStore) Get(*http.Request, string) (*sessionstore.Session, error) { return nil, nil }
func (*atomicDirectStore) Save(*http.Request, http.ResponseWriter, *sessionstore.Session) error {
	return nil
}
func (s *atomicDirectStore) LoadByID(_ context.Context, id string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	values, ok := s.values[id]
	if !ok {
		return nil, sessionstore.ErrNoSession
	}

	return cloneValues(values), nil
}
func (s *atomicDirectStore) SaveByID(_ context.Context, id string, values map[string]any, _ time.Duration) error {
	s.mu.Lock()
	s.values[id] = cloneValues(values)
	s.mu.Unlock()

	return nil
}
func (s *atomicDirectStore) DeleteByID(_ context.Context, id string) error {
	s.mu.Lock()
	delete(s.values, id)
	s.mu.Unlock()

	return nil
}
func (s *atomicDirectStore) TransactByID(
	_ context.Context,
	id string,
	ttl time.Duration,
	fn sessionstore.AtomicTransaction,
) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastTransactionTTL = ttl

	values, ok := s.values[id]
	if !ok {
		return nil, sessionstore.ErrNoSession
	}

	replacement, commit, err := fn(cloneValues(values))
	if commit {
		if replacement == nil {
			delete(s.values, id)
		} else {
			s.values[id] = cloneValues(replacement)
		}
	}

	return cloneValues(replacement), err
}

func (s *atomicDirectStore) transactionTTL() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.lastTransactionTTL
}

func cloneValues(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}

	clone := make(map[string]any, len(values))
	for key, value := range values {
		clone[key] = value
	}

	return clone
}

func TestSessionStoreAdaptsAtomicDirectStore(t *testing.T) {
	store := newAtomicDirectStore()
	b, err := backend.NewSessionStore(store)
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	if !b.AtomicTransactionsSupported() {
		t.Fatal("atomic direct store capability was not preserved")
	}

	first := issuer.NewDefault(b, issuer.Config{})
	second := issuer.NewDefault(b, issuer.Config{})
	pair, err := first.Issue(context.Background(), &identity.Identity{
		Subject: "alice",
		Claims:  map[string]any{"updates": 0},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	const updates = 50
	var wg sync.WaitGroup
	for i := range updates {
		current := first
		if i%2 != 0 {
			current = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := current.Update(context.Background(), pair.SessionID, func(id *identity.Identity) error {
				count := int(id.Claims["updates"].(float64))
				id.Claims["updates"] = count + 1

				return nil
			})
			if err != nil {
				t.Errorf("update: %v", err)
			}
		}()
	}
	wg.Wait()

	stored, err := first.Resolve(context.Background(), pair.SessionID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := int(stored.Identity.Claims["updates"].(float64)); got != updates {
		t.Fatalf("updates = %d, want %d", got, updates)
	}
	if ttl := store.transactionTTL(); ttl != 0 {
		t.Fatalf("adapter transaction TTL = %v, want preservation sentinel", ttl)
	}
}

type conflictingDirectStore struct {
	*atomicDirectStore
	callbackCalls int
}

func (s *conflictingDirectStore) TransactByID(
	ctx context.Context,
	id string,
	_ time.Duration,
	fn sessionstore.AtomicTransaction,
) (map[string]any, error) {
	current, err := s.LoadByID(ctx, id)
	if err != nil {
		return nil, err
	}
	s.callbackCalls++
	if _, _, err := fn(current); err != nil {
		return nil, err
	}

	return nil, sessionstore.ErrTransactionConflict
}

func TestSessionStoreMapsConflictWithoutRetryingUpdater(t *testing.T) {
	store := &conflictingDirectStore{atomicDirectStore: newAtomicDirectStore()}
	b, err := backend.NewSessionStore(store)
	if err != nil {
		t.Fatal(err)
	}
	iss := issuer.NewDefault(b, issuer.Config{})
	pair, err := iss.Issue(context.Background(), &identity.Identity{Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}

	updateCalls := 0
	_, err = iss.Update(context.Background(), pair.SessionID, func(id *identity.Identity) error {
		updateCalls++
		id.Subject = "changed"

		return nil
	})
	if !errors.Is(err, issuer.ErrTransactionConflict) {
		t.Fatalf("Update() error = %v, want issuer conflict", err)
	}
	if store.callbackCalls != 1 || updateCalls != 1 {
		t.Fatalf("adapter callbacks = %d, updater callbacks = %d, want 1 each", store.callbackCalls, updateCalls)
	}
	stored, err := iss.Resolve(context.Background(), pair.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Identity.Subject != "alice" {
		t.Fatalf("conflicted replacement was stored: %+v", stored.Identity)
	}
}

func TestNamespaceIsolatesStorageKeysAndTransactions(t *testing.T) {
	memory := backend.NewMemory()
	namespaced, err := backend.NewNamespace(memory, "mfa")
	if err != nil {
		t.Fatalf("NewNamespace: %v", err)
	}
	if !namespaced.AtomicTransactionsSupported() {
		t.Fatal("namespace dropped atomic capability")
	}

	pair := samplePair("pending-id")
	if err := namespaced.SavePair(context.Background(), pair, time.Hour); err != nil {
		t.Fatalf("SavePair: %v", err)
	}
	if _, err := memory.LoadPair(context.Background(), pair.SessionID); !errors.Is(err, issuer.ErrNotFound) {
		t.Fatalf("raw pending ID resolved in shared backend: %v", err)
	}
	loaded, err := namespaced.LoadPair(context.Background(), pair.SessionID)
	if err != nil || loaded.SessionID != pair.SessionID {
		t.Fatalf("namespaced load = %+v, %v", loaded, err)
	}

	updated, err := namespaced.TransactPair(context.Background(), pair.SessionID, time.Hour,
		func(current *issuer.Pair) (*issuer.Pair, bool, error) {
			current.Identity.Name = "updated"

			return current, true, nil
		})
	if err != nil || updated.Identity.Name != "updated" {
		t.Fatalf("transaction = %+v, %v", updated, err)
	}

	pendingIssuer := issuer.NewDefault(namespaced, issuer.Config{})
	normalIssuer := issuer.NewDefault(memory, issuer.Config{})
	issued, err := pendingIssuer.Issue(context.Background(), &identity.Identity{Subject: "pending"})
	if err != nil {
		t.Fatalf("issue pending: %v", err)
	}
	if _, err := normalIssuer.Resolve(context.Background(), issued.SessionID); !errors.Is(err, issuer.ErrNotFound) {
		t.Fatalf("normal issuer resolved pending ID: %v", err)
	}
	if _, err := normalIssuer.Resolve(context.Background(), "mfa~"+issued.SessionID); !errors.Is(err, issuer.ErrNotFound) {
		t.Fatalf("normal issuer accepted namespaced storage key: %v", err)
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

func TestSessionStoreRejectsPairStoredUnderDifferentKey(t *testing.T) {
	store := newFileStore(t)
	b, err := backend.NewSessionStore(store)
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}

	ctx := context.Background()
	if err := b.SavePair(ctx, samplePair("original"), time.Hour); err != nil {
		t.Fatalf("SavePair: %v", err)
	}
	values, err := store.LoadByID(ctx, "original")
	if err != nil {
		t.Fatalf("LoadByID: %v", err)
	}
	if err := store.SaveByID(ctx, "substituted", values, time.Hour); err != nil {
		t.Fatalf("SaveByID: %v", err)
	}

	if _, err := b.LoadPair(ctx, "substituted"); err == nil {
		t.Fatal("pair whose decoded session ID differs from its storage key was accepted")
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

func TestSessionStoreCipherBindsStorageKey(t *testing.T) {
	store := newFileStore(t)
	c, err := crypto.New("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	b, err := backend.NewSessionStore(store, backend.WithCipher(c))
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}

	ctx := context.Background()
	if err := b.SavePair(ctx, samplePair("original"), time.Hour); err != nil {
		t.Fatalf("SavePair: %v", err)
	}
	values, err := store.LoadByID(ctx, "original")
	if err != nil {
		t.Fatalf("LoadByID: %v", err)
	}
	if err := store.SaveByID(ctx, "substituted", values, time.Hour); err != nil {
		t.Fatalf("SaveByID: %v", err)
	}

	if _, err := b.LoadPair(ctx, "substituted"); err == nil {
		t.Fatal("ciphertext moved to a different storage key decrypted successfully")
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

func TestMemoryDeepClonesIdentityCollections(t *testing.T) {
	m := backend.NewMemory()
	pair := samplePair("clone")
	pair.Identity.Roles = []string{"admin"}
	pair.Identity.Scopes = []string{"read"}
	pair.Identity.Claims = map[string]any{
		"profile": map[string]any{"name": "Alice"},
		"groups":  []any{"engineering", map[string]any{"level": "staff"}},
		"labels":  []string{"one"},
	}

	if err := m.SavePair(context.Background(), pair, time.Hour); err != nil {
		t.Fatalf("SavePair: %v", err)
	}

	pair.Identity.Roles[0] = "mutated"
	pair.Identity.Scopes[0] = "mutated"
	pair.Identity.Claims["profile"].(map[string]any)["name"] = "Mutated"
	pair.Identity.Claims["groups"].([]any)[1].(map[string]any)["level"] = "mutated"
	pair.Identity.Claims["labels"].([]string)[0] = "mutated"

	first, err := m.LoadPair(context.Background(), "clone")
	if err != nil {
		t.Fatalf("LoadPair: %v", err)
	}
	assertUnmutatedIdentity(t, first.Identity)

	first.Identity.Roles[0] = "changed again"
	first.Identity.Scopes[0] = "changed again"
	first.Identity.Claims["profile"].(map[string]any)["name"] = "Changed again"
	first.Identity.Claims["groups"].([]any)[1].(map[string]any)["level"] = "changed again"
	first.Identity.Claims["labels"].([]string)[0] = "changed again"

	second, err := m.LoadPair(context.Background(), "clone")
	if err != nil {
		t.Fatalf("second LoadPair: %v", err)
	}
	assertUnmutatedIdentity(t, second.Identity)
}

func assertUnmutatedIdentity(t *testing.T, id *identity.Identity) {
	t.Helper()

	if id.Roles[0] != "admin" || id.Scopes[0] != "read" {
		t.Fatalf("roles/scopes aliased: %+v", id)
	}
	if id.Claims["profile"].(map[string]any)["name"] != "Alice" ||
		id.Claims["groups"].([]any)[1].(map[string]any)["level"] != "staff" ||
		id.Claims["labels"].([]string)[0] != "one" {
		t.Fatalf("claims aliased: %+v", id.Claims)
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
