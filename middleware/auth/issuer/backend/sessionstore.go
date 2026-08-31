// Package backend wires the issuer to the sessionstore backends (file, redis)
// and provides an in-memory backend for tests and single-process deployments.
package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/issuer"
	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
)

// SessionStore is an issuer.Backend backed by a sessionstore.DirectStore.
//
// The issuer owns its own session IDs and has no request/response pair to hand
// to Store.Get/Store.Save, so the store must be able to read and write by raw
// ID. Both the file and redis stores implement sessionstore.DirectStore.
//
// The pair is stored as a single JSON blob under Values["pair"].
type SessionStore struct {
	store  sessionstore.DirectStore
	cipher issuer.Cipher
}

var _ issuer.AtomicBackend = (*SessionStore)(nil)

const pairKey = "pair"

// NewSessionStore wraps a sessionstore.Store for the issuer.
//
// It returns sessionstore.ErrNotDirect if the store cannot address records by
// raw session ID. Driving a codec-based store through a synthesized request
// silently loses every write, so this is a hard error rather than a fallback.
func NewSessionStore(store sessionstore.Store, opts ...SessionStoreOption) (*SessionStore, error) {
	direct, ok := store.(sessionstore.DirectStore)
	if !ok {
		return nil, fmt.Errorf("%w: %T", sessionstore.ErrNotDirect, store)
	}

	s := &SessionStore{store: direct}
	for _, o := range opts {
		o(s)
	}

	return s, nil
}

// SessionStoreOption configures a SessionStore.
type SessionStoreOption func(*SessionStore)

// WithCipher encrypts the stored pair at rest. Without it the pair — which
// holds both live tokens and the full identity — is persisted as plain JSON.
func WithCipher(c issuer.Cipher) SessionStoreOption {
	return func(s *SessionStore) { s.cipher = c }
}

// LoadPair retrieves the pair by sessionID.
func (s *SessionStore) LoadPair(ctx context.Context, sessionID string) (*issuer.Pair, error) {
	values, err := s.store.LoadByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, sessionstore.ErrNoSession) {
			return nil, issuer.ErrNotFound
		}

		return nil, fmt.Errorf("backend: load: %w", err)
	}

	return s.decodePair(sessionID, values)
}

func (s *SessionStore) decodePair(sessionID string, values map[string]any) (*issuer.Pair, error) {
	raw, ok := values[pairKey].(string)
	if !ok || raw == "" {
		return nil, issuer.ErrNotFound
	}

	blob := []byte(raw)

	if s.cipher != nil {
		var err error
		if c, ok := s.cipher.(issuer.AssociatedDataCipher); ok {
			blob, err = c.DecryptWithAssociatedData(blob, []byte(sessionID))
		} else {
			blob, err = s.cipher.Decrypt(blob)
		}
		if err != nil {
			return nil, fmt.Errorf("backend: decrypt pair: %w", err)
		}
	}

	var p issuer.Pair
	if err := json.Unmarshal(blob, &p); err != nil {
		return nil, fmt.Errorf("backend: decode pair: %w", err)
	}
	if p.SessionID != sessionID {
		return nil, fmt.Errorf("backend: decoded pair session id %q does not match storage key %q", p.SessionID, sessionID)
	}

	return &p, nil
}

// SavePair persists a pair under its session ID.
func (s *SessionStore) SavePair(ctx context.Context, p *issuer.Pair, ttl time.Duration) error {
	values, err := s.encodePair(p)
	if err != nil {
		return err
	}

	if err := s.store.SaveByID(ctx, p.SessionID, values, ttl); err != nil {
		return fmt.Errorf("backend: save: %w", err)
	}

	return nil
}

func (s *SessionStore) encodePair(p *issuer.Pair) (map[string]any, error) {
	if p == nil || p.SessionID == "" {
		return nil, fmt.Errorf("backend: pair without session id")
	}

	blob, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}

	if s.cipher != nil {
		if c, ok := s.cipher.(issuer.AssociatedDataCipher); ok {
			blob, err = c.EncryptWithAssociatedData(blob, []byte(p.SessionID))
		} else {
			blob, err = s.cipher.Encrypt(blob)
		}
		if err != nil {
			return nil, fmt.Errorf("backend: encrypt pair: %w", err)
		}
	}

	return map[string]any{pairKey: string(blob)}, nil
}

// DeletePair removes the pair.
func (s *SessionStore) DeletePair(ctx context.Context, sessionID string) error {
	if err := s.store.DeleteByID(ctx, sessionID); err != nil {
		return fmt.Errorf("backend: delete: %w", err)
	}

	return nil
}

// AtomicTransactionsSupported reports whether the wrapped DirectStore offers
// a transaction primitive. Legacy stores remain usable through Default's
// process-local fallback.
func (s *SessionStore) AtomicTransactionsSupported() bool {
	_, ok := s.store.(sessionstore.AtomicDirectStore)

	return ok
}

// TransactPair adapts sessionstore.AtomicDirectStore to issuer.AtomicBackend,
// including its ttl <= 0 expiry-preservation semantics.
func (s *SessionStore) TransactPair(
	ctx context.Context,
	sessionID string,
	ttl time.Duration,
	fn issuer.PairTransaction,
) (*issuer.Pair, error) {
	store, ok := s.store.(sessionstore.AtomicDirectStore)
	if !ok {
		return nil, fmt.Errorf("backend: atomic transactions unavailable")
	}

	var result *issuer.Pair
	_, err := store.TransactByID(ctx, sessionID, ttl, func(values map[string]any) (map[string]any, bool, error) {
		current, err := s.decodePair(sessionID, values)
		if err != nil {
			return nil, false, err
		}

		replacement, commit, txErr := fn(current)
		if !commit {
			return nil, false, txErr
		}
		if replacement == nil {
			result = nil

			return nil, true, txErr
		}
		if replacement.SessionID != sessionID {
			return nil, false, fmt.Errorf("backend: transaction changed session id")
		}

		replacementValues, err := s.encodePair(replacement)
		if err != nil {
			return nil, false, err
		}
		result = replacement

		return replacementValues, true, txErr
	})
	if err != nil {
		if errors.Is(err, sessionstore.ErrNoSession) {
			return nil, issuer.ErrNotFound
		}
		if errors.Is(err, sessionstore.ErrTransactionConflict) {
			return nil, issuer.ErrTransactionConflict
		}

		return nil, err
	}

	return result, nil
}

// Memory is an in-process Backend used in tests and as the default when no
// store is configured. Entries honour the TTL passed to SavePair, so an
// abandoned session does not pin memory for the lifetime of the process.
type Memory struct {
	mu    sync.RWMutex
	pairs map[string]memoryEntry
	keyMu sync.Mutex
	keys  map[string]*memoryKeyLock

	now func() time.Time
}

var _ issuer.AtomicBackend = (*Memory)(nil)

type memoryKeyLock struct {
	mu   sync.Mutex
	refs int
}

type memoryEntry struct {
	pair      *issuer.Pair
	expiresAt time.Time
}

// NewMemory returns an empty in-memory backend.
func NewMemory() *Memory {
	return &Memory{
		pairs: make(map[string]memoryEntry),
		keys:  make(map[string]*memoryKeyLock),
		now:   time.Now,
	}
}

// LoadPair returns a copy of the pair for sessionID, or issuer.ErrNotFound.
// Always returns a clone so callers can mutate the returned Pair freely
// without affecting the stored value.
func (m *Memory) LoadPair(_ context.Context, sessionID string) (*issuer.Pair, error) {
	m.mu.RLock()
	e, ok := m.pairs[sessionID]
	m.mu.RUnlock()

	if !ok {
		return nil, issuer.ErrNotFound
	}

	if !e.expiresAt.IsZero() && !m.now().Before(e.expiresAt) {
		unlock := m.lockPair(sessionID)
		defer unlock()

		m.mu.Lock()
		if cur, still := m.pairs[sessionID]; still && !cur.expiresAt.IsZero() && !m.now().Before(cur.expiresAt) {
			delete(m.pairs, sessionID)
		}
		m.mu.Unlock()

		return nil, issuer.ErrNotFound
	}

	return clonePair(e.pair), nil
}

// SavePair stores a clone of the pair, expiring it after ttl. A ttl of zero
// means "never expire".
func (m *Memory) SavePair(_ context.Context, p *issuer.Pair, ttl time.Duration) error {
	if p == nil || p.SessionID == "" {
		return fmt.Errorf("backend: pair without session id")
	}

	unlock := m.lockPair(p.SessionID)
	defer unlock()

	e := memoryEntry{pair: clonePair(p)}
	if ttl > 0 {
		e.expiresAt = m.now().Add(ttl)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.pairs[p.SessionID] = e

	// Opportunistic sweep: bounded work, keeps an idle-but-written-to backend
	// from growing without limit.
	m.sweepLocked()

	return nil
}

// AtomicTransactionsSupported reports true for Memory. Transactions are
// serialized per session ID, not through one global operation lock.
func (m *Memory) AtomicTransactionsSupported() bool { return true }

// TransactPair implements issuer.AtomicBackend. A non-positive TTL preserves
// the current memoryEntry expiry for a committed replacement.
func (m *Memory) TransactPair(
	_ context.Context,
	sessionID string,
	ttl time.Duration,
	fn issuer.PairTransaction,
) (*issuer.Pair, error) {
	if sessionID == "" {
		return nil, issuer.ErrNotFound
	}

	unlock := m.lockPair(sessionID)
	defer unlock()

	m.mu.RLock()
	entry, ok := m.pairs[sessionID]
	m.mu.RUnlock()
	if !ok || (!entry.expiresAt.IsZero() && !m.now().Before(entry.expiresAt)) {
		if ok {
			m.mu.Lock()
			delete(m.pairs, sessionID)
			m.mu.Unlock()
		}

		return nil, issuer.ErrNotFound
	}

	replacement, commit, txErr := fn(clonePair(entry.pair))
	if !commit {
		return nil, txErr
	}
	if replacement != nil && replacement.SessionID != sessionID {
		return nil, fmt.Errorf("backend: transaction changed session id")
	}

	m.mu.Lock()
	if replacement == nil {
		delete(m.pairs, sessionID)
	} else {
		next := memoryEntry{pair: clonePair(replacement), expiresAt: entry.expiresAt}
		if ttl > 0 {
			next.expiresAt = m.now().Add(ttl)
		}
		m.pairs[sessionID] = next
		m.sweepLocked()
	}
	m.mu.Unlock()

	return clonePair(replacement), txErr
}

func (m *Memory) lockPair(sessionID string) func() {
	m.keyMu.Lock()
	lock := m.keys[sessionID]
	if lock == nil {
		lock = &memoryKeyLock{}
		m.keys[sessionID] = lock
	}
	lock.refs++
	m.keyMu.Unlock()

	lock.mu.Lock()

	return func() {
		lock.mu.Unlock()

		m.keyMu.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(m.keys, sessionID)
		}
		m.keyMu.Unlock()
	}
}

const memorySweepBudget = 32

func (m *Memory) sweepLocked() {
	now := m.now()
	n := 0

	for id, e := range m.pairs {
		if n >= memorySweepBudget {
			return
		}

		n++

		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(m.pairs, id)
		}
	}
}

// Len reports the number of live entries. Intended for tests and metrics.
func (m *Memory) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.pairs)
}

func clonePair(p *issuer.Pair) *issuer.Pair {
	if p == nil {
		return nil
	}

	cp := *p

	if p.Identity != nil {
		idCopy := *p.Identity
		idCopy.Roles = append([]string(nil), p.Identity.Roles...)
		idCopy.Scopes = append([]string(nil), p.Identity.Scopes...)
		idCopy.Claims = cloneClaims(p.Identity.Claims)
		cp.Identity = &idCopy
	}

	return &cp
}

func cloneClaims(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}

	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = cloneClaimValue(value)
	}

	return out
}

func cloneClaimValue(value any) any {
	if value == nil {
		return nil
	}

	return cloneClaimReflect(reflect.ValueOf(value)).Interface()
}

func cloneClaimReflect(value reflect.Value) reflect.Value {
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}

		out := reflect.New(value.Type()).Elem()
		out.Set(cloneClaimReflect(value.Elem()))

		return out
	case reflect.Map:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}

		out := reflect.MakeMapWithSize(value.Type(), value.Len())
		iter := value.MapRange()
		for iter.Next() {
			out.SetMapIndex(iter.Key(), cloneClaimReflect(iter.Value()))
		}

		return out
	case reflect.Slice:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}

		out := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		for i := range value.Len() {
			out.Index(i).Set(cloneClaimReflect(value.Index(i)))
		}

		return out
	case reflect.Array:
		out := reflect.New(value.Type()).Elem()
		for i := range value.Len() {
			out.Index(i).Set(cloneClaimReflect(value.Index(i)))
		}

		return out
	case reflect.Pointer:
		if value.IsNil() {
			return reflect.Zero(value.Type())
		}

		out := reflect.New(value.Type().Elem())
		out.Elem().Set(cloneClaimReflect(value.Elem()))

		return out
	case reflect.Struct:
		out := reflect.New(value.Type()).Elem()
		out.Set(value)
		for i := range value.NumField() {
			if out.Field(i).CanSet() && value.Field(i).CanInterface() {
				out.Field(i).Set(cloneClaimReflect(value.Field(i)))
			}
		}

		return out
	default:
		return value
	}
}

// DeletePair removes the pair.
func (m *Memory) DeletePair(_ context.Context, sessionID string) error {
	unlock := m.lockPair(sessionID)
	defer unlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.pairs, sessionID)

	return nil
}
