// Package backend wires the issuer to the sessionstore backends (file, redis)
// and provides an in-memory backend for tests and single-process deployments.
package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	raw, ok := values[pairKey].(string)
	if !ok || raw == "" {
		return nil, issuer.ErrNotFound
	}

	blob := []byte(raw)

	if s.cipher != nil {
		blob, err = s.cipher.Decrypt(blob)
		if err != nil {
			return nil, fmt.Errorf("backend: decrypt pair: %w", err)
		}
	}

	var p issuer.Pair
	if err := json.Unmarshal(blob, &p); err != nil {
		return nil, fmt.Errorf("backend: decode pair: %w", err)
	}

	return &p, nil
}

// SavePair persists a pair under its session ID.
func (s *SessionStore) SavePair(ctx context.Context, p *issuer.Pair, ttl time.Duration) error {
	if p == nil || p.SessionID == "" {
		return fmt.Errorf("backend: pair without session id")
	}

	blob, err := json.Marshal(p)
	if err != nil {
		return err
	}

	if s.cipher != nil {
		blob, err = s.cipher.Encrypt(blob)
		if err != nil {
			return fmt.Errorf("backend: encrypt pair: %w", err)
		}
	}

	values := map[string]any{pairKey: string(blob)}

	if err := s.store.SaveByID(ctx, p.SessionID, values, ttl); err != nil {
		return fmt.Errorf("backend: save: %w", err)
	}

	return nil
}

// DeletePair removes the pair.
func (s *SessionStore) DeletePair(ctx context.Context, sessionID string) error {
	if err := s.store.DeleteByID(ctx, sessionID); err != nil {
		return fmt.Errorf("backend: delete: %w", err)
	}

	return nil
}

// Memory is an in-process Backend used in tests and as the default when no
// store is configured. Entries honour the TTL passed to SavePair, so an
// abandoned session does not pin memory for the lifetime of the process.
type Memory struct {
	mu    sync.RWMutex
	pairs map[string]memoryEntry

	now func() time.Time
}

type memoryEntry struct {
	pair      *issuer.Pair
	expiresAt time.Time
}

// NewMemory returns an empty in-memory backend.
func NewMemory() *Memory {
	return &Memory{pairs: make(map[string]memoryEntry), now: time.Now}
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
		m.mu.Lock()
		// Re-check: a concurrent SavePair may have refreshed the entry.
		if cur, still := m.pairs[sessionID]; still && cur.expiresAt.Equal(e.expiresAt) {
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
		cp.Identity = &idCopy
	}

	return &cp
}

// DeletePair removes the pair.
func (m *Memory) DeletePair(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.pairs, sessionID)

	return nil
}
