// Package backend wires the issuer to the existing sessionstore backends
// (cookie/file/redis). Each adapter exposes a Backend that the default issuer
// can call without knowing the underlying storage.
package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/issuer"
	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
)

// SessionStore is an issuer.Backend backed by a sessionstore.Store. It works
// for stores that key values by an opaque cookie name (file, redis); the
// cookie-only store needs a different adapter (CookieOnly below).
//
// The pair is stored as a single JSON blob under sessionstore.Session.Values
// keyed by "pair".
type SessionStore struct {
	store      sessionstore.Store
	cookieName string
}

const pairKey = "pair"

// NewSessionStore wraps a sessionstore.Store for the issuer. cookieName is the
// session cookie name; the issuer's session ID is mapped to a "fake" request
// cookie when reading and a Set-Cookie is issued when saving.
//
// Note: this adapter is awkward for the issuer pattern because sessionstore
// expects a *http.Request to extract the cookie. We keep the existing store
// for redis/file but provide a richer Direct backend that works without an
// HTTP request (issuer/backend/memory.go) for tests.
func NewSessionStore(store sessionstore.Store, cookieName string) *SessionStore {
	return &SessionStore{store: store, cookieName: cookieName}
}

// LoadPair retrieves the pair by sessionID. It synthesizes a request carrying
// the sessionID as the session cookie so the underlying store can decode it.
func (s *SessionStore) LoadPair(ctx context.Context, sessionID string) (*issuer.Pair, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	if err != nil {
		return nil, err
	}

	r.AddCookie(&http.Cookie{Name: s.cookieName, Value: sessionID})

	sess, err := s.store.Get(r, s.cookieName)
	if err != nil || sess == nil || sess.IsNew {
		return nil, issuer.ErrNotFound
	}

	raw, ok := sess.Values[pairKey].(string)
	if !ok || raw == "" {
		return nil, issuer.ErrNotFound
	}

	var p issuer.Pair
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, fmt.Errorf("backend: decode pair: %w", err)
	}

	return &p, nil
}

// SavePair persists a pair. The underlying sessionstore writes a Set-Cookie on
// the synthesized response — we discard that header because the auth
// middleware writes the real cookie itself with the issuer's SessionID.
func (s *SessionStore) SavePair(ctx context.Context, p *issuer.Pair, _ time.Duration) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}

	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	if err != nil {
		return err
	}

	r.AddCookie(&http.Cookie{Name: s.cookieName, Value: p.SessionID})

	sess, _ := s.store.Get(r, s.cookieName)
	if sess == nil {
		return fmt.Errorf("backend: store returned nil session")
	}

	sess.Values[pairKey] = string(raw)

	// The store needs a writer to set its cookie; we hand it a discard writer.
	if err := s.store.Save(r, discardWriter{}, sess); err != nil {
		return fmt.Errorf("backend: save: %w", err)
	}

	return nil
}

// DeletePair removes the pair.
func (s *SessionStore) DeletePair(ctx context.Context, sessionID string) error {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	if err != nil {
		return err
	}

	r.AddCookie(&http.Cookie{Name: s.cookieName, Value: sessionID})

	sess, err := s.store.Get(r, s.cookieName)
	if err != nil || sess == nil || sess.IsNew {
		return nil
	}

	sess.Options.MaxAge = -1

	return s.store.Save(r, discardWriter{}, sess)
}

// discardWriter implements http.ResponseWriter and ignores all writes.
type discardWriter struct{ headers http.Header }

func (d discardWriter) Header() http.Header {
	if d.headers == nil {
		return http.Header{}
	}

	return d.headers
}
func (d discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d discardWriter) WriteHeader(_ int)            {}

// Memory is an in-process Backend used in tests and as the default when no
// store is configured.
type Memory struct {
	mu    sync.RWMutex
	pairs map[string]*issuer.Pair
}

// NewMemory returns an empty in-memory backend.
func NewMemory() *Memory {
	return &Memory{pairs: make(map[string]*issuer.Pair)}
}

// LoadPair returns a copy of the pair for sessionID, or issuer.ErrNotFound.
// Always returns a clone so callers can mutate the returned Pair freely
// without affecting the stored value.
func (m *Memory) LoadPair(_ context.Context, sessionID string) (*issuer.Pair, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, ok := m.pairs[sessionID]
	if !ok {
		return nil, issuer.ErrNotFound
	}

	return clonePair(p), nil
}

// SavePair stores a clone of the pair.
func (m *Memory) SavePair(_ context.Context, p *issuer.Pair, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pairs[p.SessionID] = clonePair(p)

	return nil
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
