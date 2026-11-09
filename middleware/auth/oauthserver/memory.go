package oauthserver

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

// MemoryStore keeps everything in process memory. It implements Store,
// ClientFinder and ConsentStore.
//
// Use it for tests, single-process tools and as a reference for your own
// Store. Registrations and tokens are lost on restart, which an MCP client
// survives by registering and signing in again.
type MemoryStore struct {
	mu       sync.Mutex
	clients  map[string]*Client
	codes    map[string]*Code
	tokens   map[string]*Token
	access   map[string]string // access hash -> token id
	refresh  map[string]string // current or previous refresh hash -> token id
	consents map[[2]string]*Consent
	now      func() time.Time
}

var (
	_ Store        = (*MemoryStore)(nil)
	_ ClientFinder = (*MemoryStore)(nil)
	_ ConsentStore = (*MemoryStore)(nil)
)

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		clients:  map[string]*Client{},
		codes:    map[string]*Code{},
		tokens:   map[string]*Token{},
		access:   map[string]string{},
		refresh:  map[string]string{},
		consents: map[[2]string]*Consent{},
		now:      time.Now,
	}
}

// CreateClient implements Store.
func (m *MemoryStore) CreateClient(_ context.Context, c *Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.clients[c.ID] = cloneClient(c)

	return nil
}

// GetClient implements Store.
func (m *MemoryStore) GetClient(_ context.Context, id string) (*Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.clients[id]
	if !ok {
		return nil, ErrNotFound
	}

	return cloneClient(c), nil
}

// ClientsByName implements ClientFinder.
func (m *MemoryStore) ClientsByName(_ context.Context, name string) ([]*Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []*Client
	for _, c := range m.clients {
		if c.Name == name {
			out = append(out, cloneClient(c))
		}
	}

	slices.SortFunc(out, func(a, b *Client) int { return a.CreatedAt.Compare(b.CreatedAt) })

	return out, nil
}

// ListClients returns every client, oldest first.
func (m *MemoryStore) ListClients(_ context.Context) ([]*Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]*Client, 0, len(m.clients))
	for _, c := range m.clients {
		out = append(out, cloneClient(c))
	}

	slices.SortFunc(out, func(a, b *Client) int { return a.CreatedAt.Compare(b.CreatedAt) })

	return out, nil
}

// DeleteClient removes a client with its tokens and consents.
func (m *MemoryStore) DeleteClient(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.clients, id)

	for tid, t := range m.tokens {
		if t.ClientID == id {
			m.deleteTokenLocked(tid)
		}
	}

	for k := range m.consents {
		if k[1] == id {
			delete(m.consents, k)
		}
	}

	return nil
}

// SaveCode implements Store.
func (m *MemoryStore) SaveCode(_ context.Context, c *Code) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sweepLocked()

	cp := *c
	cp.Scopes = slices.Clone(c.Scopes)
	cp.Extra = maps.Clone(c.Extra)
	cp.Identity = cloneIdentity(c.Identity)
	m.codes[c.Hash] = &cp

	return nil
}

// TakeCode implements Store.
func (m *MemoryStore) TakeCode(_ context.Context, hash string) (*Code, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.codes[hash]
	if !ok {
		return nil, ErrNotFound
	}

	delete(m.codes, hash)

	return c, nil
}

// SaveToken implements Store.
func (m *MemoryStore) SaveToken(_ context.Context, t *Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sweepLocked()
	m.putTokenLocked(t)

	return nil
}

func (m *MemoryStore) putTokenLocked(t *Token) {
	if old, ok := m.tokens[t.ID]; ok {
		delete(m.access, old.AccessHash)
		delete(m.refresh, old.RefreshHash)
		delete(m.refresh, old.PreviousRefreshHash)
	}

	cp := cloneToken(t)
	m.tokens[t.ID] = cp
	m.access[cp.AccessHash] = cp.ID
	if cp.RefreshHash != "" {
		m.refresh[cp.RefreshHash] = cp.ID
	}
	if cp.PreviousRefreshHash != "" {
		m.refresh[cp.PreviousRefreshHash] = cp.ID
	}
}

// TokenByAccess implements Store.
func (m *MemoryStore) TokenByAccess(_ context.Context, hash string) (*Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.lookupLocked(m.access, hash)
}

// TokenByRefresh implements Store.
func (m *MemoryStore) TokenByRefresh(_ context.Context, hash string) (*Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.lookupLocked(m.refresh, hash)
}

func (m *MemoryStore) lookupLocked(index map[string]string, hash string) (*Token, error) {
	id, ok := index[hash]
	if !ok {
		return nil, ErrNotFound
	}

	t, ok := m.tokens[id]
	if !ok {
		return nil, ErrNotFound
	}

	return cloneToken(t), nil
}

// RotateToken implements Store.
func (m *MemoryStore) RotateToken(_ context.Context, oldRefreshHash string, t *Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	current, ok := m.tokens[t.ID]
	if !ok {
		return ErrNotFound
	}
	if current.RefreshHash != oldRefreshHash {
		return ErrConflict
	}

	m.putTokenLocked(t)

	return nil
}

// DeleteToken implements Store.
func (m *MemoryStore) DeleteToken(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.deleteTokenLocked(id)

	return nil
}

func (m *MemoryStore) deleteTokenLocked(id string) {
	t, ok := m.tokens[id]
	if !ok {
		return
	}

	delete(m.access, t.AccessHash)
	delete(m.refresh, t.RefreshHash)
	delete(m.refresh, t.PreviousRefreshHash)
	delete(m.tokens, id)
}

// TokensBySubject lists the tokens of a user, newest first — what a "your
// tokens" settings page shows.
func (m *MemoryStore) TokensBySubject(_ context.Context, subject string) ([]*Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []*Token
	for _, t := range m.tokens {
		if t.Subject() == subject {
			out = append(out, cloneToken(t))
		}
	}

	slices.SortFunc(out, func(a, b *Token) int { return b.CreatedAt.Compare(a.CreatedAt) })

	return out, nil
}

// SaveConsent implements ConsentStore.
func (m *MemoryStore) SaveConsent(_ context.Context, c *Consent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *c
	cp.Scopes = slices.Clone(c.Scopes)
	m.consents[[2]string{c.Subject, c.ClientID}] = &cp

	return nil
}

// GetConsent implements ConsentStore.
func (m *MemoryStore) GetConsent(_ context.Context, subject, clientID string) (*Consent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.consents[[2]string{subject, clientID}]
	if !ok {
		return nil, ErrNotFound
	}

	cp := *c
	cp.Scopes = slices.Clone(c.Scopes)

	return &cp, nil
}

// DeleteConsent implements ConsentStore.
func (m *MemoryStore) DeleteConsent(_ context.Context, subject, clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.consents, [2]string{subject, clientID})

	return nil
}

// sweepLocked drops expired codes and tokens so the maps do not grow with
// abandoned sign-ins.
func (m *MemoryStore) sweepLocked() {
	now := m.now()

	for hash, c := range m.codes {
		if !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt) {
			delete(m.codes, hash)
		}
	}

	for id, t := range m.tokens {
		if tokenDead(t, now) {
			m.deleteTokenLocked(id)
		}
	}
}

// tokenDead reports whether neither half of t can be used any more.
func tokenDead(t *Token, now time.Time) bool {
	accessDead := !t.AccessExpiresAt.IsZero() && now.After(t.AccessExpiresAt)
	if !accessDead {
		return false
	}

	if t.RefreshHash == "" {
		return true
	}

	return !t.RefreshExpiresAt.IsZero() && now.After(t.RefreshExpiresAt)
}

func cloneClient(c *Client) *Client {
	cp := *c
	cp.RedirectURIs = slices.Clone(c.RedirectURIs)
	cp.GrantTypes = slices.Clone(c.GrantTypes)

	return &cp
}

func cloneToken(t *Token) *Token {
	cp := *t
	cp.Scopes = slices.Clone(t.Scopes)
	cp.GrantedScopes = slices.Clone(t.GrantedScopes)
	cp.Extra = maps.Clone(t.Extra)
	cp.Identity = cloneIdentity(t.Identity)

	return &cp
}

func cloneIdentity(id *identity.Identity) *identity.Identity {
	if id == nil {
		return nil
	}

	cp := *id
	cp.Roles = slices.Clone(id.Roles)
	cp.Scopes = slices.Clone(id.Scopes)
	cp.Claims = maps.Clone(id.Claims)

	return &cp
}
