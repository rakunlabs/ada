package users

import (
	"context"
	"slices"
	"strings"
	"sync"
)

// MemoryStore keeps users in process memory. For tests and demos; users are
// lost on restart.
type MemoryStore struct {
	mu    sync.Mutex
	users map[string]*User
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{users: map[string]*User{}}
}

// CreateUser implements Store.
func (m *MemoryStore) CreateUser(_ context.Context, u *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.byNameLocked(u.Username) != nil {
		return ErrExists
	}

	m.users[u.ID] = cloneUser(u)

	return nil
}

// GetUser implements Store.
func (m *MemoryStore) GetUser(_ context.Context, id string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	u, ok := m.users[id]
	if !ok {
		return nil, ErrNotFound
	}

	return cloneUser(u), nil
}

// GetUserByUsername implements Store.
func (m *MemoryStore) GetUserByUsername(_ context.Context, username string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if u := m.byNameLocked(username); u != nil {
		return cloneUser(u), nil
	}

	return nil, ErrNotFound
}

func (m *MemoryStore) byNameLocked(username string) *User {
	for _, u := range m.users {
		if strings.EqualFold(u.Username, username) {
			return u
		}
	}

	return nil
}

// ListUsers implements Store.
func (m *MemoryStore) ListUsers(_ context.Context) ([]*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]*User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, cloneUser(u))
	}

	slices.SortFunc(out, func(a, b *User) int { return strings.Compare(strings.ToLower(a.Username), strings.ToLower(b.Username)) })

	return out, nil
}

// UpdateUser implements Store.
func (m *MemoryStore) UpdateUser(_ context.Context, u *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.users[u.ID]; !ok {
		return ErrNotFound
	}
	if other := m.byNameLocked(u.Username); other != nil && other.ID != u.ID {
		return ErrExists
	}

	m.users[u.ID] = cloneUser(u)

	return nil
}

// DeleteUser implements Store.
func (m *MemoryStore) DeleteUser(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.users[id]; !ok {
		return ErrNotFound
	}

	delete(m.users, id)

	return nil
}

// CountUsers implements Store.
func (m *MemoryStore) CountUsers(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.users), nil
}
