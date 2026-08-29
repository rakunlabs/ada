package sessions

import (
	"context"
	"errors"
	"net/http"
	"sync"
)

type ctxKey int

const registryKey ctxKey = iota

// Registry caches the sessions touched during a single request so that repeated
// Store.Get calls return the same instance and Save can flush them all at once.
type Registry struct {
	mu       sync.Mutex
	sessions map[sessionKey]registryEntry
}

type sessionKey struct {
	store Store
	name  string
}

type registryEntry struct {
	session *Session
	err     error
}

func newRegistry() *Registry {
	return &Registry{sessions: make(map[sessionKey]registryEntry)}
}

func (reg *Registry) get(store Store, name string) (*Session, error, bool) {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	entry, ok := reg.sessions[sessionKey{store: store, name: name}]

	return entry.session, entry.err, ok
}

func (reg *Registry) set(store Store, name string, s *Session, err error) {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	reg.sessions[sessionKey{store: store, name: name}] = registryEntry{session: s, err: err}
}

// NewContext returns a copy of ctx carrying a fresh, empty session registry.
func NewContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, registryKey, newRegistry())
}

// GetRegistry returns the per-request registry installed by Middleware, or nil
// if none is present.
func GetRegistry(r *http.Request) *Registry {
	reg, _ := r.Context().Value(registryKey).(*Registry)

	return reg
}

// Middleware installs a per-request session registry. With it in place,
// repeated Store.Get calls for the same name share one *Session and a single
// sessions.Save flushes every touched session.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := NewContext(r.Context())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Save persists every session registered during the request. It is a no-op when
// Middleware was not installed; in that case call Session.Save directly.
func Save(r *http.Request, w http.ResponseWriter) error {
	reg := GetRegistry(r)
	if reg == nil {
		return nil
	}

	reg.mu.Lock()
	defer reg.mu.Unlock()

	var errs []error
	for _, entry := range reg.sessions {
		if err := entry.session.store.Save(r, w, entry.session); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
