// Package sessionstore defines the session storage interface and common types.
//
// The cookie codec (signing/verification) lives in this package; concrete
// stores live in sub-packages: file (stdlib only) and redis (own module).
package sessionstore

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// ErrNotDirect is returned by adapters that need DirectStore semantics from a
// Store that does not implement it.
var ErrNotDirect = errors.New("sessionstore: store does not implement DirectStore")

// Store is the interface for session storage backends.
type Store interface {
	// Get returns the session for the given name.
	// If the session does not exist, a new empty session is returned with IsNew=true.
	Get(r *http.Request, name string) (*Session, error)

	// Save persists the session to the backend and writes the session cookie.
	Save(r *http.Request, w http.ResponseWriter, s *Session) error
}

// DirectStore is an optional interface for stores that can read and write
// session values keyed by a raw session ID, without an *http.Request and
// without going through the cookie codec.
//
// The issuer backend requires this: it owns its own session IDs and never has
// a real request/response pair to hand to Get/Save. Attempting to drive a
// codec-based Store through a synthesized request silently fails, because the
// codec expects a signed "b64(id)|b64(mac)" cookie value rather than a raw ID.
//
// Both the file and redis stores implement DirectStore.
type DirectStore interface {
	Store

	// LoadByID returns the stored values for id. It must return ErrNoSession
	// when the id is unknown.
	LoadByID(ctx context.Context, id string) (map[string]any, error)

	// SaveByID persists values under id. A ttl of 0 means "no explicit
	// expiry"; stores that cannot express that may apply their default.
	SaveByID(ctx context.Context, id string, values map[string]any, ttl time.Duration) error

	// DeleteByID removes the record for id. Deleting an unknown id is not an
	// error.
	DeleteByID(ctx context.Context, id string) error
}

// ErrNoSession is returned by DirectStore.LoadByID when the id is unknown.
var ErrNoSession = errors.New("sessionstore: session not found")

// Session represents a server-side session.
type Session struct {
	// ID is the unique session identifier.
	ID string

	// Values is the session data.
	Values map[string]interface{}

	// Options controls the session cookie behavior.
	Options *Options

	// IsNew is true if the session was not loaded from the store.
	IsNew bool

	name  string
	store Store
}

// Name returns the session name (the cookie name it was loaded with).
func (s *Session) Name() string {
	return s.name
}

// Save is a convenience method that calls the store's Save method.
func (s *Session) Save(r *http.Request, w http.ResponseWriter) error {
	return s.store.Save(r, w, s)
}

// Options controls session cookie attributes.
type Options struct {
	Path     string
	MaxAge   int // seconds; 0 means no explicit max-age; <0 means delete
	Domain   string
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

// NewSession creates a new session with the given store, name, and options.
func NewSession(store Store, name string, opts *Options) *Session {
	if opts == nil {
		opts = &Options{
			Path:   "/",
			MaxAge: 86400,
		}
	}

	return &Session{
		Values:  make(map[string]interface{}),
		Options: opts,
		IsNew:   true,
		name:    name,
		store:   store,
	}
}
