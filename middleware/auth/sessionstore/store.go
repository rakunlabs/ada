// Package sessionstore defines the session storage interface and common types.
//
// Implementations live in this package (cookie, file) or in sub-modules
// (redis) that carry their own dependencies.
package sessionstore

import (
	"net/http"
)

// Store is the interface for session storage backends.
type Store interface {
	// Get returns the session for the given name.
	// If the session does not exist, a new empty session is returned with IsNew=true.
	Get(r *http.Request, name string) (*Session, error)

	// Save persists the session to the backend and writes the session cookie.
	Save(r *http.Request, w http.ResponseWriter, s *Session) error
}

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
