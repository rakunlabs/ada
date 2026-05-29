// Package sessions provides cookie-based session management for ada.
//
// It is an idiomatic, dependency-free alternative to gorilla/sessions, built on
// the github.com/rakunlabs/ada/securecookie codec. Session values use string
// keys, matching the rest of ada.
//
// Typical use with the cookie store:
//
//	store := sessions.NewCookieStore(hashKey, blockKey)
//
//	sess, _ := store.Get(r, "auth")
//	sess.Values["user"] = "ada"
//	if err := sess.Save(r, w); err != nil {
//		// handle error
//	}
//
// To share session state across a request (and to use sessions.Save to flush
// every touched session at once), wrap handlers with sessions.Middleware.
package sessions

import (
	"net/http"
	"time"
)

// timeZero is used as the Expires value when deleting a cookie, for clients
// that ignore Max-Age.
var timeZero = time.Unix(1, 0)

// Store persists sessions. Implementations decide where the data lives (in the
// cookie, on disk, in a database, ...).
type Store interface {
	// Get returns a cached session for the request if one exists, otherwise it
	// behaves like New. When a per-request registry is installed (see
	// Middleware), repeated calls with the same name return the same instance.
	Get(r *http.Request, name string) (*Session, error)

	// New always returns a fresh session loaded from the request, if present.
	// On a decode failure it returns a new empty session together with the
	// error so the caller can decide how to react.
	New(r *http.Request, name string) (*Session, error)

	// Save writes the session to the response. A session whose Options.MaxAge is
	// negative is deleted.
	Save(r *http.Request, w http.ResponseWriter, s *Session) error
}

// Options controls the attributes of a session cookie.
type Options struct {
	Path        string
	Domain      string
	MaxAge      int // seconds; 0 = session cookie; <0 deletes the cookie
	Secure      bool
	HttpOnly    bool
	Partitioned bool
	SameSite    http.SameSite
}

func (o *Options) clone() *Options {
	if o == nil {
		return &Options{Path: "/"}
	}
	c := *o

	return &c
}

// Session holds the data for a single session.
type Session struct {
	// ID is an optional identifier set by server-side stores. The cookie store
	// leaves it empty.
	ID string

	// Values is the session payload. Keys are strings.
	Values map[string]any

	// Options controls the Set-Cookie attributes for this session.
	Options *Options

	// IsNew reports whether the session was created during this request rather
	// than loaded from an existing cookie.
	IsNew bool

	name  string
	store Store
}

// NewSession returns an empty session bound to store under name. Stores use it
// from their New method; application code normally calls Store.Get instead.
func NewSession(store Store, name string) *Session {
	return &Session{
		Values: make(map[string]any),
		IsNew:  true,
		name:   name,
		store:  store,
	}
}

// Name returns the session name (the cookie name it is stored under).
func (s *Session) Name() string { return s.name }

// Store returns the store this session belongs to.
func (s *Session) Store() Store { return s.store }

// Save is a convenience wrapper around the store's Save method.
func (s *Session) Save(r *http.Request, w http.ResponseWriter) error {
	return s.store.Save(r, w, s)
}

// newCookie builds an *http.Cookie from a name, value and options.
func newCookie(name, value string, opts *Options) *http.Cookie {
	c := &http.Cookie{
		Name:        name,
		Value:       value,
		Path:        opts.Path,
		Domain:      opts.Domain,
		MaxAge:      opts.MaxAge,
		Secure:      opts.Secure,
		HttpOnly:    opts.HttpOnly,
		Partitioned: opts.Partitioned,
		SameSite:    opts.SameSite,
	}

	// A negative MaxAge means "delete now"; mirror it onto Expires for old
	// clients that ignore Max-Age.
	if opts.MaxAge < 0 {
		c.Expires = timeZero
	}

	return c
}
