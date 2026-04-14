// Package file implements sessionstore.Store using the filesystem.
package file

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
)

// Store implements sessionstore.Store using the filesystem.
type Store struct {
	path      string
	maxLength int

	codec   *sessionstore.CookieCodec
	options sessionstore.Options

	mu sync.RWMutex
}

// Config holds configuration for a filesystem session store.
type Config struct {
	// SessionKey is the HMAC key for signing session cookies.
	// If empty, a random key is generated.
	SessionKey string `cfg:"session_key"`

	// Path is the directory for session files.
	// Defaults to os.TempDir()/ada_sessions.
	Path string `cfg:"path"`
}

// New creates a new filesystem-based session store.
func New(cfg Config, opts sessionstore.Options) *Store {
	sessionKey := []byte(cfg.SessionKey)
	if len(sessionKey) == 0 {
		sessionKey = sessionstore.GenerateRandomKey(32)
	}

	storePath := cfg.Path
	if storePath == "" {
		storePath = filepath.Join(os.TempDir(), "ada_sessions")
	}

	os.MkdirAll(storePath, 0700)

	return &Store{
		path:      storePath,
		maxLength: 1 << 20, // 1MB
		codec:     sessionstore.NewCookieCodec(sessionKey),
		options:   opts,
	}
}

// Get returns the session for the given name.
func (s *Store) Get(r *http.Request, name string) (*sessionstore.Session, error) {
	cookieValue, err := sessionstore.ReadSessionCookie(r, name)
	if err != nil {
		return sessionstore.NewSession(s, name, &s.options), nil
	}

	sessionID, err := s.codec.Decode(name, cookieValue)
	if err != nil {
		return sessionstore.NewSession(s, name, &s.options), nil
	}

	session := sessionstore.NewSession(s, name, &s.options)
	session.ID = sessionID

	data, err := s.load(sessionID)
	if err != nil {
		return sessionstore.NewSession(s, name, &s.options), nil
	}

	session.Values = data
	session.IsNew = false

	return session, nil
}

// Save persists the session and sets the cookie.
func (s *Store) Save(r *http.Request, w http.ResponseWriter, session *sessionstore.Session) error {
	if session.Options.MaxAge < 0 {
		if session.ID != "" {
			s.delete(session.ID)
		}

		sessionstore.SetSessionCookie(w, session.Name(), "", session.Options)

		return nil
	}

	if session.ID == "" {
		id, err := sessionstore.GenerateSessionID()
		if err != nil {
			return fmt.Errorf("failed to generate session ID: %w", err)
		}
		session.ID = id
	}

	if err := s.save(session.ID, session.Values); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	cookieValue := s.codec.Encode(session.Name(), session.ID)
	sessionstore.SetSessionCookie(w, session.Name(), cookieValue, session.Options)

	return nil
}

func (s *Store) filePath(sessionID string) string {
	return filepath.Join(s.path, "session_"+sessionID+".json")
}

func (s *Store) load(sessionID string) (map[string]any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.filePath(sessionID))
	if err != nil {
		return nil, err
	}

	if s.maxLength > 0 && len(data) > s.maxLength {
		return nil, fmt.Errorf("session data exceeds maximum length")
	}

	values := make(map[string]any)
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, err
	}

	return values, nil
}

func (s *Store) save(sessionID string, values map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(values)
	if err != nil {
		return err
	}

	if s.maxLength > 0 && len(data) > s.maxLength {
		return fmt.Errorf("session data exceeds maximum length")
	}

	return os.WriteFile(s.filePath(sessionID), data, 0600)
}

func (s *Store) delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	os.Remove(s.filePath(sessionID))
}
