// Package file implements sessionstore.Store using the filesystem.
package file

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
)

// Store implements sessionstore.Store and sessionstore.DirectStore using the
// filesystem.
type Store struct {
	path      string
	maxLength int

	codec   *sessionstore.CookieCodec
	options sessionstore.Options

	now func() time.Time

	mu sync.RWMutex

	gcOnce sync.Once
	gcStop chan struct{}
	gcTick time.Duration
}

var _ sessionstore.DirectStore = (*Store)(nil)

// Config holds configuration for a filesystem session store.
type Config struct {
	// SessionKey is the HMAC key for signing session cookies.
	//
	// If empty, a random key is generated at construction. That is only
	// acceptable for a single-process, restart-tolerant deployment: every
	// existing session is invalidated on restart and no two replicas can read
	// each other's cookies. Set it explicitly in production.
	SessionKey string `cfg:"session_key"`

	// Path is the directory for session files.
	// Defaults to os.TempDir()/ada_sessions.
	Path string `cfg:"path"`

	// GCInterval controls how often expired session files are swept.
	// Defaults to 10 minutes. A negative value disables the sweeper.
	GCInterval time.Duration `cfg:"gc_interval"`
}

const (
	filePrefix             = "session_"
	transactionLockStripes = 64
)

// New creates a new filesystem-based session store.
func New(cfg Config, opts sessionstore.Options) (*Store, error) {
	sessionKey := []byte(cfg.SessionKey)
	if len(sessionKey) == 0 {
		key, err := sessionstore.NewRandomKey(32)
		if err != nil {
			return nil, fmt.Errorf("file: generate session key: %w", err)
		}

		sessionKey = key
	}

	storePath := cfg.Path
	if storePath == "" {
		storePath = filepath.Join(os.TempDir(), "ada_sessions")
	}

	if err := os.MkdirAll(storePath, 0o700); err != nil {
		return nil, fmt.Errorf("file: create session dir %q: %w", storePath, err)
	}

	gcTick := cfg.GCInterval
	if gcTick == 0 {
		gcTick = 10 * time.Minute
	}

	return &Store{
		path:      storePath,
		maxLength: 1 << 20, // 1MB
		codec:     sessionstore.NewCookieCodec(sessionKey),
		options:   opts,
		now:       time.Now,
		gcStop:    make(chan struct{}),
		gcTick:    gcTick,
	}, nil
}

// StartGC launches the background sweeper that removes expired session files.
// It is safe to call more than once; only the first call has an effect.
// Call Close to stop it.
func (s *Store) StartGC() {
	if s.gcTick < 0 {
		return
	}

	s.gcOnce.Do(func() {
		go func() {
			t := time.NewTicker(s.gcTick)
			defer t.Stop()

			for {
				select {
				case <-s.gcStop:
					return
				case <-t.C:
					s.sweep()
				}
			}
		}()
	})
}

// Close stops the background sweeper.
func (s *Store) Close() error {
	select {
	case <-s.gcStop:
	default:
		close(s.gcStop)
	}

	return nil
}

func (s *Store) newSession(name string) *sessionstore.Session {
	options := s.options

	return sessionstore.NewSession(s, name, &options)
}

// Get returns the session for the given name.
func (s *Store) Get(r *http.Request, name string) (*sessionstore.Session, error) {
	cookieValue, err := sessionstore.ReadSessionCookie(r, name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return s.newSession(name), nil
		}

		return nil, fmt.Errorf("file: read session cookie: %w", err)
	}

	sessionID, err := s.codec.Decode(name, cookieValue)
	if err != nil {
		return s.newSession(name), nil
	}

	data, err := s.load(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, sessionstore.ErrNoSession) {
			return s.newSession(name), nil
		}

		return nil, fmt.Errorf("file: load session: %w", err)
	}

	session := s.newSession(name)
	session.ID = sessionID
	session.Values = data
	session.IsNew = false

	return session, nil
}

// Save persists the session and sets the cookie.
func (s *Store) Save(r *http.Request, w http.ResponseWriter, session *sessionstore.Session) error {
	if session.Options.MaxAge < 0 {
		var deleteErr error
		if session.ID != "" {
			deleteErr = s.delete(r.Context(), session.ID)
		}

		sessionstore.SetSessionCookie(w, session.Name(), "", session.Options)
		if deleteErr != nil {
			return fmt.Errorf("failed to delete session: %w", deleteErr)
		}

		return nil
	}

	if session.ID == "" {
		id, err := sessionstore.GenerateSessionID()
		if err != nil {
			return fmt.Errorf("failed to generate session ID: %w", err)
		}

		session.ID = id
	}

	var ttl time.Duration
	if session.Options.MaxAge > 0 {
		ttl = time.Duration(session.Options.MaxAge) * time.Second
	}

	if err := s.save(r.Context(), session.ID, session.Values, ttl); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	cookieValue := s.codec.Encode(session.Name(), session.ID)
	sessionstore.SetSessionCookie(w, session.Name(), cookieValue, session.Options)

	return nil
}

// LoadByID implements sessionstore.DirectStore.
func (s *Store) LoadByID(ctx context.Context, id string) (map[string]any, error) {
	v, err := s.load(ctx, id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, sessionstore.ErrNoSession
		}

		return nil, err
	}

	return v, nil
}

// SaveByID implements sessionstore.DirectStore.
func (s *Store) SaveByID(ctx context.Context, id string, values map[string]any, ttl time.Duration) error {
	return s.save(ctx, id, values, ttl)
}

// DeleteByID implements sessionstore.DirectStore.
func (s *Store) DeleteByID(ctx context.Context, id string) error {
	return s.delete(ctx, id)
}

// record is the on-disk envelope. Values are nested so an expiry can be stored
// alongside them without colliding with user keys.
type record struct {
	Values    map[string]any `json:"values"`
	ExpiresAt int64          `json:"expires_at,omitempty"`
}

func (s *Store) filePath(sessionID string) string {
	// Session IDs are generated by this package (base64url + "_"), but a
	// caller-supplied issuer ID also lands here. Refuse anything that could
	// escape the directory.
	return filepath.Join(s.path, filePrefix+sessionID+".json")
}

func safeID(sessionID string) bool {
	if sessionID == "" || len(sessionID) > 256 {
		return false
	}

	return !strings.ContainsAny(sessionID, `/\.`)
}

func transactionLockStripe(sessionID string) byte {
	digest := sha256.Sum256([]byte(sessionID))

	return digest[0] % transactionLockStripes
}

func (s *Store) transactionLockPath(sessionID string) string {
	name := fmt.Sprintf(".transaction-%02x.lock", transactionLockStripe(sessionID))

	return filepath.Join(s.path, name)
}

func (s *Store) load(ctx context.Context, sessionID string) (map[string]any, error) {
	if !safeID(sessionID) {
		return nil, sessionstore.ErrNoSession
	}

	rec, err := s.readRecord(sessionID)
	if err != nil {
		return nil, err
	}
	if !s.expired(rec) {
		return recordValues(rec), nil
	}

	// A concurrent save may have replaced the expired record after the first
	// read. Serialize with writers and re-read before removing anything.
	unlock, err := s.lockTransaction(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	defer unlock()

	return s.loadLocked(sessionID)
}

func (s *Store) loadLocked(sessionID string) (map[string]any, error) {
	rec, err := s.liveRecordLocked(sessionID)
	if err != nil {
		return nil, err
	}

	return recordValues(rec), nil
}

func (s *Store) liveRecordLocked(sessionID string) (record, error) {
	rec, err := s.readRecord(sessionID)
	if err != nil {
		return record{}, err
	}
	if s.expired(rec) {
		if err := s.deleteLocked(sessionID); err != nil {
			return record{}, err
		}

		return record{}, sessionstore.ErrNoSession
	}

	return rec, nil
}

func (s *Store) readRecord(sessionID string) (record, error) {
	s.mu.RLock()
	data, err := os.ReadFile(s.filePath(sessionID))
	s.mu.RUnlock()

	if err != nil {
		return record{}, err
	}

	if s.maxLength > 0 && len(data) > s.maxLength {
		return record{}, fmt.Errorf("session data exceeds maximum length")
	}

	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		return record{}, err
	}

	return rec, nil
}

func (s *Store) expired(rec record) bool {
	return rec.ExpiresAt > 0 && s.now().Unix() >= rec.ExpiresAt
}

func recordValues(rec record) map[string]any {
	if rec.Values == nil {
		rec.Values = make(map[string]any)
	}

	return rec.Values
}

func (s *Store) save(ctx context.Context, sessionID string, values map[string]any, ttl time.Duration) error {
	if !safeID(sessionID) {
		return fmt.Errorf("file: unsafe session id")
	}

	data, err := s.marshalRecord(values, ttl)
	if err != nil {
		return err
	}

	unlock, err := s.lockTransaction(ctx, sessionID)
	if err != nil {
		return err
	}
	defer unlock()

	return s.writeRecord(sessionID, data)
}

func (s *Store) marshalRecord(values map[string]any, ttl time.Duration) ([]byte, error) {
	rec := record{Values: values}
	if ttl > 0 {
		rec.ExpiresAt = s.now().Add(ttl).Unix()
	}

	return s.marshalRecordEnvelope(rec)
}

func (s *Store) marshalRecordEnvelope(rec record) ([]byte, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}

	if s.maxLength > 0 && len(data) > s.maxLength {
		return nil, fmt.Errorf("session data exceeds maximum length")
	}

	return data, nil
}

func (s *Store) writeRecord(sessionID string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tmp, err := os.CreateTemp(s.path, ".session-*.tmp")
	if err != nil {
		return err
	}

	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()

		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, s.filePath(sessionID))
}

func (s *Store) delete(ctx context.Context, sessionID string) error {
	if !safeID(sessionID) {
		return fmt.Errorf("file: unsafe session id")
	}

	unlock, err := s.lockTransaction(ctx, sessionID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}
	defer unlock()

	return s.deleteLocked(sessionID)
}

func (s *Store) deleteLocked(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := os.Remove(s.filePath(sessionID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	return err
}

// sweep removes every expired session file.
func (s *Store) sweep() {
	entries, err := os.ReadDir(s.path)
	if err != nil {
		return
	}

	now := s.now().Unix()

	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), filePrefix) || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}

		sessionID := strings.TrimSuffix(strings.TrimPrefix(e.Name(), filePrefix), ".json")
		if !safeID(sessionID) {
			continue
		}

		rec, err := s.readRecord(sessionID)
		if err != nil {
			continue
		}

		if rec.ExpiresAt > 0 && now >= rec.ExpiresAt {
			_, _ = s.load(context.Background(), sessionID)
		}
	}
}
