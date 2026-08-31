// Package redis implements sessionstore.Store using Redis.
package redis

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/twmb/tlscfg"

	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
)

// Store implements sessionstore.Store, sessionstore.DirectStore, and
// sessionstore.AtomicDirectStore using Redis.
type Store struct {
	client    redis.UniversalClient
	keyPrefix string
	codec     *sessionstore.CookieCodec
	options   sessionstore.Options
	ttl       time.Duration
}

var _ sessionstore.DirectStore = (*Store)(nil)
var _ sessionstore.AtomicDirectStore = (*Store)(nil)

// Config holds configuration for a Redis session store.
type Config struct {
	// Address is the Redis server address (e.g., "localhost:6379").
	Address string `cfg:"address"`

	// Username for Redis AUTH.
	Username string `cfg:"username"`

	// Password for Redis AUTH.
	Password string `cfg:"password"`

	// KeyPrefix is prepended to all session keys in Redis.
	// Defaults to "session_".
	KeyPrefix string `cfg:"key_prefix"`

	// SessionKey is the HMAC key for signing session cookies.
	// If empty, a random key is generated.
	SessionKey string `cfg:"session_key"`

	// TLS configuration for Redis connection.
	TLS *TLSConfig `cfg:"tls"`
}

// TLSConfig contains TLS options for the Redis connection.
type TLSConfig struct {
	Enabled            bool   `cfg:"enabled"`
	InsecureSkipVerify bool   `cfg:"insecure_skip_verify"`
	CertFile           string `cfg:"cert_file"`
	KeyFile            string `cfg:"key_file"`
	CAFile             string `cfg:"ca_file"`
}

// New creates a new Redis-based session store.
func New(ctx context.Context, cfg Config, opts sessionstore.Options) (*Store, error) {
	tlsConfig, err := newTLSConfig(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	client := redis.NewClient(&redis.Options{
		Addr:      cfg.Address,
		Username:  cfg.Username,
		Password:  cfg.Password,
		TLSConfig: tlsConfig,
	})

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()

		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	keyPrefix := cfg.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = "session_"
	}

	sessionKey := []byte(cfg.SessionKey)
	if len(sessionKey) == 0 {
		key, err := sessionstore.NewRandomKey(32)
		if err != nil {
			_ = client.Close()

			return nil, fmt.Errorf("redis: generate session key: %w", err)
		}

		sessionKey = key
	}

	ttl := time.Duration(opts.MaxAge) * time.Second
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	return &Store{
		client:    client,
		keyPrefix: keyPrefix,
		codec:     sessionstore.NewCookieCodec(sessionKey),
		options:   opts,
		ttl:       ttl,
	}, nil
}

func newTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, errors.New("both TLS cert and key files must be specified")
	}

	var tlsOpts []tlscfg.Opt
	if cfg.CAFile != "" {
		tlsOpts = append(tlsOpts, tlscfg.MaybeWithDiskCA(cfg.CAFile, tlscfg.ForClient))
	}
	if cfg.CertFile != "" {
		tlsOpts = append(tlsOpts, tlscfg.MaybeWithDiskKeyPair(cfg.CertFile, cfg.KeyFile))
	}

	tlsConfig, err := tlscfg.New(tlsOpts...)
	if err != nil {
		return nil, err
	}
	// This weakens certificate verification only when explicitly configured.
	tlsConfig.InsecureSkipVerify = cfg.InsecureSkipVerify
	return tlsConfig, nil
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

		return nil, fmt.Errorf("redis: read session cookie: %w", err)
	}

	sessionID, err := s.codec.Decode(name, cookieValue)
	if err != nil {
		return s.newSession(name), nil
	}

	session := s.newSession(name)
	session.ID = sessionID

	data, err := s.load(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return s.newSession(name), nil
		}

		return nil, fmt.Errorf("redis: load session: %w", err)
	}

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

	ttl := s.ttl
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
		if errors.Is(err, redis.Nil) {
			return nil, sessionstore.ErrNoSession
		}

		return nil, err
	}

	return v, nil
}

// SaveByID implements sessionstore.DirectStore.
func (s *Store) SaveByID(ctx context.Context, id string, values map[string]any, ttl time.Duration) error {
	if ttl <= 0 {
		// Avoid redis.KeepTTL (-1): ordinary saves with no positive TTL are
		// non-expiring rather than expiry-preserving transactions.
		ttl = 0
	}

	data, err := json.Marshal(values)
	if err != nil {
		return err
	}

	return s.client.Set(ctx, s.redisKey(id), data, ttl).Err()
}

// DeleteByID implements sessionstore.DirectStore.
func (s *Store) DeleteByID(ctx context.Context, id string) error {
	return s.client.Del(ctx, s.redisKey(id)).Err()
}

// TransactByID implements sessionstore.AtomicDirectStore with an optimistic
// transaction on exactly one session key. A change to the watched key before
// EXEC returns sessionstore.ErrTransactionConflict. Non-positive TTLs use
// Redis SET KEEPTTL so the existing absolute expiry is retained atomically.
func (s *Store) TransactByID(
	ctx context.Context,
	id string,
	ttl time.Duration,
	fn sessionstore.AtomicTransaction,
) (map[string]any, error) {
	key := s.redisKey(id)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var result map[string]any
	execAttempted := false
	committed := false
	err := s.client.Watch(ctx, func(tx *redis.Tx) error {
		data, err := tx.Get(ctx, key).Bytes()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return sessionstore.ErrNoSession
			}
			return err
		}

		current := make(map[string]any)
		if err := json.Unmarshal(data, &current); err != nil {
			return err
		}
		replacement, commit, txErr := fn(current)
		if !commit {
			return txErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		var replacementData []byte
		if replacement != nil {
			replacementData, err = json.Marshal(replacement)
			if err != nil {
				return err
			}
		}

		execAttempted = true
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			if replacement == nil {
				pipe.Del(ctx, key)
			} else if ttl <= 0 {
				pipe.Set(ctx, key, replacementData, redis.KeepTTL)
			} else {
				pipe.Set(ctx, key, replacementData, ttl)
			}
			return nil
		})
		if err != nil {
			return err
		}

		result = replacement
		committed = true

		return txErr
	}, key)
	if committed {
		return result, err
	}
	if execAttempted && errors.Is(err, redis.TxFailedErr) {
		return nil, sessionstore.ErrTransactionConflict
	}

	return nil, err
}

// Close closes the Redis client connection.
func (s *Store) Close() error {
	return s.client.Close()
}

func (s *Store) redisKey(sessionID string) string {
	return s.keyPrefix + sessionID
}

func (s *Store) load(ctx context.Context, sessionID string) (map[string]interface{}, error) {
	data, err := s.client.Get(ctx, s.redisKey(sessionID)).Bytes()
	if err != nil {
		return nil, err
	}

	values := make(map[string]interface{})
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, err
	}

	return values, nil
}

func (s *Store) save(ctx context.Context, sessionID string, values map[string]interface{}, ttl time.Duration) error {
	data, err := json.Marshal(values)
	if err != nil {
		return err
	}

	return s.client.Set(ctx, s.redisKey(sessionID), data, ttl).Err()
}

func (s *Store) delete(ctx context.Context, sessionID string) error {
	return s.client.Del(ctx, s.redisKey(sessionID)).Err()
}
