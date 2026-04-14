// Package redis implements sessionstore.Store using Redis.
package redis

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/twmb/tlscfg"

	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
)

// Store implements sessionstore.Store using Redis.
type Store struct {
	client    redis.UniversalClient
	keyPrefix string
	codec     *sessionstore.CookieCodec
	options   sessionstore.Options
	ttl       time.Duration
}

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
	var tlsOpts []tlscfg.Opt

	if cfg.TLS != nil && cfg.TLS.Enabled {
		if cfg.TLS.InsecureSkipVerify {
			tlsOpts = append(tlsOpts, tlscfg.MaybeWithDiskCA("", tlscfg.ForClient))
		}

		if cfg.TLS.CAFile != "" {
			tlsOpts = append(tlsOpts, tlscfg.MaybeWithDiskCA(cfg.TLS.CAFile, tlscfg.ForClient))
		}

		if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
			tlsOpts = append(tlsOpts, tlscfg.MaybeWithDiskKeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile))
		}
	}

	var tlsConfig *tls.Config
	if len(tlsOpts) > 0 {
		var err error
		tlsConfig, err = tlscfg.New(tlsOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}

		if cfg.TLS != nil && cfg.TLS.InsecureSkipVerify {
			tlsConfig.InsecureSkipVerify = true
		}
	}

	client := redis.NewClient(&redis.Options{
		Addr:      cfg.Address,
		Username:  cfg.Username,
		Password:  cfg.Password,
		TLSConfig: tlsConfig,
	})

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()

		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	keyPrefix := cfg.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = "session_"
	}

	sessionKey := []byte(cfg.SessionKey)
	if len(sessionKey) == 0 {
		sessionKey = sessionstore.GenerateRandomKey(32)
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

	data, err := s.load(r.Context(), sessionID)
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
			s.delete(r.Context(), session.ID)
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

	if err := s.save(r.Context(), session.ID, session.Values); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	cookieValue := s.codec.Encode(session.Name(), session.ID)
	sessionstore.SetSessionCookie(w, session.Name(), cookieValue, session.Options)

	return nil
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

func (s *Store) save(ctx context.Context, sessionID string, values map[string]interface{}) error {
	data, err := json.Marshal(values)
	if err != nil {
		return err
	}

	return s.client.Set(ctx, s.redisKey(sessionID), data, s.ttl).Err()
}

func (s *Store) delete(ctx context.Context, sessionID string) {
	s.client.Del(ctx, s.redisKey(sessionID))
}
