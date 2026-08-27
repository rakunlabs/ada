package issuer

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

// Backend is the storage abstraction used by Default. It is intentionally
// narrower than sessionstore.Store: the issuer owns the (sessionID, Pair)
// shape so callers do not need to know the cookie format.
type Backend interface {
	// LoadPair retrieves a Pair by sessionID, or ErrNotFound.
	LoadPair(ctx context.Context, sessionID string) (*Pair, error)
	// SavePair persists a Pair with the given TTL.
	SavePair(ctx context.Context, p *Pair, ttl time.Duration) error
	// DeletePair removes the Pair.
	DeletePair(ctx context.Context, sessionID string) error
}

// Config sets the TTL/rotation behavior for the default issuer.
type Config struct {
	// AccessTTL is how long an access token is valid. Default 15 minutes.
	AccessTTL time.Duration `cfg:"access_ttl"`
	// RefreshTTL is how long a refresh token is valid. Default 7 days.
	RefreshTTL time.Duration `cfg:"refresh_ttl"`
	// DisableRefreshRotation turns off refresh-token rotation.
	//
	// Rotation is on by default: every Refresh mints a fresh refresh token and
	// invalidates the previous one, so a leaked refresh token is usable at most
	// once. Turn it off only when several clients share one session and would
	// race each other out of it.
	DisableRefreshRotation bool `cfg:"disable_refresh_rotation"`
	// Now is the time source; defaults to time.Now. Tests override.
	Now func() time.Time `cfg:"-"`
}

func (c Config) withDefaults() Config {
	if c.AccessTTL <= 0 {
		c.AccessTTL = 15 * time.Minute
	}

	if c.RefreshTTL <= 0 {
		c.RefreshTTL = 7 * 24 * time.Hour
	}

	if c.Now == nil {
		c.Now = time.Now
	}

	return c
}

// Default is the standard Issuer: opaque random tokens, JSON-serialized Pair
// stored in a Backend, single-flight protection on Refresh.
type Default struct {
	backend Backend
	cfg     Config

	mu      sync.Mutex
	flights map[string]*refreshFlight
}

type refreshFlight struct {
	done   chan struct{}
	result *Pair
	err    error
}

// NewDefault returns the standard Issuer wired to the given Backend.
func NewDefault(backend Backend, cfg Config) *Default {
	return &Default{
		backend: backend,
		cfg:     cfg.withDefaults(),
		flights: make(map[string]*refreshFlight),
	}
}

// Issue mints a new session for id.
func (d *Default) Issue(ctx context.Context, id *identity.Identity) (*Pair, error) {
	if id == nil {
		return nil, fmt.Errorf("issuer: nil identity")
	}

	now := d.cfg.Now()

	if id.IssuedAt.IsZero() {
		id.IssuedAt = now
	}

	sessionID, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("issuer: random sessionID: %w", err)
	}

	access, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("issuer: random access: %w", err)
	}

	refresh, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("issuer: random refresh: %w", err)
	}

	accessExp := now.Add(d.cfg.AccessTTL)

	// The identity never outlives the access token it travels with: a strategy
	// may advertise a longer upstream expiry, but our own access TTL is the
	// binding one.
	if id.ExpiresAt.IsZero() || id.ExpiresAt.After(accessExp) {
		id.ExpiresAt = accessExp
	}

	pair := &Pair{
		SessionID: sessionID,
		Identity:  id,
		Access:    Token{Value: access, ExpiresAt: accessExp},
		Refresh:   Token{Value: refresh, ExpiresAt: now.Add(d.cfg.RefreshTTL)},
	}

	if err := d.backend.SavePair(ctx, pair, d.storageTTL()); err != nil {
		return nil, fmt.Errorf("issuer: save pair: %w", err)
	}

	return pair, nil
}

// storageGrace keeps a record alive slightly past the refresh token it holds.
//
// Without it, the backend TTL and the token expiry land at the same instant
// and a client that refreshes a moment too late gets ErrNotFound — "no such
// session" — instead of ErrRefreshExpired. Same outcome, worse diagnosis, and
// callers that distinguish the two would take the wrong branch.
const storageGrace = time.Minute

func (d *Default) storageTTL() time.Duration {
	return d.cfg.RefreshTTL + storageGrace
}

// Resolve fetches the pair for sessionID. The caller decides what to do based
// on Access.Expired() / Refresh.Expired().
func (d *Default) Resolve(ctx context.Context, sessionID string) (*Pair, error) {
	if sessionID == "" {
		return nil, ErrNotFound
	}

	return d.backend.LoadPair(ctx, sessionID)
}

// Refresh validates the supplied refresh token and mints a new access token.
// Concurrent refreshes for the same sessionID share one flight.
func (d *Default) Refresh(ctx context.Context, sessionID, refreshToken string) (*Pair, error) {
	if sessionID == "" || refreshToken == "" {
		return nil, ErrRefreshInvalid
	}

	d.mu.Lock()
	if f, ok := d.flights[sessionID]; ok {
		d.mu.Unlock()
		<-f.done

		return f.result, f.err
	}

	f := &refreshFlight{done: make(chan struct{})}
	d.flights[sessionID] = f
	d.mu.Unlock()

	defer func() {
		d.mu.Lock()
		delete(d.flights, sessionID)
		d.mu.Unlock()
		close(f.done)
	}()

	f.result, f.err = d.refresh(ctx, sessionID, refreshToken)

	return f.result, f.err
}

func (d *Default) refresh(ctx context.Context, sessionID, refreshToken string) (*Pair, error) {
	pair, err := d.backend.LoadPair(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	// Constant time: the refresh token is a bearer secret, so a comparison
	// that returns early leaks its prefix to a patient caller.
	if subtle.ConstantTimeCompare([]byte(pair.Refresh.Value), []byte(refreshToken)) != 1 {
		return nil, ErrRefreshInvalid
	}

	now := d.cfg.Now()

	if pair.Refresh.ExpiredAt(now) {
		_ = d.backend.DeletePair(ctx, sessionID)

		return nil, ErrRefreshExpired
	}

	newAccess, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("issuer: random access: %w", err)
	}

	accessExp := now.Add(d.cfg.AccessTTL)
	pair.Access = Token{Value: newAccess, ExpiresAt: accessExp}

	if pair.Identity != nil {
		pair.Identity.ExpiresAt = accessExp
	}

	if !d.cfg.DisableRefreshRotation {
		newRefresh, err := randomToken(32)
		if err != nil {
			return nil, fmt.Errorf("issuer: random refresh: %w", err)
		}

		pair.Refresh = Token{Value: newRefresh, ExpiresAt: now.Add(d.cfg.RefreshTTL)}
	}

	if err := d.backend.SavePair(ctx, pair, d.storageTTL()); err != nil {
		return nil, fmt.Errorf("issuer: save pair: %w", err)
	}

	return pair, nil
}

// Update implements Updater: it rewrites the stored identity in place.
//
// Serialized against Refresh through the same per-session flight lock, so an
// update and a rotation cannot interleave and lose each other's write.
func (d *Default) Update(ctx context.Context, sessionID string, fn func(*identity.Identity) error) (*Pair, error) {
	if sessionID == "" {
		return nil, ErrNotFound
	}

	unlock := d.lockSession(sessionID)
	defer unlock()

	pair, err := d.backend.LoadPair(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if pair.Identity == nil {
		pair.Identity = &identity.Identity{}
	}

	if err := fn(pair.Identity); err != nil {
		return nil, err
	}

	if err := d.backend.SavePair(ctx, pair, d.storageTTL()); err != nil {
		return nil, fmt.Errorf("issuer: save pair: %w", err)
	}

	return pair, nil
}

// lockSession serializes writes for one session ID.
func (d *Default) lockSession(sessionID string) func() {
	for {
		d.mu.Lock()

		f, busy := d.flights[sessionID]
		if !busy {
			f = &refreshFlight{done: make(chan struct{})}
			d.flights[sessionID] = f
			d.mu.Unlock()

			return func() {
				d.mu.Lock()
				delete(d.flights, sessionID)
				d.mu.Unlock()
				close(f.done)
			}
		}

		d.mu.Unlock()
		<-f.done
	}
}

// Revoke deletes the session.
func (d *Default) Revoke(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}

	return d.backend.DeletePair(ctx, sessionID)
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// EncodePair / DecodePair are exposed for backends (notably the cookie
// backend) that need to serialize the Pair without owning its layout.
func EncodePair(p *Pair) ([]byte, error) {
	return json.Marshal(p)
}

func DecodePair(data []byte) (*Pair, error) {
	var p Pair
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}

	return &p, nil
}
