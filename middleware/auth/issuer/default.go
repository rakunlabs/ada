package issuer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	// SavePair persists a Pair with the given TTL. A zero TTL means no expiry.
	SavePair(ctx context.Context, p *Pair, ttl time.Duration) error
	// DeletePair removes the Pair.
	DeletePair(ctx context.Context, sessionID string) error
}

// PairTransaction computes an optional replacement for one stored pair.
// When commit is false, the backend leaves the record unchanged. When commit
// is true, a nil replacement deletes it and a non-nil replacement saves it.
// The callback error is returned after applying a requested commit, allowing a
// transaction to delete an expired credential while returning ErrRefreshExpired.
// Backends invoke the callback at most once per TransactPair call and exactly
// once after loading the pair; optimistic commit failures return
// ErrTransactionConflict without invoking it again.
type PairTransaction func(current *Pair) (replacement *Pair, commit bool, err error)

// AtomicBackend is an optional Backend capability for a single atomic
// read-modify-write transaction. Implementations shared by multiple replicas
// must serialize TransactPair across those replicas.
//
// Legacy backends continue to work: Default falls back to process-local keyed
// locks around LoadPair/SavePair/DeletePair. That fallback does not protect two
// application replicas using the same external backend.
type AtomicBackend interface {
	Backend
	AtomicTransactionsSupported() bool
	// TransactPair preserves the current record expiry when ttl <= 0 and the
	// callback commits a non-nil replacement. Deletion ignores ttl. Optimistic
	// implementations return ErrTransactionConflict on a failed commit.
	TransactPair(ctx context.Context, sessionID string, ttl time.Duration, fn PairTransaction) (*Pair, error)
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
	flights map[refreshFlightKey]*refreshFlight
	locks   map[string]*sessionLock
}

type refreshFlight struct {
	done   chan struct{}
	result *Pair
	err    error
}

type refreshFlightKey struct {
	sessionID string
	tokenHash [sha256.Size]byte
}

type sessionLock struct {
	ready chan struct{}
	refs  int
}

// NewDefault returns the standard Issuer wired to the given Backend.
func NewDefault(backend Backend, cfg Config) *Default {
	return &Default{
		backend: backend,
		cfg:     cfg.withDefaults(),
		flights: make(map[refreshFlightKey]*refreshFlight),
		locks:   make(map[string]*sessionLock),
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

	refreshExp := now.Add(d.cfg.RefreshTTL)
	accessExp := now.Add(d.cfg.AccessTTL)
	if accessExp.After(refreshExp) {
		accessExp = refreshExp
	}

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
		Refresh:   Token{Value: refresh, ExpiresAt: refreshExp},
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

func (d *Default) storageTTLFor(pair *Pair) time.Duration {
	if pair == nil || pair.Refresh.ExpiresAt.IsZero() {
		return d.storageTTL()
	}

	ttl := pair.Refresh.ExpiresAt.Add(storageGrace).Sub(d.cfg.Now())
	if ttl <= 0 {
		// Backends commonly interpret a non-positive TTL as no expiry. Keep an
		// already-past storage deadline eligible for immediate cleanup instead.
		return time.Nanosecond
	}

	return ttl
}

// Resolve fetches the pair for sessionID. The caller decides what to do based
// on Access.Expired() / Refresh.Expired().
func (d *Default) Resolve(ctx context.Context, sessionID string) (*Pair, error) {
	if !validSessionID(sessionID) {
		return nil, ErrNotFound
	}

	return d.backend.LoadPair(ctx, sessionID)
}

// Refresh validates the supplied refresh token and mints a new access token.
// Concurrent refreshes for the same sessionID and refresh token share one
// flight. A digest is used in the key so the bearer token is not retained.
func (d *Default) Refresh(ctx context.Context, sessionID, refreshToken string) (*Pair, error) {
	if !validSessionID(sessionID) || refreshToken == "" {
		return nil, ErrRefreshInvalid
	}

	flightKey := refreshFlightKey{sessionID: sessionID, tokenHash: sha256.Sum256([]byte(refreshToken))}
	// Let a live follower recover once without allowing a chain of canceled
	// leaders to keep one Refresh call alive indefinitely.
	retryCanceledLeader := true

	for {
		d.mu.Lock()
		if f, ok := d.flights[flightKey]; ok {
			d.mu.Unlock()
			select {
			case <-f.done:
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if retryCanceledLeader &&
					(errors.Is(f.err, context.Canceled) || errors.Is(f.err, context.DeadlineExceeded)) {
					retryCanceledLeader = false

					continue
				}

				return f.result, f.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		f := &refreshFlight{done: make(chan struct{})}
		d.flights[flightKey] = f
		d.mu.Unlock()

		var unlock func()

		defer func() {
			d.mu.Lock()
			delete(d.flights, flightKey)
			close(f.done)
			d.mu.Unlock()

			if unlock != nil {
				unlock()
			}
		}()

		unlock, f.err = d.lockSession(ctx, sessionID)
		if f.err != nil {
			return nil, f.err
		}

		f.result, f.err = d.refresh(ctx, sessionID, refreshToken)

		return f.result, f.err
	}
}

func (d *Default) refresh(ctx context.Context, sessionID, refreshToken string) (*Pair, error) {
	ttl := d.storageTTL()
	if d.cfg.DisableRefreshRotation {
		// A non-rotating refresh must retain the backend's exact current
		// deadline. Atomic backends interpret a non-positive TTL that way.
		ttl = 0
	}

	if atomic, ok := d.atomicBackend(); ok {
		pair, err := atomic.TransactPair(ctx, sessionID, ttl, func(pair *Pair) (*Pair, bool, error) {
			return d.refreshPair(pair, refreshToken)
		})
		if err != nil {
			return nil, err
		}

		return pair, nil
	}

	pair, err := d.backend.LoadPair(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if d.cfg.DisableRefreshRotation {
		// Legacy backends cannot preserve storage metadata atomically, so use
		// the remaining lifetime from the pair loaded under the local lock.
		ttl = d.storageTTLFor(pair)
	}

	replacement, commit, err := d.refreshPair(pair, refreshToken)
	if commit {
		if replacement == nil {
			_ = d.backend.DeletePair(ctx, sessionID)
		} else if saveErr := d.backend.SavePair(ctx, replacement, ttl); saveErr != nil {
			return nil, fmt.Errorf("issuer: save pair: %w", saveErr)
		}
	}
	if err != nil {
		return nil, err
	}

	return replacement, nil
}

func (d *Default) refreshPair(pair *Pair, refreshToken string) (*Pair, bool, error) {
	// Constant time: the refresh token is a bearer secret, so a comparison
	// that returns early leaks its prefix to a patient caller.
	if subtle.ConstantTimeCompare([]byte(pair.Refresh.Value), []byte(refreshToken)) != 1 {
		return nil, false, ErrRefreshInvalid
	}

	now := d.cfg.Now()

	if pair.Refresh.ExpiredAt(now) {
		return nil, true, ErrRefreshExpired
	}

	newAccess, err := randomToken(32)
	if err != nil {
		return nil, false, fmt.Errorf("issuer: random access: %w", err)
	}

	if !d.cfg.DisableRefreshRotation {
		newRefresh, err := randomToken(32)
		if err != nil {
			return nil, false, fmt.Errorf("issuer: random refresh: %w", err)
		}

		pair.Refresh = Token{Value: newRefresh, ExpiresAt: now.Add(d.cfg.RefreshTTL)}
	}

	accessExp := now.Add(d.cfg.AccessTTL)
	if !pair.Refresh.ExpiresAt.IsZero() && accessExp.After(pair.Refresh.ExpiresAt) {
		accessExp = pair.Refresh.ExpiresAt
	}
	pair.Access = Token{Value: newAccess, ExpiresAt: accessExp}

	if pair.Identity != nil {
		pair.Identity.ExpiresAt = accessExp
	}

	return pair, true, nil
}

// Update implements Updater: it rewrites the stored identity in place.
//
// Serialized against Refresh through the same per-session lock, so an
// update and a rotation cannot interleave and lose each other's write.
func (d *Default) Update(ctx context.Context, sessionID string, fn func(*identity.Identity) error) (*Pair, error) {
	if !validSessionID(sessionID) {
		return nil, ErrNotFound
	}

	unlock, err := d.lockSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if atomic, ok := d.atomicBackend(); ok {
		pair, err := atomic.TransactPair(ctx, sessionID, 0, func(pair *Pair) (*Pair, bool, error) {
			if pair.Identity == nil {
				pair.Identity = &identity.Identity{}
			}
			if err := fn(pair.Identity); err != nil {
				return nil, false, err
			}

			return pair, true, nil
		})
		if err != nil {
			return nil, err
		}

		return pair, nil
	}

	pair, err := d.backend.LoadPair(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	ttl := d.storageTTLFor(pair)

	if pair.Identity == nil {
		pair.Identity = &identity.Identity{}
	}

	if err := fn(pair.Identity); err != nil {
		return nil, err
	}

	if err := d.backend.SavePair(ctx, pair, ttl); err != nil {
		return nil, fmt.Errorf("issuer: save pair: %w", err)
	}

	return pair, nil
}

// AtomicUpdates reports whether Update is backed by a transaction that is safe
// across multiple issuer instances and application replicas.
func (d *Default) AtomicUpdates() bool {
	_, ok := d.atomicBackend()

	return ok
}

func (d *Default) atomicBackend() (AtomicBackend, bool) {
	atomic, ok := d.backend.(AtomicBackend)
	if !ok || !atomic.AtomicTransactionsSupported() {
		return nil, false
	}

	return atomic, true
}

// lockSession serializes mutations for one session ID. The global mutex is held
// only while acquiring or releasing a keyed lock, so unrelated sessions never
// wait on each other's backend work.
func (d *Default) lockSession(ctx context.Context, sessionID string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	d.mu.Lock()
	l := d.locks[sessionID]
	if l == nil {
		l = &sessionLock{ready: make(chan struct{}, 1)}
		l.ready <- struct{}{}
		d.locks[sessionID] = l
	}
	l.refs++
	d.mu.Unlock()

	select {
	case <-ctx.Done():
		d.releaseSessionLock(sessionID, l)

		return nil, ctx.Err()
	case <-l.ready:
	}

	if err := ctx.Err(); err != nil {
		l.ready <- struct{}{}
		d.releaseSessionLock(sessionID, l)

		return nil, err
	}

	return func() {
		l.ready <- struct{}{}
		d.releaseSessionLock(sessionID, l)
	}, nil
}

func (d *Default) releaseSessionLock(sessionID string, l *sessionLock) {
	d.mu.Lock()
	l.refs--
	if l.refs == 0 && d.locks[sessionID] == l {
		delete(d.locks, sessionID)
	}
	d.mu.Unlock()
}

// Revoke deletes the session.
func (d *Default) Revoke(ctx context.Context, sessionID string) error {
	if !validSessionID(sessionID) {
		return nil
	}

	unlock, err := d.lockSession(ctx, sessionID)
	if err != nil {
		return err
	}
	defer unlock()

	if atomic, ok := d.atomicBackend(); ok {
		const attempts = 3
		for attempt := range attempts {
			_, err := atomic.TransactPair(ctx, sessionID, 0, func(*Pair) (*Pair, bool, error) {
				return nil, true, nil
			})
			switch {
			case err == nil, errors.Is(err, ErrNotFound):
				return nil
			case errors.Is(err, ErrTransactionConflict) && attempt+1 < attempts:
				continue
			default:
				return err
			}
		}

		return ErrTransactionConflict
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

func validSessionID(sessionID string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(sessionID)

	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == sessionID
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
