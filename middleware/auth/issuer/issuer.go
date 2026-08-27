// Package issuer mints and validates the auth middleware's own opaque session
// tokens. Strategies authenticate users; the issuer turns the resulting
// Identity into an access/refresh pair keyed by an opaque session ID. The
// browser only ever sees the session ID in its cookie.
package issuer

import (
	"context"
	"errors"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

// Errors returned by Issuer implementations.
var (
	ErrNotFound       = errors.New("issuer: session not found")
	ErrAccessExpired  = errors.New("issuer: access token expired")
	ErrRefreshExpired = errors.New("issuer: refresh token expired")
	ErrRefreshInvalid = errors.New("issuer: refresh token invalid")
	ErrRevoked        = errors.New("issuer: session revoked")
)

// Token is one of our opaque tokens. Value never leaves the server in clear
// text; only the SessionID is exposed via cookie.
type Token struct {
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Expired reports whether t is past its expiry. A zero ExpiresAt is treated as
// "never expires"; callers should set TTLs explicitly.
func (t Token) Expired() bool {
	return t.ExpiredAt(time.Now())
}

// ExpiredAt reports whether t is past its expiry relative to now. Callers with
// an injected clock should use this instead of Expired.
func (t Token) ExpiredAt(now time.Time) bool {
	if t.ExpiresAt.IsZero() {
		return false
	}

	return now.After(t.ExpiresAt)
}

// Pair is the live state for one session: the identity and our two tokens,
// keyed by an opaque session ID.
type Pair struct {
	SessionID string             `json:"session_id"`
	Identity  *identity.Identity `json:"identity"`
	Access    Token              `json:"access"`
	Refresh   Token              `json:"refresh"`
}

// Cipher encrypts and decrypts a serialized Pair at rest. Backends that
// persist outside the process (file, redis) should be given one: the stored
// blob otherwise holds both live tokens and the full identity in clear text.
//
// See the crypto sub-package for an AES-GCM implementation.
type Cipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// Revoker is an optional Issuer capability: dropping every session belonging
// to one subject, e.g. after a password change or an account lockout.
type Revoker interface {
	RevokeSubject(ctx context.Context, subject string) (int, error)
}

// Updater is an optional Issuer capability: rewriting the identity of a live
// session without minting new tokens.
//
// The four-method Issuer interface has no way to persist a change to an
// existing session — Refresh reloads from storage and discards whatever the
// caller had in hand. Anything that has to accumulate state across requests
// within one session (a failed-attempt counter, a step-up marker) needs this.
type Updater interface {
	// Update applies fn to the stored identity and persists the result.
	// Returning an error from fn aborts the write.
	Update(ctx context.Context, sessionID string, fn func(*identity.Identity) error) (*Pair, error)
}

// Issuer mints and manages our own access/refresh tokens keyed by SessionID.
type Issuer interface {
	// Issue creates a brand-new session for the given identity and returns the
	// pair the caller should set in the cookie (SessionID) and request context
	// (Identity, Access).
	Issue(ctx context.Context, id *identity.Identity) (*Pair, error)

	// Resolve looks up the session by SessionID. If the access token is expired
	// the caller should call Refresh; if the refresh token is also expired the
	// caller should redirect to login.
	Resolve(ctx context.Context, sessionID string) (*Pair, error)

	// Refresh validates the supplied refresh token, optionally rotates it, and
	// returns a new pair (same SessionID) with a fresh access token.
	Refresh(ctx context.Context, sessionID, refreshToken string) (*Pair, error)

	// Revoke deletes the session.
	Revoke(ctx context.Context, sessionID string) error
}
