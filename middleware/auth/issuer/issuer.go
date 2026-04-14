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
	if t.ExpiresAt.IsZero() {
		return false
	}

	return time.Now().After(t.ExpiresAt)
}

// Pair is the live state for one session: the identity and our two tokens,
// keyed by an opaque session ID.
type Pair struct {
	SessionID string             `json:"session_id"`
	Identity  *identity.Identity `json:"identity"`
	Access    Token              `json:"access"`
	Refresh   Token              `json:"refresh"`
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
