// Package identity defines the normalized user model returned by every
// authentication strategy.
package identity

import (
	"slices"
	"time"
)

// Identity is the normalized user info produced by a strategy after a
// successful login. It is the only shape downstream handlers see, regardless
// of which strategy authenticated the user.
type Identity struct {
	// Subject is the stable unique identifier for the user (sub, user_id, email).
	Subject string `json:"subject"`
	// Name is a display name. Optional.
	Name string `json:"name,omitempty"`
	// Email is the user's email address. Optional.
	Email string `json:"email,omitempty"`
	// EmailVerified mirrors the OIDC claim when the strategy supplies it.
	EmailVerified bool `json:"email_verified,omitempty"`
	// Roles are app-level role strings.
	Roles []string `json:"roles,omitempty"`
	// Scopes are granted scope strings.
	Scopes []string `json:"scopes,omitempty"`
	// Claims carries free-form extras (custom OIDC claims, app-specific data).
	Claims map[string]any `json:"claims,omitempty"`
	// Provider is the strategy name (e.g. "local", "google") that authenticated
	// this identity.
	Provider string `json:"provider"`
	// IssuedAt is when the strategy verified the identity.
	IssuedAt time.Time `json:"issued_at,omitzero"`
	// ExpiresAt is the strategy-supplied expiry hint. Zero means "use issuer
	// defaults". The issuer always caps to its configured access TTL.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// HasRole reports whether the identity has the given role.
// An empty role string returns true (no requirement).
func (i *Identity) HasRole(role string) bool {
	if role == "" {
		return true
	}

	return slices.Contains(i.Roles, role)
}

// HasScope reports whether the identity has the given scope.
// An empty scope string returns true (no requirement).
func (i *Identity) HasScope(scope string) bool {
	if scope == "" {
		return true
	}

	return slices.Contains(i.Scopes, scope)
}

// Claim returns the value at key from Claims, or zero T if missing or wrong type.
func Claim[T any](i *Identity, key string) T {
	var zero T
	if i == nil || i.Claims == nil {
		return zero
	}

	v, ok := i.Claims[key].(T)
	if !ok {
		return zero
	}

	return v
}
