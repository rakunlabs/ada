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
//
// A nil identity or an empty role is false. It used to return true for an
// empty role, on the reading that "no requirement" is trivially satisfied —
// but the call site that matters is `if id.HasRole(cfg.RequiredRole)`, where a
// missing configuration value would then wave everyone through. Absence of a
// requirement is the caller's decision to make, not this function's.
func (i *Identity) HasRole(role string) bool {
	if i == nil || role == "" {
		return false
	}

	return slices.Contains(i.Roles, role)
}

// HasScope reports whether the identity has the given scope.
//
// A nil identity or an empty scope is false; see HasRole.
func (i *Identity) HasScope(scope string) bool {
	if i == nil || scope == "" {
		return false
	}

	return slices.Contains(i.Scopes, scope)
}

// HasAnyRole reports whether the identity holds at least one of roles.
// An empty list is false.
func (i *Identity) HasAnyRole(roles ...string) bool {
	for _, r := range roles {
		if i.HasRole(r) {
			return true
		}
	}

	return false
}

// HasAllRoles reports whether the identity holds every one of roles.
// An empty list is true: nothing was required and nothing is missing.
func (i *Identity) HasAllRoles(roles ...string) bool {
	for _, r := range roles {
		if !i.HasRole(r) {
			return false
		}
	}

	return true
}

// HasAnyScope reports whether the identity holds at least one of scopes.
func (i *Identity) HasAnyScope(scopes ...string) bool {
	for _, s := range scopes {
		if i.HasScope(s) {
			return true
		}
	}

	return false
}

// HasAllScopes reports whether the identity holds every one of scopes.
func (i *Identity) HasAllScopes(scopes ...string) bool {
	for _, s := range scopes {
		if !i.HasScope(s) {
			return false
		}
	}

	return true
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
