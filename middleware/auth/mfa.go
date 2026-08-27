package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/cookie"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/issuer"
	"github.com/rakunlabs/ada/middleware/auth/session"
)

// SecondFactor gates session issuance behind an additional check.
//
// The package ships strategy/totp as a well-tested RFC 6238 primitive and
// nothing that uses it: there was no point in the login flow where a second
// factor could be demanded. This is that point.
//
// The flow is:
//
//  1. A strategy authenticates the user and returns an Identity.
//  2. Required is consulted. If false, the session is issued as before.
//  3. Otherwise the identity is parked in a short-lived pending session, a
//     separate cookie is set, and the response says mfa_required.
//  4. The client posts the second factor to {base}login/mfa.
//  5. Verify passes, and only then is the real session issued.
//
// The pending session is stored through the same issuer as a real one, so it
// inherits whatever persistence and encryption the deployment configured. It
// is not usable as a session: Auth.Require rejects it.
type SecondFactor interface {
	// Required reports whether id must complete a second factor.
	//
	// An error fails the login closed. Answering "no" on a database outage
	// would turn an outage into an authentication bypass.
	Required(ctx context.Context, id *identity.Identity) (bool, error)

	// Verify checks the challenge response carried on r.
	//
	// Return nil to complete the login. Return an error to reject it; the
	// caller writes the response, so Verify must not.
	Verify(ctx context.Context, r *http.Request, id *identity.Identity) error
}

// SecondFactorFunc adapts two functions to SecondFactor.
type SecondFactorFunc struct {
	RequiredFn func(context.Context, *identity.Identity) (bool, error)
	VerifyFn   func(context.Context, *http.Request, *identity.Identity) error
}

// Required implements SecondFactor.
func (f SecondFactorFunc) Required(ctx context.Context, id *identity.Identity) (bool, error) {
	if f.RequiredFn == nil {
		return false, nil
	}

	return f.RequiredFn(ctx, id)
}

// Verify implements SecondFactor.
func (f SecondFactorFunc) Verify(ctx context.Context, r *http.Request, id *identity.Identity) error {
	if f.VerifyFn == nil {
		return errors.New("auth: second factor has no verifier")
	}

	return f.VerifyFn(ctx, r, id)
}

// MFAConfig tunes the second-factor step.
type MFAConfig struct {
	// CookieName is the pending-login cookie. Default "auth_mfa".
	CookieName string `cfg:"cookie_name"`

	// TTL is how long the user has to complete the second factor.
	// Default 5 minutes.
	TTL time.Duration `cfg:"ttl"`

	// MaxAttempts is how many wrong codes are tolerated before the pending
	// login is destroyed and the user has to start over. Default 5.
	//
	// A TOTP code is six digits. Without a cap, an attacker holding a stolen
	// password walks the whole space inside the pending window.
	MaxAttempts int `cfg:"max_attempts"`
}

func (c MFAConfig) withDefaults() MFAConfig {
	if c.CookieName == "" {
		c.CookieName = "auth_mfa"
	}

	if c.TTL <= 0 {
		c.TTL = 5 * time.Minute
	}

	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 5
	}

	return c
}

// pendingProvider marks an identity as half-authenticated.
//
// It is written into Identity.Provider's sibling claim rather than Provider
// itself, so the original strategy name survives to the finished session.
const pendingClaim = "__auth_mfa_pending"

// WithSecondFactor enables the MFA step. Must be called before Init.
func (a *Auth) WithSecondFactor(sf SecondFactor) *Auth {
	a.secondFactor = sf

	return a
}

// mfaCookieOptions is the policy for the pending-login cookie.
//
// It is scoped to the MFA endpoint's path so it is not attached to every
// request in the application, and it lives for the pending TTL only.
func (a *Auth) mfaCookieOptions() cookie.Options {
	opts := a.cfg.Cookie
	opts.Path = a.resolvedPaths.MFA
	opts.MaxAge = int(a.cfg.MFA.TTL / time.Second)
	opts.DisableHTTPOnly = false

	return opts.WithDefaults()
}

// beginSecondFactor parks the identity and tells the client to send a code.
// It returns true when it has taken over the response.
func (a *Auth) beginSecondFactor(w http.ResponseWriter, r *http.Request, id *identity.Identity, strategyName string) bool {
	if a.secondFactor == nil {
		return false
	}

	required, err := a.secondFactor.Required(r.Context(), id)
	if err != nil {
		slog.Error("auth: second factor check failed", "strategy", strategyName, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "mfa_check_failed", "could not determine second-factor requirement")

		return true
	}

	if !required {
		return false
	}

	pending := *id
	pending.Claims = cloneClaims(id.Claims)
	pending.Claims[pendingClaim] = strategyName

	// Park it in the issuer so it inherits the configured storage. The TTL is
	// the MFA window, not the session TTL.
	pair, err := a.issuePending(r.Context(), &pending)
	if err != nil {
		slog.Error("auth: park pending login", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "issue_failed", "could not start second-factor step")

		return true
	}

	a.mfaCookieOptions().Set(w, r, a.cfg.MFA.CookieName, pair.SessionID)

	writeJSON(w, http.StatusOK, map[string]any{
		"strategy":      strategyName,
		"mfa_required":  true,
		"mfa_url":       a.resolvedPaths.MFA,
		"redirect_path": session.SafeRedirectPath(r.URL.Query().Get("redirect_path")),
	})

	return true
}

// issuePending mints a session whose only purpose is to hold the identity
// between the first and second factor.
func (a *Auth) issuePending(ctx context.Context, id *identity.Identity) (*issuer.Pair, error) {
	pendingIssuer := a.pendingIssuer
	if pendingIssuer == nil {
		pendingIssuer = a.issuer
	}

	pair, err := pendingIssuer.Issue(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("auth: issue pending: %w", err)
	}

	return pair, nil
}

// handleMFA completes a parked login.
func (a *Auth) handleMFA(w http.ResponseWriter, r *http.Request) {
	if a.secondFactor == nil {
		writeError(w, http.StatusNotFound, "mfa_disabled", "second factor is not configured")

		return
	}

	c, err := r.Cookie(a.cfg.MFA.CookieName)
	if err != nil || c.Value == "" {
		writeError(w, http.StatusUnauthorized, "no_pending_login", "no pending login")

		return
	}

	pendingIssuer := a.pendingIssuer
	if pendingIssuer == nil {
		pendingIssuer = a.issuer
	}

	pair, err := pendingIssuer.Resolve(r.Context(), c.Value)
	if err != nil || pair.Identity == nil {
		a.clearMFACookie(w, r)
		writeError(w, http.StatusUnauthorized, "no_pending_login", "pending login expired")

		return
	}

	strategyName, ok := pair.Identity.Claims[pendingClaim].(string)
	if !ok {
		// Somebody handed us a real session ID. Refusing it keeps the MFA
		// endpoint from being a way to re-confirm an existing session.
		a.clearMFACookie(w, r)
		writeError(w, http.StatusUnauthorized, "no_pending_login", "no pending login")

		return
	}

	if a.mfaAttempts(pair.Identity) >= a.cfg.MFA.MaxAttempts {
		_ = pendingIssuer.Revoke(r.Context(), c.Value)
		a.clearMFACookie(w, r)
		writeError(w, http.StatusTooManyRequests, "too_many_attempts", "too many failed codes, start over")

		return
	}

	final := *pair.Identity
	final.Claims = cloneClaims(pair.Identity.Claims)
	delete(final.Claims, pendingClaim)
	delete(final.Claims, attemptsClaim)

	if len(final.Claims) == 0 {
		final.Claims = nil
	}

	if err := a.secondFactor.Verify(r.Context(), r, &final); err != nil {
		a.recordMFAFailure(r.Context(), pendingIssuer, pair)
		writeError(w, http.StatusUnauthorized, "mfa_invalid", "invalid code")

		return
	}

	// The pending session has done its job.
	if err := pendingIssuer.Revoke(r.Context(), c.Value); err != nil {
		slog.Warn("auth: revoke pending login", "error", err.Error())
	}

	a.clearMFACookie(w, r)

	// Reset the clock: the session starts now, not when the password was
	// entered.
	final.IssuedAt = time.Now()
	final.ExpiresAt = time.Time{}

	real, err := a.issuer.Issue(r.Context(), &final)
	if err != nil {
		slog.Error("auth: issue session", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "issue_failed", err.Error())

		return
	}

	a.session.IssueCookie(w, r, real.SessionID)
	a.setSuccessCookie(w, r)

	writeJSON(w, http.StatusOK, map[string]any{
		"strategy":      strategyName,
		"redirect_path": session.SafeRedirectPath(r.URL.Query().Get("redirect_path")),
	})
}

const attemptsClaim = "__auth_mfa_attempts"

func (a *Auth) mfaAttempts(id *identity.Identity) int {
	if id == nil || id.Claims == nil {
		return 0
	}

	switch v := id.Claims[attemptsClaim].(type) {
	case int:
		return v
	case float64: // survives a JSON round-trip through the backend
		return int(v)
	}

	return 0
}

// recordMFAFailure increments the attempt counter on the parked login.
//
// A custom Issuer that does not implement issuer.Updater cannot persist the
// counter, so the cap does not apply. That is a real hole, and it is logged
// once per failure rather than silently tolerated.
func (a *Auth) recordMFAFailure(ctx context.Context, iss issuer.Issuer, pair *issuer.Pair) {
	updater, ok := iss.(issuer.Updater)
	if !ok {
		slog.Warn("auth: issuer cannot record MFA attempts; the attempt cap is not enforced",
			"issuer", fmt.Sprintf("%T", iss))

		return
	}

	_, err := updater.Update(ctx, pair.SessionID, func(id *identity.Identity) error {
		id.Claims = cloneClaims(id.Claims)
		id.Claims[attemptsClaim] = a.mfaAttempts(id) + 1

		return nil
	})
	if err != nil {
		slog.Debug("auth: record mfa failure", "error", err.Error())
	}
}

func (a *Auth) clearMFACookie(w http.ResponseWriter, r *http.Request) {
	a.mfaCookieOptions().Clear(w, r, a.cfg.MFA.CookieName)
}

func cloneClaims(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+2)
	for k, v := range in {
		out[k] = v
	}

	return out
}

// PendingIdentity reports whether id is a half-authenticated placeholder.
//
// Auth.Require uses it to make sure a pending session ID, if it ever reaches
// the session cookie, is not mistaken for a completed login.
func PendingIdentity(id *identity.Identity) bool {
	if id == nil || id.Claims == nil {
		return false
	}

	_, ok := id.Claims[pendingClaim]

	return ok
}
