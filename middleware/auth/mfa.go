package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
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

	// MaxAttempts is the maximum number of verification calls for one pending
	// login. Once exhausted, the pending login is unusable and the user has to
	// start over. Default 5.
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

	pendingIssuer := a.pendingIssuer
	if pendingIssuer == nil {
		pendingIssuer = a.issuer
	}
	if _, ok := pendingIssuer.(issuer.Updater); !ok {
		slog.Error("auth: issuer cannot persist MFA attempt state", "issuer", fmt.Sprintf("%T", pendingIssuer))
		writeError(w, http.StatusInternalServerError, "mfa_persistence_unavailable", "could not enforce second-factor attempt limits")

		return true
	}

	pending := *id
	pending.Claims = cloneClaims(id.Claims)
	delete(pending.Claims, pendingClaim)
	delete(pending.Claims, pendingExpiresClaim)
	delete(pending.Claims, attemptsClaim)
	delete(pending.Claims, completedClaim)
	pending.Claims[pendingClaim] = strategyName
	pending.Claims[pendingExpiresClaim] = time.Now().Add(a.cfg.MFA.TTL).UTC().Format(time.RFC3339Nano)
	pending.Claims[attemptsClaim] = 0

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

	updater, ok := pendingIssuer.(issuer.Updater)
	if !ok {
		slog.Error("auth: issuer cannot persist MFA attempt state", "issuer", fmt.Sprintf("%T", pendingIssuer))
		writeError(w, http.StatusInternalServerError, "mfa_persistence_unavailable", "could not enforce second-factor attempt limits")

		return
	}

	// Reserve and persist an attempt before invoking the verifier. Concurrent
	// requests can reserve at most MaxAttempts slots, and a storage failure
	// prevents verification rather than silently disabling the limit.
	reserveTime := time.Now()
	pair, err := updateMFA(r.Context(), updater, c.Value, func(id *identity.Identity) error {
		if id == nil || id.Claims == nil {
			return errMFANotPending
		}
		if _, ok := id.Claims[pendingClaim].(string); !ok || mfaCompleted(id) {
			return errMFANotPending
		}
		if !mfaPendingActive(id, reserveTime) {
			return errMFAPendingExpired
		}
		attempts, err := mfaAttempts(id)
		if err != nil {
			return errMFAAttemptsInvalid
		}
		if attempts >= a.cfg.MFA.MaxAttempts {
			return errMFAAttemptsExhausted
		}

		id.Claims = cloneClaims(id.Claims)
		id.Claims[attemptsClaim] = attempts + 1

		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, errMFAAttemptsExhausted):
			a.clearMFACookie(w, r)
			writeError(w, http.StatusTooManyRequests, "too_many_attempts", "too many failed codes, start over")
		case errors.Is(err, issuer.ErrNotFound), errors.Is(err, errMFANotPending),
			errors.Is(err, errMFAPendingExpired), errors.Is(err, errMFAAttemptsInvalid):
			if errors.Is(err, errMFAPendingExpired) || errors.Is(err, errMFAAttemptsInvalid) {
				if revokeErr := pendingIssuer.Revoke(r.Context(), c.Value); revokeErr != nil {
					slog.Warn("auth: revoke invalid pending login", "error", revokeErr.Error())
				}
			}
			a.clearMFACookie(w, r)
			writeError(w, http.StatusUnauthorized, "no_pending_login", "pending login expired")
		default:
			slog.Error("auth: reserve MFA attempt", "error", err.Error())
			writeError(w, http.StatusInternalServerError, "mfa_persistence_failed", "could not persist second-factor attempt")
		}

		return
	}
	if pair == nil || pair.Identity == nil {
		writeError(w, http.StatusInternalServerError, "mfa_persistence_failed", "could not persist second-factor attempt")

		return
	}

	strategyName, _ := pair.Identity.Claims[pendingClaim].(string)

	final := *pair.Identity
	final.Claims = cloneClaims(pair.Identity.Claims)
	delete(final.Claims, pendingClaim)
	delete(final.Claims, pendingExpiresClaim)
	delete(final.Claims, attemptsClaim)

	if len(final.Claims) == 0 {
		final.Claims = nil
	}

	if err := a.secondFactor.Verify(r.Context(), r, &final); err != nil {
		writeError(w, http.StatusUnauthorized, "mfa_invalid", "invalid code")

		return
	}

	// Claim completion atomically. Multiple valid submissions may already be
	// inside Verify, but only one can persist this transition and mint a real
	// session.
	completionTime := time.Now()
	claimed, err := updateMFA(r.Context(), updater, c.Value, func(id *identity.Identity) error {
		if id == nil || id.Claims == nil {
			return errMFANotPending
		}
		if _, ok := id.Claims[pendingClaim].(string); !ok || mfaCompleted(id) {
			return errMFANotPending
		}
		if !mfaPendingActive(id, completionTime) {
			return errMFAPendingExpired
		}

		id.Claims = cloneClaims(id.Claims)
		id.Claims[completedClaim] = true

		return nil
	})
	if err != nil {
		if errors.Is(err, issuer.ErrNotFound) || errors.Is(err, errMFANotPending) || errors.Is(err, errMFAPendingExpired) {
			if errors.Is(err, errMFAPendingExpired) {
				if revokeErr := pendingIssuer.Revoke(r.Context(), c.Value); revokeErr != nil {
					slog.Warn("auth: revoke expired pending login", "error", revokeErr.Error())
				}
			}
			a.clearMFACookie(w, r)
			writeError(w, http.StatusUnauthorized, "no_pending_login", "pending login expired or already completed")
		} else {
			slog.Error("auth: claim MFA completion", "error", err.Error())
			writeError(w, http.StatusInternalServerError, "mfa_persistence_failed", "could not persist second-factor completion")
		}

		return
	}
	if claimed == nil || claimed.Identity == nil {
		writeError(w, http.StatusInternalServerError, "mfa_persistence_failed", "could not persist second-factor completion")

		return
	}

	final = *claimed.Identity
	final.Claims = cloneClaims(claimed.Identity.Claims)
	delete(final.Claims, pendingClaim)
	delete(final.Claims, pendingExpiresClaim)
	delete(final.Claims, attemptsClaim)
	delete(final.Claims, completedClaim)
	if len(final.Claims) == 0 {
		final.Claims = nil
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
		writeError(w, http.StatusInternalServerError, "issue_failed", "could not create session")

		return
	}

	a.session.IssueCookie(w, r, real.SessionID)
	a.setSuccessCookie(w, r)

	writeJSON(w, http.StatusOK, map[string]any{
		"strategy":      strategyName,
		"redirect_path": session.SafeRedirectPath(r.URL.Query().Get("redirect_path")),
	})
}

const (
	attemptsClaim       = "__auth_mfa_attempts"
	completedClaim      = "__auth_mfa_completed"
	pendingExpiresClaim = "__auth_mfa_expires"
)

var (
	errMFANotPending        = errors.New("auth: session is not pending MFA")
	errMFAAttemptsExhausted = errors.New("auth: MFA attempts exhausted")
	errMFAPendingExpired    = errors.New("auth: pending MFA session expired")
	errMFAAttemptsInvalid   = errors.New("auth: invalid MFA attempt count")
)

// updateMFA may repeat fn because both MFA state transitions are pure: all
// bookkeeping is derived from the freshly loaded identity and has no effects
// outside the transaction. Public Updater callers retain the once-per-call
// callback contract.
func updateMFA(
	ctx context.Context,
	updater issuer.Updater,
	sessionID string,
	fn func(*identity.Identity) error,
) (*issuer.Pair, error) {
	const attempts = 3

	for attempt := range attempts {
		pair, err := updater.Update(ctx, sessionID, fn)
		if !errors.Is(err, issuer.ErrTransactionConflict) || attempt+1 == attempts {
			return pair, err
		}
	}

	return nil, issuer.ErrTransactionConflict
}

func mfaAttempts(id *identity.Identity) (int, error) {
	if id == nil || id.Claims == nil {
		return 0, nil
	}

	switch v := id.Claims[attemptsClaim].(type) {
	case int:
		if v < 0 {
			return 0, errMFAAttemptsInvalid
		}

		return v, nil
	case int8:
		return checkedMFAAttempts(int64(v))
	case int16:
		return checkedMFAAttempts(int64(v))
	case int32:
		return checkedMFAAttempts(int64(v))
	case int64:
		return checkedMFAAttempts(v)
	case uint:
		return checkedUnsignedMFAAttempts(uint64(v))
	case uint8:
		return int(v), nil
	case uint16:
		return int(v), nil
	case uint32:
		return checkedUnsignedMFAAttempts(uint64(v))
	case uint64:
		return checkedUnsignedMFAAttempts(v)
	case float32:
		return checkedFloatMFAAttempts(float64(v))
	case float64: // survives a JSON round-trip through the backend
		return checkedFloatMFAAttempts(v)
	case nil:
		return 0, nil
	}

	return 0, errMFAAttemptsInvalid
}

func checkedMFAAttempts(value int64) (int, error) {
	if value < 0 || uint64(value) > uint64(^uint(0)>>1) {
		return 0, errMFAAttemptsInvalid
	}

	return int(value), nil
}

func checkedUnsignedMFAAttempts(value uint64) (int, error) {
	if value > uint64(^uint(0)>>1) {
		return 0, errMFAAttemptsInvalid
	}

	return int(value), nil
}

func checkedFloatMFAAttempts(value float64) (int, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || math.Trunc(value) != value ||
		value >= math.Exp2(strconv.IntSize-1) {
		return 0, errMFAAttemptsInvalid
	}

	return int(value), nil
}

func mfaCompleted(id *identity.Identity) bool {
	completed, _ := id.Claims[completedClaim].(bool)

	return completed
}

func mfaPendingActive(id *identity.Identity, now time.Time) bool {
	raw, ok := id.Claims[pendingExpiresClaim].(string)
	if !ok {
		return false
	}

	expiresAt, err := time.Parse(time.RFC3339Nano, raw)

	return err == nil && now.Before(expiresAt)
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
