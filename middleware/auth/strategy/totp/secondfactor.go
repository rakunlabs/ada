package totp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

// SecretLookup returns the enrolled TOTP secret for an identity.
//
// Return ErrNotEnrolled when the user has no secret; the SecondFactor then
// reports that no second factor is required, which is what lets a deployment
// roll TOTP out per user instead of all at once.
type SecretLookup func(ctx context.Context, id *identity.Identity) (*Secret, error)

// RecoveryConsumer checks and consumes a single-use recovery code.
//
// It must be atomic: two concurrent requests presenting the same code must not
// both succeed. Return false to reject.
type RecoveryConsumer func(ctx context.Context, id *identity.Identity, code string) (bool, error)

// ErrNotEnrolled means the identity has no TOTP secret.
var ErrNotEnrolled = errors.New("totp: not enrolled")

// ErrReplayed means the code was already used within its window.
var ErrReplayed = errors.New("totp: code already used")

// SecondFactor implements auth.SecondFactor using TOTP.
//
// It closes the two gaps that made the bare primitive unusable as a second
// factor: there was no place in the login flow to demand a code, and Verify
// had no replay protection — a six-digit code stays valid for the whole skew
// window, so an attacker who observes one can use it again inside that window.
type SecondFactor struct {
	cfg    Config
	lookup SecretLookup

	recovery RecoveryConsumer

	used *usedCodes

	// Field is the JSON/form key carrying the code. Default "code".
	Field string

	// RecoveryField is the key carrying a recovery code. Default
	// "recovery_code".
	RecoveryField string
}

// NewSecondFactor returns a TOTP second factor.
//
// cfg may be the zero value, in which case Default() applies.
func NewSecondFactor(cfg Config, lookup SecretLookup, opts ...SecondFactorOption) *SecondFactor {
	if cfg.Period == 0 && cfg.Digits == 0 && cfg.Algorithm == "" {
		cfg = Default()
	}

	sf := &SecondFactor{
		cfg:           cfg,
		lookup:        lookup,
		used:          newUsedCodes(),
		Field:         "code",
		RecoveryField: "recovery_code",
	}

	for _, o := range opts {
		o(sf)
	}

	return sf
}

// SecondFactorOption configures a SecondFactor.
type SecondFactorOption func(*SecondFactor)

// WithRecoveryCodes accepts single-use recovery codes as an alternative to a
// TOTP code.
//
// Without one, a lost phone is a lost account, and the support process that
// grows in its place is usually a worse authenticator than the one it
// replaces.
func WithRecoveryCodes(fn RecoveryConsumer) SecondFactorOption {
	return func(sf *SecondFactor) { sf.recovery = fn }
}

// Close stops the replay cache's sweeper.
func (sf *SecondFactor) Close() error { return sf.used.Close() }

// Required reports whether the identity has an enrolled secret.
func (sf *SecondFactor) Required(ctx context.Context, id *identity.Identity) (bool, error) {
	if sf.lookup == nil {
		return false, nil
	}

	_, err := sf.lookup(ctx, id)

	switch {
	case errors.Is(err, ErrNotEnrolled):
		return false, nil
	case err != nil:
		// Fail closed: an unreadable enrolment store must not silently
		// downgrade everyone to single-factor.
		return false, fmt.Errorf("totp: lookup secret: %w", err)
	}

	return true, nil
}

// Verify checks the submitted code.
func (sf *SecondFactor) Verify(ctx context.Context, r *http.Request, id *identity.Identity) error {
	code, recovery, err := sf.readCode(r)
	if err != nil {
		return err
	}

	if recovery != "" {
		if sf.recovery == nil {
			return errors.New("totp: recovery codes are not configured")
		}

		ok, err := sf.recovery(ctx, id, recovery)
		if err != nil {
			return fmt.Errorf("totp: consume recovery code: %w", err)
		}

		if !ok {
			return ErrInvalidCode
		}

		return nil
	}

	secret, err := sf.lookup(ctx, id)
	if err != nil {
		return fmt.Errorf("totp: lookup secret: %w", err)
	}

	now := time.Now()

	if !sf.cfg.Verify(secret, code, now) {
		return ErrInvalidCode
	}

	// A code is valid for the whole skew window. Marking it used closes the
	// replay hole the primitive deliberately leaves to its caller.
	if !sf.used.claim(id.Subject, code, sf.window(now)) {
		return ErrReplayed
	}

	return nil
}

// window is how long a used code must be remembered: the validity period plus
// the skew on both sides, with a little slack.
func (sf *SecondFactor) window(now time.Time) time.Time {
	period := sf.cfg.Period
	if period <= 0 {
		period = 30 * time.Second
	}

	skew := time.Duration(sf.cfg.Skew) * period

	return now.Add(period + 2*skew + period)
}

// ErrInvalidCode is returned when the submitted code does not verify.
var ErrInvalidCode = errors.New("totp: invalid code")

func (sf *SecondFactor) readCode(r *http.Request) (code, recovery string, err error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<14))
	if err != nil {
		return "", "", fmt.Errorf("totp: read body: %w", err)
	}

	ct := r.Header.Get("Content-Type")

	switch {
	case strings.HasPrefix(ct, "application/json"):
		var m map[string]string
		if err := json.Unmarshal(body, &m); err != nil {
			return "", "", fmt.Errorf("totp: decode json: %w", err)
		}

		code, recovery = m[sf.Field], m[sf.RecoveryField]

	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return "", "", fmt.Errorf("totp: parse form: %w", err)
		}

		code, recovery = values.Get(sf.Field), values.Get(sf.RecoveryField)

	default:
		return "", "", fmt.Errorf("totp: unsupported content type %q", ct)
	}

	code = strings.TrimSpace(code)
	recovery = strings.TrimSpace(recovery)

	if code == "" && recovery == "" {
		return "", "", errors.New("totp: no code supplied")
	}

	return code, recovery, nil
}

// usedCodes remembers recently accepted codes per subject.
//
// In-process, like the rest of the defaults: with several replicas, a code can
// be replayed once per replica. Supply a shared implementation if that matters
// — but note that even the in-process version closes the window that matters
// most, which is an attacker replaying against the same instance they
// observed.
type usedCodes struct {
	mu      sync.Mutex
	entries map[string]time.Time

	stop   chan struct{}
	done   chan struct{}
	closed sync.Once
}

func newUsedCodes() *usedCodes {
	u := &usedCodes{
		entries: make(map[string]time.Time),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}

	go u.janitor()

	return u
}

func (u *usedCodes) claim(subject, code string, until time.Time) bool {
	key := subject + "\x00" + code

	u.mu.Lock()
	defer u.mu.Unlock()

	if exp, ok := u.entries[key]; ok && time.Now().Before(exp) {
		return false
	}

	u.entries[key] = until

	return true
}

func (u *usedCodes) Close() error {
	u.closed.Do(func() { close(u.stop) })
	<-u.done

	return nil
}

func (u *usedCodes) janitor() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	defer close(u.done)

	for {
		select {
		case <-u.stop:
			return
		case now := <-t.C:
			u.mu.Lock()

			for k, exp := range u.entries {
				if now.After(exp) {
					delete(u.entries, k)
				}
			}

			u.mu.Unlock()
		}
	}
}
