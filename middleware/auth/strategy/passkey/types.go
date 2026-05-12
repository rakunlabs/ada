// Package passkey implements WebAuthn (FIDO2) registration and login
// for the ada auth middleware. It is intentionally dependency-free:
// the entire CBOR/COSE/attestation stack is implemented in this
// package using only the Go standard library.
//
// Supported algorithms:
//   - ES256/ES384/ES512 (ECDSA with NIST curves)
//   - RS256/RS384/RS512 (RSA with PKCS#1 v1.5)
//   - PS256/PS384/PS512 (RSA-PSS)
//
// Supported attestation formats:
//   - "none" (recommended; what platform authenticators emit)
//   - "packed" with self attestation or x5c basic attestation
//
// Unsupported (deliberate, not bugs):
//   - tpm, android-key, android-safetynet, apple, fido-u2f
//   - EdDSA / OKP keys
//   - ECDAA
//
// These cover the bulk of real-world deployments. Adding more
// attestation formats is straightforward — slot them into the
// switch in verifyAttestation.
package passkey

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Config is the relying-party configuration. RPID is the effective
// domain (no scheme, no port — e.g. "example.com" or "localhost").
// RPOrigins is the set of allowed origins emitted by the user agent
// in clientDataJSON (e.g. "https://example.com", "https://example.com:8443").
//
// RPDisplayName is shown to the user in the platform passkey UI.
// UserVerification controls whether the authenticator must verify
// the user (biometric / PIN) — "preferred" is the WebAuthn default
// and lets the authenticator decide.
//
// ChallengeTTL is how long a registration or login challenge stays
// valid. 5 minutes is the typical sweet spot — long enough for a
// user to plug in a hardware key and tap, short enough that a
// stolen challenge has minimal replay window.
type Config struct {
	RPID             string
	RPDisplayName    string
	RPOrigins        []string
	UserVerification UserVerification
	ChallengeTTL     time.Duration

	// Algorithms is the public-key algorithm preference list sent to
	// the authenticator at registration. The first algorithm the
	// authenticator supports wins. Empty means DefaultAlgorithms.
	Algorithms []CredentialAlgorithm
}

// UserVerification mirrors the WebAuthn enum.
type UserVerification string

const (
	// UVRequired forces a user-verifying gesture (PIN/biometric) at
	// every ceremony. Use this when passkey is the sole credential
	// or you want explicit step-up.
	UVRequired UserVerification = "required"
	// UVPreferred asks the authenticator to do UV when it can, but
	// accepts UP-only when not. This is the WebAuthn default.
	UVPreferred UserVerification = "preferred"
	// UVDiscouraged hints "don't bother the user". Rare in practice
	// because most authenticators do UV anyway.
	UVDiscouraged UserVerification = "discouraged"
)

// validate fills defaults and rejects misconfiguration up front.
// A nil receiver is an error — the caller MUST construct a config
// before invoking ceremony methods.
func (c *Config) validate() error {
	if c == nil {
		return errors.New("passkey: nil config")
	}
	if c.RPID == "" {
		return errors.New("passkey: RPID is required")
	}
	// We don't validate the RPID against RFC 1035 here because some
	// callers use "localhost" for dev, which is technically a valid
	// host label but trips up overly-strict validators. The browser
	// will reject anything truly malformed.
	if strings.ContainsAny(c.RPID, "/:?#") {
		return fmt.Errorf("passkey: RPID %q must be a bare host, not a URL", c.RPID)
	}
	if len(c.RPOrigins) == 0 {
		return errors.New("passkey: at least one RPOrigin is required")
	}
	if c.UserVerification == "" {
		c.UserVerification = UVPreferred
	}
	if c.ChallengeTTL <= 0 {
		c.ChallengeTTL = 5 * time.Minute
	}
	if len(c.Algorithms) == 0 {
		c.Algorithms = DefaultAlgorithms
	}
	return nil
}

// User is the relying-party's view of the user enrolling or signing
// in via WebAuthn. The Handle is the opaque per-user identifier the
// authenticator stores alongside the credential (up to 64 bytes,
// MUST NOT be a username — see WebAuthn §5.4.3). Name and DisplayName
// are shown in the platform UI.
//
// Pika uses the user_id (16-byte random hex string) as the handle.
// The handle must be stable for the lifetime of the user account.
type User struct {
	Handle      []byte
	Name        string
	DisplayName string
}

// Credential is the persistent state for one enrolled passkey. The
// caller stores it after a successful registration ceremony and
// hands it back at login time. PublicKey is the raw CBOR COSE_Key —
// we re-parse it on every verification rather than caching a parsed
// form because the cost is negligible and round-tripping through a
// parsed shape adds bug surface.
//
// SignCount is updated after every successful login (see
// FinishLogin's returned value). A sign-count that goes backwards
// across logins indicates a cloned authenticator and is policy-
// rejected.
type Credential struct {
	ID              []byte
	UserHandle      []byte
	PublicKey       []byte
	AAGUID          []byte
	SignCount       uint32
	Transports      []string
	AttestationType string
	BackupEligible  bool
	BackupState     bool
	UserVerified    bool
}

// SessionData is the opaque blob a Begin call returns alongside the
// client-bound options. The caller persists it (in a short-TTL
// store, keyed by an opaque session id handed to the client) and
// hands it back to Finish to defeat replay and same-origin CSRF.
//
// Fields are exported for the caller's storage convenience but
// callers MUST NOT mutate them between Begin and Finish. The struct
// is JSON-serializable for storage in something like a Redis blob.
type SessionData struct {
	Challenge        []byte           `json:"challenge"`
	UserHandle       []byte           `json:"user_handle,omitempty"`
	UserVerification UserVerification `json:"uv"`
	Expires          time.Time        `json:"expires"`
	// AllowedCredentialIDs is populated by the login ceremony when
	// the RP knows which user is signing in (i.e. non-discoverable
	// flow). Empty means "any credential the authenticator offers".
	AllowedCredentialIDs [][]byte `json:"allowed,omitempty"`
}

// expired reports whether the session has passed its TTL. The Finish
// path checks this before doing any cryptographic work, so an
// attacker can't burn server CPU by submitting expired ceremonies.
func (s *SessionData) expired(now time.Time) bool {
	return !s.Expires.IsZero() && s.Expires.Before(now)
}
