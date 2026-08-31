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
// Signature algorithms: ES256/384/512, RS256/384/512, PS256/384/512
// and EdDSA (Ed25519).
//
// Unsupported (deliberate, not bugs):
//   - tpm, android-key, android-safetynet, apple, fido-u2f
//   - ECDAA
//
// x5c chains are parsed but not validated against a trust anchor:
// there is no metadata service here, so an attestation certificate
// proves only that the authenticator holds its private key.
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

// cloneConfig applies defaults to an owned copy and validates it. New must not
// mutate or retain caller-owned slices because they define authentication policy.
func cloneConfig(c *Config) (*Config, error) {
	if c == nil {
		return nil, errors.New("passkey: nil config")
	}

	cloned := *c
	cloned.RPOrigins = append([]string(nil), c.RPOrigins...)
	cloned.Algorithms = append([]CredentialAlgorithm(nil), c.Algorithms...)
	if cloned.UserVerification == "" {
		cloned.UserVerification = UVPreferred
	}
	if cloned.ChallengeTTL <= 0 {
		cloned.ChallengeTTL = 5 * time.Minute
	}
	if len(cloned.Algorithms) == 0 {
		cloned.Algorithms = append([]CredentialAlgorithm(nil), DefaultAlgorithms...)
	}

	if err := cloned.validate(); err != nil {
		return nil, err
	}
	return &cloned, nil
}

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
	if !c.UserVerification.valid() {
		return fmt.Errorf("passkey: invalid UserVerification %q", c.UserVerification)
	}
	if len(c.Algorithms) == 0 {
		return errors.New("passkey: at least one credential algorithm is required")
	}

	seenAlgorithms := make(map[int]struct{}, len(c.Algorithms))
	for _, algorithm := range c.Algorithms {
		if !supportedCredentialAlgorithm(algorithm.COSE) {
			return fmt.Errorf("passkey: unsupported credential algorithm %d", algorithm.COSE)
		}
		if _, duplicate := seenAlgorithms[algorithm.COSE]; duplicate {
			return fmt.Errorf("passkey: duplicate credential algorithm %d", algorithm.COSE)
		}
		seenAlgorithms[algorithm.COSE] = struct{}{}
	}
	return nil
}

func (u UserVerification) valid() bool {
	switch u {
	case UVRequired, UVPreferred, UVDiscouraged:
		return true
	default:
		return false
	}
}

func supportedCredentialAlgorithm(algorithm int) bool {
	switch algorithm {
	case algES256, algES384, algES512,
		algRS256, algRS384, algRS512,
		algPS256, algPS384, algPS512,
		algEdDSA:
		return true
	default:
		return false
	}
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

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

func cloneByteSlices(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	cloned := make([][]byte, len(values))
	for i, value := range values {
		cloned[i] = cloneBytes(value)
	}
	return cloned
}

func cloneSessionData(data *SessionData) *SessionData {
	if data == nil {
		return nil
	}
	cloned := *data
	cloned.Challenge = cloneBytes(data.Challenge)
	cloned.UserHandle = cloneBytes(data.UserHandle)
	cloned.AllowedCredentialIDs = cloneByteSlices(data.AllowedCredentialIDs)
	return &cloned
}
