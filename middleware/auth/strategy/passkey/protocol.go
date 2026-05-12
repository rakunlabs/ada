package passkey

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// collectedClientData is the JSON-encoded blob the user agent passes
// alongside an authenticator response. The browser populates Type,
// Challenge, Origin and CrossOrigin; tokenBinding is informational
// only and modern browsers (post-2023) omit it.
//
// WebAuthn §6.5: the RP must verify the type, challenge, and origin
// match what it issued. We do that in verifyClientData.
type collectedClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
	TopOrigin   string `json:"topOrigin,omitempty"`
}

// expected types for the two ceremonies. The spec is strict: a
// registration response MUST carry type "webauthn.create" and an
// assertion response "webauthn.get". A type mismatch defeats the
// "type confusion" attack where a recorded registration response is
// replayed as a login.
const (
	clientDataTypeCreate = "webauthn.create"
	clientDataTypeGet    = "webauthn.get"
)

// verifyClientData parses and validates a clientDataJSON blob against
// the expected type, challenge and allowed origins. Returns the
// SHA-256 hash of the raw blob (used later as input to authenticator
// data signature verification).
//
// IMPORTANT: hashing is over the *raw* blob, not the re-serialized
// JSON. WebAuthn binds the signature to the exact byte sequence the
// authenticator saw, so any whitespace/order normalization would
// break the verification chain.
//
// Unknown fields are deliberately tolerated. WebAuthn §5.8.1 (and the
// W3C example clientDataJSON) explicitly seeds the structure with a
// placeholder key named "other_keys_can_be_added_here" as a trap for
// implementers tempted to do strict template matching — the spec
// mandates that RPs MUST ignore members they don't recognize so the
// format can be extended without breaking existing servers. Several
// shipping authenticators (some mobile password managers, virtual
// authenticator extensions) emit this literal key, plus legacy
// browsers may still emit "tokenBinding". DisallowUnknownFields was
// previously used here and rejected all of them; we now lean on the
// default lenient decode and only check Type/Challenge/Origin.
func verifyClientData(raw []byte, expectedType string, expectedChallenge []byte, allowedOrigins []string) ([32]byte, error) {
	var cd collectedClientData
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&cd); err != nil {
		return [32]byte{}, fmt.Errorf("client data: parse json: %w", err)
	}
	if dec.More() {
		return [32]byte{}, errors.New("client data: trailing content after json object")
	}

	if cd.Type != expectedType {
		return [32]byte{}, fmt.Errorf("client data: type %q does not match expected %q", cd.Type, expectedType)
	}

	// Challenge is URL-safe base64 without padding (RFC 4648 §5).
	chal, err := decodeBase64URL(cd.Challenge)
	if err != nil {
		return [32]byte{}, fmt.Errorf("client data: decode challenge: %w", err)
	}
	if !constantTimeBytesEqual(chal, expectedChallenge) {
		return [32]byte{}, errors.New("client data: challenge mismatch")
	}

	if !originAllowed(cd.Origin, allowedOrigins) {
		return [32]byte{}, fmt.Errorf("client data: origin %q not in allowed list", cd.Origin)
	}

	// We don't enforce cross-origin or topOrigin policies here — the
	// WebAuthn spec lets the RP decide, and pika's typical deployment
	// (single-origin admin UI) gets no benefit from enabling them.
	// If a future use case requires it, add a config knob rather than
	// silently allowing the value through.
	if cd.CrossOrigin {
		return [32]byte{}, errors.New("client data: cross-origin requests are not allowed")
	}

	return sha256.Sum256(raw), nil
}

// authenticator data flag bits (WebAuthn §6.1).
const (
	flagUserPresent            = 0x01
	flagUserVerified           = 0x04
	flagBackupEligible         = 0x08
	flagBackupState            = 0x10
	flagAttestedCredentialData = 0x40
	flagExtensionData          = 0x80
)

// authenticatorData is the parsed authenticator data blob. The
// rpIDHash is verified during ceremony validation; flags and
// signCount are surfaced for storage and replay-detection; the
// optional attestedCredentialData carries the new credential's id +
// COSE public key during registration.
type authenticatorData struct {
	RPIDHash           [32]byte
	Flags              byte
	SignCount          uint32
	AttestedCredential *attestedCredentialData // nil when AT flag is unset
	Raw                []byte                  // verbatim blob for signature input
}

// attestedCredentialData is the variable-length block embedded in the
// registration response's authenticator data. The COSE_Key portion
// has no fixed length so we slice out the public-key suffix and
// hand it to the COSE parser separately.
type attestedCredentialData struct {
	AAGUID        [16]byte
	CredentialID  []byte
	PublicKeyCBOR []byte // raw bytes to feed parseCOSEPublicKey
}

// parseAuthenticatorData unpacks the binary format defined in
// WebAuthn §6.1. Layout:
//
//   - 32 bytes: SHA-256(rpId)
//   - 1 byte:   flags
//   - 4 bytes:  signCount (big-endian uint32)
//   - If AT flag set:
//   - 16 bytes: AAGUID
//   - 2 bytes:  credentialIdLength (big-endian uint16)
//   - N bytes:  credentialId
//   - M bytes:  COSE_Key (CBOR-encoded, variable length)
//   - If ED flag set: CBOR-encoded extension map (we skip)
//
// The COSE_Key length is implicit — we have to parse it as a CBOR
// data item and consume exactly as many bytes as it occupies. The
// CBOR decoder returns the byte count so we can split the key from
// the trailing extension data cleanly.
func parseAuthenticatorData(blob []byte) (*authenticatorData, error) {
	if len(blob) < 37 {
		return nil, fmt.Errorf("authenticator data: too short (%d bytes, need ≥37)", len(blob))
	}

	ad := &authenticatorData{
		Flags:     blob[32],
		SignCount: binary.BigEndian.Uint32(blob[33:37]),
		Raw:       blob,
	}
	copy(ad.RPIDHash[:], blob[0:32])

	off := 37
	if ad.Flags&flagAttestedCredentialData != 0 {
		if len(blob) < off+18 {
			return nil, errors.New("authenticator data: truncated attested credential header")
		}
		acd := &attestedCredentialData{}
		copy(acd.AAGUID[:], blob[off:off+16])
		off += 16

		credIDLen := int(binary.BigEndian.Uint16(blob[off : off+2]))
		off += 2

		if credIDLen == 0 || credIDLen > 1023 {
			// WebAuthn §6.5.2 caps credential IDs at 1023 bytes.
			return nil, fmt.Errorf("authenticator data: credential id length %d out of bounds", credIDLen)
		}
		if len(blob) < off+credIDLen {
			return nil, errors.New("authenticator data: truncated credential id")
		}
		acd.CredentialID = make([]byte, credIDLen)
		copy(acd.CredentialID, blob[off:off+credIDLen])
		off += credIDLen

		// The COSE_Key is the next CBOR data item. We parse it to
		// determine its byte length, then store the raw slice.
		// Subsequent verification (parseCOSEPublicKey) re-parses it.
		_, n, err := decodeCBOR(blob[off:])
		if err != nil {
			return nil, fmt.Errorf("authenticator data: cose public key: %w", err)
		}
		acd.PublicKeyCBOR = make([]byte, n)
		copy(acd.PublicKeyCBOR, blob[off:off+n])
		off += n

		ad.AttestedCredential = acd
	}

	// We silently skip extension data — none of the extensions
	// emitted by current authenticators (credProps, etc.) affect
	// pika's authentication flow. A future need to inspect them
	// would slot in here.
	_ = off

	return ad, nil
}

// verifyRPIDHash compares the rpIdHash in authenticator data against
// SHA-256 of the configured RP ID. A mismatch means either the
// authenticator was registered with a different RP (cookie confusion
// attack) or the configured RP ID is wrong.
func verifyRPIDHash(ad *authenticatorData, rpID string) error {
	want := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(ad.RPIDHash[:], want[:]) {
		return errors.New("authenticator data: rpIdHash does not match configured RP ID")
	}
	return nil
}

// originAllowed reports whether the given origin matches one of the
// allowed origins. We do an exact string compare — RFC 3986 origin
// canonicalization (port/scheme/host) is the caller's responsibility,
// because the only sane configuration is a fixed list of origins
// the RP issues, not a wildcard.
//
// Empty allow-list disables every login attempt, which is the right
// "fail closed" behavior for a misconfigured server.
func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == origin {
			return true
		}
	}
	return false
}
