package passkey

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// challengeLength is the minimum recommended challenge size in bytes.
// WebAuthn §13.1 requires at least 16 bytes of entropy; 32 is the
// conventional choice (it matches the output of SHA-256 and many
// authenticator implementations expect exactly that).
const challengeLength = 32

// newChallenge returns a cryptographically random challenge of
// challengeLength bytes. Used by both registration and assertion
// ceremony begin paths.
func newChallenge() ([]byte, error) {
	c := make([]byte, challengeLength)
	if _, err := rand.Read(c); err != nil {
		return nil, fmt.Errorf("passkey: read random: %w", err)
	}
	return c, nil
}

// encodeBase64URL emits the URL-safe base64 form WebAuthn uses
// throughout (RFC 4648 §5, no padding).
func encodeBase64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeBase64URL parses URL-safe base64. We accept either padded or
// unpadded input — Chrome and Safari occasionally differ, and being
// liberal here is harmless because base64 has no ambiguity.
func decodeBase64URL(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// Base64URLEncode is the exported form of encodeBase64URL. Callers
// that need to emit credential descriptors or challenges directly
// (e.g. when building exclude lists for begin-registration outside
// of this package) use this helper to keep the wire encoding
// consistent.
func Base64URLEncode(b []byte) string { return encodeBase64URL(b) }

// Base64URLDecode is the exported form of decodeBase64URL.
func Base64URLDecode(s string) ([]byte, error) { return decodeBase64URL(s) }

// constantTimeBytesEqual compares two byte slices in constant time.
// Used for challenge / credential ID comparisons where a timing-side
// channel would leak information about the secret being checked.
//
// subtle.ConstantTimeCompare bails early if the lengths differ, but
// the timing of that early exit only leaks the length — which is
// already public information for the inputs we use it on (challenge
// length, credential ID length).
func constantTimeBytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
