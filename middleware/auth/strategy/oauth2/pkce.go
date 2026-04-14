package oauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// PKCE (Proof Key for Code Exchange) prevents authorization code interception.
// RFC 7636: https://tools.ietf.org/html/rfc7636

// pkceParams holds the verifier/challenge pair for one authorization request.
type pkceParams struct {
	Verifier  string // stored in cookie alongside state
	Challenge string // sent to the authorize endpoint
	Method    string // always "S256"
}

// newPKCE generates a fresh PKCE verifier and its S256 challenge.
func newPKCE() (*pkceParams, error) {
	// RFC 7636 §4.1: verifier is 43-128 chars of [A-Z][a-z][0-9]-._~
	// We use 32 random bytes → 43 base64url chars.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	verifier := base64.RawURLEncoding.EncodeToString(b)

	// RFC 7636 §4.2: challenge = BASE64URL(SHA256(verifier))
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	return &pkceParams{
		Verifier:  verifier,
		Challenge: challenge,
		Method:    "S256",
	}, nil
}
