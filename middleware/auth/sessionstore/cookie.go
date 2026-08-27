package sessionstore

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var (
	ErrInvalidCookie = errors.New("invalid session cookie")
	ErrInvalidMAC    = errors.New("invalid session cookie signature")
)

// CookieCodec handles encoding/decoding of session ID cookies with HMAC signing.
type CookieCodec struct {
	// HashKey is used for HMAC signing. Must be at least 32 bytes.
	HashKey []byte
}

// NewCookieCodec creates a new CookieCodec with the given hash key.
func NewCookieCodec(hashKey []byte) *CookieCodec {
	return &CookieCodec{HashKey: hashKey}
}

// Encode creates a signed cookie value from a session ID.
// Format: base64(sessionID) | base64(HMAC-SHA256(name|sessionID))
func (c *CookieCodec) Encode(name, sessionID string) string {
	b64ID := base64.RawURLEncoding.EncodeToString([]byte(sessionID))
	mac := c.computeMAC(name, sessionID)
	b64MAC := base64.RawURLEncoding.EncodeToString(mac)

	return b64ID + "|" + b64MAC
}

// Decode verifies and extracts the session ID from a cookie value.
func (c *CookieCodec) Decode(name, cookieValue string) (string, error) {
	parts := strings.SplitN(cookieValue, "|", 2)
	if len(parts) != 2 {
		return "", ErrInvalidCookie
	}

	idBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidCookie, err)
	}

	macBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidCookie, err)
	}

	sessionID := string(idBytes)
	expectedMAC := c.computeMAC(name, sessionID)

	if !hmac.Equal(macBytes, expectedMAC) {
		return "", ErrInvalidMAC
	}

	return sessionID, nil
}

func (c *CookieCodec) computeMAC(name, sessionID string) []byte {
	mac := hmac.New(sha256.New, c.HashKey)
	mac.Write([]byte(name + "|" + sessionID))

	return mac.Sum(nil)
}

// GenerateSessionID creates a cryptographically random session ID.
//
// The ID carries no structure on purpose: an earlier version prefixed it with
// the creation timestamp, which leaked session age to anyone who saw the
// cookie.
func GenerateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sessionstore: read random: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SetSessionCookie writes the session cookie to the response.
func SetSessionCookie(w http.ResponseWriter, name, value string, opts *Options) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     opts.Path,
		Domain:   opts.Domain,
		MaxAge:   opts.MaxAge,
		Secure:   opts.Secure,
		HttpOnly: opts.HttpOnly,
		SameSite: opts.SameSite,
	}

	http.SetCookie(w, cookie)
}

// ReadSessionCookie reads the session cookie from the request.
func ReadSessionCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}

	return cookie.Value, nil
}

// NewRandomKey generates a random key of the given length, reporting failure.
func NewRandomKey(length int) ([]byte, error) {
	k := make([]byte, length)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("sessionstore: read random: %w", err)
	}

	return k, nil
}

// GenerateRandomKey generates a random key of the given length.
//
// Deprecated: it cannot report an RNG failure — a nil key would silently be
// used as an HMAC key. Use NewRandomKey.
func GenerateRandomKey(length int) []byte {
	k, err := NewRandomKey(length)
	if err != nil {
		panic(err)
	}

	return k
}
