// Package password hashes and verifies passwords.
//
// strategy/local delegates credential checking entirely to a Verifier and
// ships nothing to build one with, which leaves every caller to reinvent
// password storage — the one place in an auth system where reinvention
// reliably goes wrong.
//
// The default algorithm is PBKDF2-HMAC-SHA256, because it is in the standard
// library and this module has no third-party dependencies. It is the weakest
// of the acceptable choices: it is memory-cheap, so a GPU attacks it far more
// efficiently than it attacks Argon2id or scrypt. If you can take the
// dependency, register an Argon2id Hasher instead; the interface exists for
// exactly that.
//
// Encoded hashes use a PHC-style string:
//
//	$pbkdf2-sha256$i=600000$<base64 salt>$<base64 hash>
//
// The parameters travel with the hash, so raising the cost later does not
// invalidate existing passwords: Verify keeps working and NeedsRehash tells
// you which ones to upgrade on next login.
package password

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Errors returned by this package.
var (
	ErrMismatch      = errors.New("password: does not match")
	ErrInvalidHash   = errors.New("password: malformed encoded hash")
	ErrUnknownScheme = errors.New("password: unknown hash scheme")
	ErrTooLong       = errors.New("password: too long")
	ErrTooShort      = errors.New("password: too short")
)

// MaxLength caps the accepted password length.
//
// Not a security limit — a bound on work. Without it, a megabyte "password" is
// a free denial of service, since the caller controls how much data the KDF
// has to chew through.
const MaxLength = 1024

// Hasher hashes and verifies passwords.
type Hasher interface {
	// Hash returns an encoded hash string for the password.
	Hash(password string) (string, error)

	// Verify reports whether password matches the encoded hash. It must
	// return ErrMismatch — not a bare false — so a caller cannot confuse
	// "wrong password" with "corrupt record".
	Verify(encoded, password string) error

	// NeedsRehash reports whether encoded was produced with weaker parameters
	// than the hasher currently uses.
	NeedsRehash(encoded string) bool
}

// PBKDF2 is the default Hasher.
type PBKDF2 struct {
	// Iterations defaults to 600,000, the OWASP figure for PBKDF2-HMAC-SHA256.
	Iterations int `cfg:"iterations"`

	// SaltLength in bytes. Defaults to 16.
	SaltLength int `cfg:"salt_length"`

	// KeyLength in bytes. Defaults to 32, the SHA-256 output size. Asking for
	// more than the hash output buys nothing but costs proportionally more.
	KeyLength int `cfg:"key_length"`

	// MinLength rejects short passwords at Hash time. Defaults to 8.
	// Verification never applies it: a policy change must not lock out
	// existing users.
	MinLength int `cfg:"min_length"`
}

const (
	defaultIterations = 600_000
	defaultSaltLength = 16
	defaultKeyLength  = 32
	defaultMinLength  = 8

	schemePBKDF2SHA256 = "pbkdf2-sha256"
)

// New returns a PBKDF2 hasher with defaults applied.
func New() *PBKDF2 {
	return (&PBKDF2{}).withDefaults()
}

func (p *PBKDF2) withDefaults() *PBKDF2 {
	c := *p

	if c.Iterations <= 0 {
		c.Iterations = defaultIterations
	}

	if c.SaltLength <= 0 {
		c.SaltLength = defaultSaltLength
	}

	if c.KeyLength <= 0 {
		c.KeyLength = defaultKeyLength
	}

	if c.MinLength <= 0 {
		c.MinLength = defaultMinLength
	}

	return &c
}

var _ Hasher = (*PBKDF2)(nil)

// Hash returns the encoded hash for password.
func (p *PBKDF2) Hash(password string) (string, error) {
	c := p.withDefaults()

	if len(password) > MaxLength {
		return "", ErrTooLong
	}

	if len([]rune(password)) < c.MinLength {
		return "", fmt.Errorf("%w: need at least %d characters", ErrTooShort, c.MinLength)
	}

	salt := make([]byte, c.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: read random: %w", err)
	}

	key, err := pbkdf2.Key(sha256.New, password, salt, c.Iterations, c.KeyLength)
	if err != nil {
		return "", fmt.Errorf("password: derive: %w", err)
	}

	return encode(schemePBKDF2SHA256, c.Iterations, salt, key), nil
}

// Verify reports whether password matches encoded.
func (p *PBKDF2) Verify(encoded, password string) error {
	if len(password) > MaxLength {
		return ErrTooLong
	}

	scheme, iterations, salt, want, err := decode(encoded)
	if err != nil {
		return err
	}

	if scheme != schemePBKDF2SHA256 {
		return fmt.Errorf("%w: %q", ErrUnknownScheme, scheme)
	}

	got, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(want))
	if err != nil {
		return fmt.Errorf("password: derive: %w", err)
	}

	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}

	return nil
}

// NeedsRehash reports whether encoded should be upgraded.
func (p *PBKDF2) NeedsRehash(encoded string) bool {
	c := p.withDefaults()

	scheme, iterations, salt, key, err := decode(encoded)
	if err != nil {
		// Unparseable: it cannot be verified either, so "rehash" is the only
		// useful answer.
		return true
	}

	return scheme != schemePBKDF2SHA256 ||
		iterations < c.Iterations ||
		len(salt) < c.SaltLength ||
		len(key) < c.KeyLength
}

func encode(scheme string, iterations int, salt, key []byte) string {
	return "$" + scheme +
		"$i=" + strconv.Itoa(iterations) +
		"$" + base64.RawStdEncoding.EncodeToString(salt) +
		"$" + base64.RawStdEncoding.EncodeToString(key)
}

func decode(encoded string) (scheme string, iterations int, salt, key []byte, err error) {
	// "$scheme$params$salt$hash" splits into 5 with a leading empty field.
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "" {
		return "", 0, nil, nil, ErrInvalidHash
	}

	scheme = parts[1]

	params, ok := strings.CutPrefix(parts[2], "i=")
	if !ok {
		return "", 0, nil, nil, ErrInvalidHash
	}

	iterations, err = strconv.Atoi(params)
	if err != nil || iterations <= 0 {
		return "", 0, nil, nil, ErrInvalidHash
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return "", 0, nil, nil, ErrInvalidHash
	}

	key, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(key) == 0 {
		return "", 0, nil, nil, ErrInvalidHash
	}

	return scheme, iterations, salt, key, nil
}

// Dummy is a valid encoded hash of a random value.
//
// Use it when a lookup finds no such user, so the request still pays for one
// derivation. Without it, "user not found" returns in microseconds while
// "wrong password" takes the full KDF cost, and the difference is a reliable
// account-enumeration oracle that no amount of identical error messages will
// hide.
//
//	hash, ok := store.Lookup(username)
//	if !ok {
//	    hash = password.Dummy
//	}
//	if err := hasher.Verify(hash, given); err != nil { ... }
var Dummy = func() string {
	// Generated once at init with the default cost, so the timing matches
	// whatever the deployment actually uses for real accounts.
	h, err := New().Hash(strings.Repeat("x", 32))
	if err != nil {
		// A failure here means crypto/rand is broken; there is nothing
		// sensible to return.
		panic(fmt.Errorf("password: build dummy hash: %w", err))
	}

	return h
}()
