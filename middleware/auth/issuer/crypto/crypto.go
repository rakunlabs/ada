// Package crypto provides an AES-GCM issuer.Cipher for encrypting the stored
// session pair at rest.
//
// A pair holds both live tokens and the full identity, including every raw
// upstream claim. Anything that persists it outside process memory — a file on
// disk, a Redis key, a database row — should be handed a Cipher, so that a
// stolen dump is not a stack of usable sessions.
//
// The key may be rotated at runtime with SetKey; in-flight readers keep using
// whichever key they picked up, and any value written under the previous key
// becomes undecryptable, which is the intended effect of a rotation.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
)

// Errors returned by Cipher.
var (
	ErrKeyRequired  = errors.New("crypto: key required")
	ErrCiphertext   = errors.New("crypto: malformed ciphertext")
	ErrNotEncrypted = errors.New("crypto: value is not encrypted")
)

// prefix marks our wire format so a plaintext value left over from an
// unencrypted deployment is recognisable rather than garbage.
const prefix = "enc:v1:"

// Cipher is an AES-GCM issuer.Cipher with hot-swappable keys.
type Cipher struct {
	aead atomic.Pointer[cipher.AEAD]
}

// New builds a Cipher from a key.
//
// A raw 16, 24 or 32 byte key is used as-is (AES-128/192/256). A
// base64-encoded key of one of those lengths is decoded first. Anything else —
// a passphrase, say — is hashed with SHA-256 into a 32 byte key, so a short
// human-chosen secret still yields a well-formed key. That is a convenience,
// not a KDF: prefer a real 32 byte random key.
func New(key string) (*Cipher, error) {
	if key == "" {
		return nil, ErrKeyRequired
	}

	c := &Cipher{}
	if err := c.SetKey(key); err != nil {
		return nil, err
	}

	return c, nil
}

// SetKey swaps the active key atomically. Values written under the previous
// key can no longer be decrypted.
func (c *Cipher) SetKey(key string) error {
	if key == "" {
		return ErrKeyRequired
	}

	block, err := aes.NewCipher(normalizeKey(key))
	if err != nil {
		return fmt.Errorf("crypto: new cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("crypto: new gcm: %w", err)
	}

	c.aead.Store(&aead)

	return nil
}

func normalizeKey(key string) []byte {
	raw := []byte(key)

	if isAESLen(len(raw)) {
		return raw
	}

	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := enc.DecodeString(key); err == nil && isAESLen(len(decoded)) {
			return decoded
		}
	}

	sum := sha256.Sum256(raw)

	return sum[:]
}

func isAESLen(n int) bool {
	return n == 16 || n == 24 || n == 32
}

// Encrypt seals plaintext and returns a prefixed, base64-encoded value.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	aead := c.load()
	if aead == nil {
		return nil, ErrKeyRequired
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: read random: %w", err)
	}

	sealed := aead.Seal(nonce, nonce, plaintext, nil)

	out := make([]byte, 0, len(prefix)+base64.RawStdEncoding.EncodedLen(len(sealed)))
	out = append(out, prefix...)
	out = base64.RawStdEncoding.AppendEncode(out, sealed)

	return out, nil
}

// Decrypt opens a value produced by Encrypt.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	aead := c.load()
	if aead == nil {
		return nil, ErrKeyRequired
	}

	if !IsEncrypted(ciphertext) {
		return nil, ErrNotEncrypted
	}

	sealed, err := base64.RawStdEncoding.AppendDecode(nil, ciphertext[len(prefix):])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCiphertext, err)
	}

	if len(sealed) < aead.NonceSize() {
		return nil, ErrCiphertext
	}

	nonce, body := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCiphertext, err)
	}

	return plaintext, nil
}

// IsEncrypted reports whether v carries this package's wire format.
func IsEncrypted(v []byte) bool {
	return len(v) > len(prefix) && string(v[:len(prefix)]) == prefix
}

func (c *Cipher) load() cipher.AEAD {
	p := c.aead.Load()
	if p == nil {
		return nil
	}

	return *p
}
