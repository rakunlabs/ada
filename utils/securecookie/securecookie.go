// Package securecookie encodes and decodes authenticated and optionally
// encrypted cookie values.
//
// A Codec serializes an arbitrary value, optionally encrypts it with AES-CTR,
// and signs the result with HMAC-SHA256. The signature also covers the cookie
// name and a timestamp, so values cannot be moved between cookies or replayed
// outside their validity window.
//
// Encoded layout (before the outer base64):
//
//	timestamp | base64(payload) | base64(hmac)
//
// where payload is "serialized" in sign-only mode, or "iv || aes-ctr(serialized)"
// when a block key is configured.
//
// The API is dependency-free and uses only the standard library.
package securecookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultMaxAge is the default validity window for an encoded value.
	DefaultMaxAge = 30 * 24 * 60 * 60 // 30 days in seconds
	// DefaultMaxLength is the default maximum length of an encoded value.
	DefaultMaxLength = 4096
)

// Codec encodes and decodes secure cookie values. A zero Codec is not usable;
// construct one with New.
type Codec struct {
	hashKey    []byte
	block      cipher.Block // nil when encryption is disabled
	maxAge     int64        // seconds; 0 disables the max-age check
	minAge     int64        // seconds; 0 disables the min-age check
	maxLength  int          // 0 disables the length check
	serializer Serializer
	now        func() time.Time
}

// Option configures a Codec.
type Option func(*Codec)

// WithMaxAge sets the maximum age in seconds of a value to be decoded. A value
// of 0 disables the check. Defaults to DefaultMaxAge.
func WithMaxAge(seconds int) Option {
	return func(c *Codec) { c.maxAge = int64(seconds) }
}

// WithMinAge sets the minimum age in seconds of a value to be decoded. A value
// of 0 disables the check. Useful to reject values that appear to come from the
// future due to clock skew.
func WithMinAge(seconds int) Option {
	return func(c *Codec) { c.minAge = int64(seconds) }
}

// WithMaxLength sets the maximum length of the encoded value. A value of 0
// disables the check. Defaults to DefaultMaxLength.
func WithMaxLength(n int) Option {
	return func(c *Codec) { c.maxLength = n }
}

// WithSerializer sets the serializer used to encode values. Defaults to
// GobSerializer.
func WithSerializer(s Serializer) Option {
	return func(c *Codec) {
		if s != nil {
			c.serializer = s
		}
	}
}

// WithNow overrides the clock used for timestamps. Intended for tests.
func WithNow(fn func() time.Time) Option {
	return func(c *Codec) {
		if fn != nil {
			c.now = fn
		}
	}
}

// New returns a Codec that signs values with hashKey using HMAC-SHA256 and, if
// blockKey is non-empty, encrypts them with AES-CTR.
//
// hashKey is required and should be at least 32 bytes. blockKey, when set, must
// be 16, 24 or 32 bytes to select AES-128, AES-192 or AES-256. It panics on
// invalid keys; use NewWithError if you need to handle the error.
func New(hashKey, blockKey []byte, opts ...Option) *Codec {
	c, err := NewWithError(hashKey, blockKey, opts...)
	if err != nil {
		panic(err.Error())
	}

	return c
}

// NewWithError is like New but returns an error instead of panicking on invalid
// keys.
func NewWithError(hashKey, blockKey []byte, opts ...Option) (*Codec, error) {
	if len(hashKey) == 0 {
		return nil, ErrHashKeyRequired
	}

	c := &Codec{
		hashKey:    append([]byte(nil), hashKey...),
		maxAge:     DefaultMaxAge,
		maxLength:  DefaultMaxLength,
		serializer: GobSerializer{},
		now:        time.Now,
	}

	if len(blockKey) > 0 {
		block, err := aes.NewCipher(blockKey)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidBlockKeySize, err)
		}
		c.block = block
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// Encode serializes value, optionally encrypts it, signs it together with name
// and the current timestamp, and returns a URL-safe base64 string.
func (c *Codec) Encode(name string, value any) (string, error) {
	if c == nil || len(c.hashKey) == 0 {
		return "", ErrHashKeyRequired
	}

	b, err := c.serializer.Serialize(value)
	if err != nil {
		return "", fmt.Errorf("securecookie: serialize: %w", err)
	}

	if c.block != nil {
		b, err = c.encrypt(b)
		if err != nil {
			return "", err
		}
	}

	b64 := base64.URLEncoding.EncodeToString(b)
	ts := strconv.FormatInt(c.now().Unix(), 10)

	mac := c.computeMAC(name, ts, b64)
	b64MAC := base64.URLEncoding.EncodeToString(mac)

	token := ts + "|" + b64 + "|" + b64MAC
	encoded := base64.URLEncoding.EncodeToString([]byte(token))

	if c.maxLength != 0 && len(encoded) > c.maxLength {
		return "", ErrValueTooLong
	}

	return encoded, nil
}

// Decode verifies the encoded value's signature and timestamp, decrypts it if
// necessary, and deserializes the result into dst, which must be a non-nil
// pointer.
func (c *Codec) Decode(name, encoded string, dst any) error {
	if c == nil || len(c.hashKey) == 0 {
		return ErrHashKeyRequired
	}

	if c.maxLength != 0 && len(encoded) > c.maxLength {
		return ErrValueTooLong
	}

	tokenBytes, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecode, err)
	}

	parts := strings.SplitN(string(tokenBytes), "|", 3)
	if len(parts) != 3 {
		return ErrDecode
	}
	ts, b64, b64MAC := parts[0], parts[1], parts[2]

	macBytes, err := base64.URLEncoding.DecodeString(b64MAC)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecode, err)
	}

	expected := c.computeMAC(name, ts, b64)
	if subtle.ConstantTimeCompare(macBytes, expected) != 1 {
		return ErrMACInvalid
	}

	tsUnix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: bad timestamp: %v", ErrDecode, err)
	}

	now := c.now().Unix()
	if c.minAge != 0 && tsUnix > now-c.minAge {
		return ErrTimestampTooNew
	}
	if c.maxAge != 0 && tsUnix < now-c.maxAge {
		return ErrTimestampExpired
	}

	b, err := base64.URLEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecode, err)
	}

	if c.block != nil {
		b, err = c.decrypt(b)
		if err != nil {
			return err
		}
	}

	if err := c.serializer.Deserialize(b, dst); err != nil {
		return fmt.Errorf("%w: deserialize: %v", ErrDecode, err)
	}

	return nil
}

// SetMaxAge sets the maximum age in seconds for decoding. A value of 0 disables
// the check. Intended to be called at setup time (for example by a session
// store) before the codec is shared across goroutines.
func (c *Codec) SetMaxAge(seconds int) {
	c.maxAge = int64(seconds)
}

func (c *Codec) computeMAC(name, ts, b64 string) []byte {
	mac := hmac.New(sha256.New, c.hashKey)
	mac.Write([]byte(name))
	mac.Write([]byte("|"))
	mac.Write([]byte(ts))
	mac.Write([]byte("|"))
	mac.Write([]byte(b64))

	return mac.Sum(nil)
}

// encrypt prepends a random IV and applies AES-CTR.
func (c *Codec) encrypt(data []byte) ([]byte, error) {
	iv := make([]byte, c.block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("securecookie: iv: %w", err)
	}

	out := make([]byte, len(iv)+len(data))
	copy(out, iv)

	stream := cipher.NewCTR(c.block, iv)
	stream.XORKeyStream(out[len(iv):], data)

	return out, nil
}

// decrypt strips the IV and reverses AES-CTR.
func (c *Codec) decrypt(data []byte) ([]byte, error) {
	size := c.block.BlockSize()
	if len(data) < size {
		return nil, ErrDecode
	}

	iv := data[:size]
	out := make([]byte, len(data)-size)

	stream := cipher.NewCTR(c.block, iv)
	stream.XORKeyStream(out, data[size:])

	return out, nil
}
