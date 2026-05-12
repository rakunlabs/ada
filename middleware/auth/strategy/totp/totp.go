// Package totp implements RFC 6238 time-based one-time passwords as a
// reusable cryptographic primitive. It is deliberately framework-agnostic:
// the package contains no HTTP handlers, no storage, no strategy
// implementation — only secret generation, otpauth URL formatting, and
// code generation/verification.
//
// MFA orchestration (per-user enrollment, recovery codes, login step-up)
// lives in the embedding application, not here. The reasoning: TOTP is
// always a second factor layered on top of an existing primary
// authenticator (password, LDAP, etc.) and the right place to choose
// "does this user need a second factor right now" is whatever owns the
// user table — the application — not ada's strategy registry.
//
// Defaults match every mainstream authenticator app (Google
// Authenticator, 1Password, Authy, Microsoft Authenticator, Bitwarden):
// HMAC-SHA1, 6 digits, 30s period. Don't override these unless you
// control both ends of the QR code; deviating breaks user-friendliness
// for no tangible security gain — RFC 6238 SHA1 is unbroken in this
// context (short-window HMAC, no collision relevance).
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Algorithm identifies the HMAC primitive a TOTP secret is used with.
// SHA1 is the de-facto default — every common authenticator app supports
// it; many do NOT support SHA256/SHA512 (Google Authenticator silently
// drops the algorithm parameter from otpauth URLs, falling back to SHA1
// regardless of what the URL says). Stick with SHA1 unless you know
// your users' apps.
type Algorithm string

const (
	AlgorithmSHA1   Algorithm = "SHA1"
	AlgorithmSHA256 Algorithm = "SHA256"
	AlgorithmSHA512 Algorithm = "SHA512"
)

// hasher returns the HMAC hash constructor for this algorithm. Defaults
// to SHA1 (the RFC 6238 fixture algorithm and the universal authenticator
// compatibility target).
func (a Algorithm) hasher() func() hash.Hash {
	switch a {
	case AlgorithmSHA256:
		return sha256.New
	case AlgorithmSHA512:
		return sha512.New
	default:
		return sha1.New
	}
}

// Config configures TOTP generation and verification.
//
// Period controls the validity window per code (RFC 6238: 30s by
// convention, never override without a reason).
//
// Digits is the code length the user types. 6 is the universal default;
// 8 is supported by most apps but trips up some hardware tokens.
//
// Skew is the number of windows either side of "now" that Verify will
// accept. 1 (i.e. ±30s) absorbs ordinary clock drift between server and
// authenticator; higher values weaken the rate-limit story without
// helping real users. 0 is strict but punishes users whose phones are
// 1-2s out of sync.
//
// Algorithm picks the HMAC primitive; see Algorithm doc.
//
// The zero value is invalid — call Default() to populate.
type Config struct {
	Period    time.Duration
	Digits    int
	Skew      uint
	Algorithm Algorithm
}

// Default returns a Config matching the RFC 6238 / mainstream authenticator
// defaults: SHA1, 6 digits, 30s period, ±1 window of skew.
func Default() Config {
	return Config{
		Period:    30 * time.Second,
		Digits:    6,
		Skew:      1,
		Algorithm: AlgorithmSHA1,
	}
}

// withDefaults returns a Config with zero-valued fields replaced by the
// matching Default() value, so callers don't have to construct a full
// Config when they only want to override one knob.
func (c Config) withDefaults() Config {
	d := Default()
	if c.Period <= 0 {
		c.Period = d.Period
	}
	if c.Digits <= 0 {
		c.Digits = d.Digits
	}
	if c.Algorithm == "" {
		c.Algorithm = d.Algorithm
	}
	// Skew=0 is a valid choice (strict), so we don't override it from
	// the default — explicit zero stays zero.
	return c
}

// Secret holds the raw bytes of a TOTP shared secret.
//
// The bytes are the actual HMAC key — NOT the base32 string. Generation
// uses Bytes; URL emission and authenticator pairing use Base32 (which
// is what the authenticator app stores and the otpauth URL embeds).
//
// Secrets are sensitive material. Callers should store them encrypted at
// rest where the threat model allows it.
type Secret struct {
	bytes []byte
}

// SecretFromBytes wraps raw bytes as a Secret. Useful when loading a
// secret from storage. The minimum recommended length is 16 bytes
// (RFC 4226 §4 R6); 20 bytes is the common default. We don't enforce a
// minimum here because legacy migrations may need shorter secrets to
// round-trip, but generation always emits ≥16 bytes.
func SecretFromBytes(b []byte) *Secret {
	cp := make([]byte, len(b))
	copy(cp, b)
	return &Secret{bytes: cp}
}

// SecretFromBase32 parses a base32-encoded secret string (the format
// authenticator apps use and otpauth URLs embed). Whitespace and
// padding are tolerated for hand-typed input. Returns an error if the
// string is malformed.
func SecretFromBase32(s string) (*Secret, error) {
	cleaned := strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	// base32 padding is optional in our writer; accept either form.
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(cleaned, "="))
	if err != nil {
		return nil, fmt.Errorf("totp: decode base32: %w", err)
	}
	return &Secret{bytes: b}, nil
}

// NewSecret returns a new random Secret of the given byte length. Pass
// 0 for the default (20 bytes, matching RFC 6238 test vectors and most
// authenticator app expectations). Reader defaults to crypto/rand.
//
// Use crypto/rand for production. Tests can inject a deterministic
// reader to make assertions reproducible.
func NewSecret(reader io.Reader, byteLen int) (*Secret, error) {
	if byteLen <= 0 {
		byteLen = 20
	}
	if reader == nil {
		reader = rand.Reader
	}
	b := make([]byte, byteLen)
	if _, err := io.ReadFull(reader, b); err != nil {
		return nil, fmt.Errorf("totp: read random: %w", err)
	}
	return &Secret{bytes: b}, nil
}

// Bytes returns a defensive copy of the raw secret. The returned slice
// is owned by the caller — mutations don't leak back into Secret.
func (s *Secret) Bytes() []byte {
	out := make([]byte, len(s.bytes))
	copy(out, s.bytes)
	return out
}

// Base32 returns the unpadded base32 encoding of the secret. This is the
// canonical form authenticator apps expect — both for the otpauth URL
// and for users who manually enter the secret string ("My phone won't
// scan, give me the code").
//
// Padding is intentionally omitted: most authenticator apps accept both
// forms, but Google Authenticator's manual-entry screen rejects padded
// input on some versions.
func (s *Secret) Base32() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(s.bytes)
}

// KeyURIParams are the fields needed to build an otpauth:// URI that an
// authenticator app can ingest by QR scan or paste.
//
// Issuer is the application name shown above the code in the
// authenticator UI (e.g. "Pika"). It's repeated as both the URL path
// prefix ("Issuer:account") and as the issuer query parameter — the path
// form is legacy; the query parameter is what every modern app reads.
//
// Account is the user-facing identifier (typically the username or email).
// Authenticator UIs show this as the subtitle so users can tell apart
// multiple accounts at the same issuer ("you have three @gmail entries").
//
// Config carries the algorithm / digits / period that need to match
// between the URI and what Verify uses. Mismatched values produce silent
// failures users can't diagnose.
type KeyURIParams struct {
	Issuer  string
	Account string
	Config  Config
}

// URL returns the otpauth:// URI used to provision an authenticator app
// from a QR code. The format is the de-facto Google Authenticator
// scheme; documented at
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
//
// Returns an empty string when Account is empty — without an account
// label the resulting URI provisions successfully but shows up as a
// blank row in the user's authenticator, which is universally confusing.
func (s *Secret) URL(p KeyURIParams) string {
	if p.Account == "" {
		return ""
	}
	cfg := p.Config.withDefaults()

	// The "label" path segment is "Issuer:Account" if Issuer is set,
	// just "Account" otherwise. Both halves are URL-path-encoded; ":"
	// itself is allowed as a literal separator per the spec.
	var label string
	if p.Issuer != "" {
		label = url.PathEscape(p.Issuer) + ":" + url.PathEscape(p.Account)
	} else {
		label = url.PathEscape(p.Account)
	}

	q := url.Values{}
	q.Set("secret", s.Base32())
	if p.Issuer != "" {
		q.Set("issuer", p.Issuer)
	}
	q.Set("algorithm", string(cfg.Algorithm))
	q.Set("digits", strconv.Itoa(cfg.Digits))
	q.Set("period", strconv.Itoa(int(cfg.Period/time.Second)))

	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Generate produces the TOTP code for this secret at the given time,
// using the supplied Config. Errors only on impossible configuration
// (e.g. zero Period); ordinary use never errors.
//
// Callers verifying user input should prefer Verify — it handles the
// constant-time comparison and the skew window. Generate is exposed
// for tests, for emitting "current code" via an admin tool, and for
// implementations of recovery flows.
func (cfg Config) Generate(secret *Secret, t time.Time) (string, error) {
	if secret == nil || len(secret.bytes) == 0 {
		return "", errors.New("totp: empty secret")
	}
	cfg = cfg.withDefaults()
	step := uint64(t.Unix()) / uint64(cfg.Period.Seconds())
	return cfg.generateForStep(secret.bytes, step), nil
}

// Verify reports whether code matches the secret's expected output at
// the given time, allowing ±Skew windows of clock drift. Comparison is
// constant-time.
//
// Returns false on any parse error in `code` — never errors externally,
// so callers can use it as a bool without losing track of "user typed
// garbage" vs "user typed the wrong code". For diagnostics use Generate
// + manual comparison instead.
func (cfg Config) Verify(secret *Secret, code string, t time.Time) bool {
	if secret == nil || len(secret.bytes) == 0 {
		return false
	}
	cfg = cfg.withDefaults()
	// Reject input whose length already disagrees — saves the HMAC work
	// and gives a uniform failure path for malformed input.
	code = strings.TrimSpace(code)
	if len(code) != cfg.Digits {
		return false
	}
	// Validate digits-only without touching big.Int.
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}

	periodSec := uint64(cfg.Period.Seconds())
	if periodSec == 0 {
		return false
	}
	center := uint64(t.Unix()) / periodSec

	// Walk the skew window in [center-skew, center+skew]. Compare every
	// candidate (don't short-circuit on first hit) so the runtime is
	// constant w.r.t. which window matched — keeps the side-channel
	// surface small for code-comparison oracles.
	skew := uint64(cfg.Skew)
	match := byte(0)
	for delta := int64(-int64(skew)); delta <= int64(skew); delta++ {
		step := uint64(int64(center) + delta)
		candidate := cfg.generateForStep(secret.bytes, step)
		// subtle.ConstantTimeCompare returns 1 on match. OR the result
		// into match so any window matching keeps match=1.
		match |= byte(subtle.ConstantTimeCompare([]byte(code), []byte(candidate)))
	}
	return match == 1
}

// generateForStep is the core RFC 6238 / RFC 4226 derivation. Splitting
// it out makes the verify loop above readable and lets tests assert
// against per-step outputs from the RFC 6238 fixture table.
func (cfg Config) generateForStep(secret []byte, step uint64) string {
	// RFC 4226 §5.3: counter is 8 bytes big-endian.
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, step)

	mac := hmac.New(cfg.Algorithm.hasher(), secret)
	mac.Write(counter)
	sum := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.3): the low 4 bits of the last
	// byte index into sum; take 4 bytes starting at that offset, mask
	// the high bit (avoid sign issues on 31-bit cast), then modulo
	// 10^Digits to clamp to the desired length.
	offset := int(sum[len(sum)-1] & 0x0F)
	binCode := (uint32(sum[offset])&0x7F)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < cfg.Digits; i++ {
		mod *= 10
	}
	val := binCode % mod

	// Left-pad with zeros so a code like "000123" doesn't get rendered
	// as "123" — authenticator apps always show the full Digits-length
	// string, so anything else breaks user comparison.
	return fmt.Sprintf("%0*d", cfg.Digits, val)
}
