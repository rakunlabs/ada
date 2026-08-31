package crypto_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth/issuer"
	"github.com/rakunlabs/ada/middleware/auth/issuer/crypto"
)

func TestRoundTrip(t *testing.T) {
	c, err := crypto.New("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	plain := []byte(`{"session_id":"abc","refresh":"secret"}`)

	sealed, err := c.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if bytes.Contains(sealed, []byte("secret")) {
		t.Fatal("ciphertext contains the plaintext")
	}

	if !crypto.IsEncrypted(sealed) {
		t.Fatal("ciphertext is not recognised by IsEncrypted")
	}

	got, err := c.Decrypt(sealed)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q, want %q", got, plain)
	}
}

func TestNonceIsFresh(t *testing.T) {
	c, _ := crypto.New("0123456789abcdef0123456789abcdef")

	a, _ := c.Encrypt([]byte("same"))
	b, _ := c.Encrypt([]byte("same"))

	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same plaintext must differ")
	}
}

func TestAssociatedDataIsAuthenticated(t *testing.T) {
	c, _ := crypto.New("0123456789abcdef0123456789abcdef")
	sealed, err := c.EncryptWithAssociatedData([]byte("payload"), []byte("session-a"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	plain, err := c.DecryptWithAssociatedData(sealed, []byte("session-a"))
	if err != nil || string(plain) != "payload" {
		t.Fatalf("decrypt: %q, %v", plain, err)
	}
	if _, err := c.DecryptWithAssociatedData(sealed, []byte("session-b")); !errors.Is(err, crypto.ErrCiphertext) {
		t.Fatalf("wrong associated data error = %v, want ErrCiphertext", err)
	}
}

func TestAssociatedDataDecryptsLegacyCiphertext(t *testing.T) {
	c, _ := crypto.New("0123456789abcdef0123456789abcdef")
	legacy, _ := c.Encrypt([]byte("payload"))

	plain, err := c.DecryptWithAssociatedData(legacy, []byte("session-a"))
	if err != nil || string(plain) != "payload" {
		t.Fatalf("legacy decrypt: %q, %v", plain, err)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	c, _ := crypto.New("0123456789abcdef0123456789abcdef")

	sealed, _ := c.Encrypt([]byte("a somewhat longer payload to tamper with"))

	// Substitute a character in the middle of the base64 body. Flipping bits
	// in the final byte is unreliable: the last base64 quantum carries unused
	// bits, so some edits decode to identical plaintext.
	mid := len(sealed) / 2

	tampered := append([]byte(nil), sealed...)
	if tampered[mid] == 'A' {
		tampered[mid] = 'B'
	} else {
		tampered[mid] = 'A'
	}

	if _, err := c.Decrypt(tampered); err == nil {
		t.Fatal("GCM must reject a modified ciphertext")
	}

	// Truncation must be rejected too.
	if _, err := c.Decrypt(sealed[:len(sealed)-8]); err == nil {
		t.Fatal("GCM must reject a truncated ciphertext")
	}
}

func TestWrongKeyFails(t *testing.T) {
	a, _ := crypto.New("0123456789abcdef0123456789abcdef")
	b, _ := crypto.New("fedcba9876543210fedcba9876543210")

	sealed, _ := a.Encrypt([]byte("payload"))

	if _, err := b.Decrypt(sealed); !errors.Is(err, crypto.ErrCiphertext) {
		t.Fatalf("err = %v, want ErrCiphertext", err)
	}
}

func TestPlaintextIsRejected(t *testing.T) {
	c, _ := crypto.New("0123456789abcdef0123456789abcdef")

	if _, err := c.Decrypt([]byte(`{"plain":"json"}`)); !errors.Is(err, crypto.ErrNotEncrypted) {
		t.Fatalf("err = %v, want ErrNotEncrypted", err)
	}
}

func TestKeyNormalisation(t *testing.T) {
	// A base64-encoded 32-byte key and the raw bytes it decodes to must
	// produce the same cipher.
	raw := []byte("0123456789abcdef0123456789abcdef")
	encoded := base64.StdEncoding.EncodeToString(raw)

	a, err := crypto.New(string(raw))
	if err != nil {
		t.Fatalf("new raw: %v", err)
	}

	b, err := crypto.New(encoded)
	if err != nil {
		t.Fatalf("new base64: %v", err)
	}

	sealed, _ := a.Encrypt([]byte("payload"))

	if _, err := b.Decrypt(sealed); err != nil {
		t.Fatalf("base64 key should equal the raw key: %v", err)
	}

	// A passphrase of an unusual length is hashed rather than rejected.
	if _, err := crypto.New("a short passphrase"); err != nil {
		t.Fatalf("passphrase: %v", err)
	}
}

func TestEmptyKeyRejected(t *testing.T) {
	if _, err := crypto.New(""); !errors.Is(err, crypto.ErrKeyRequired) {
		t.Fatalf("err = %v, want ErrKeyRequired", err)
	}
}

func TestSetKeyRotates(t *testing.T) {
	c, _ := crypto.New("0123456789abcdef0123456789abcdef")

	sealed, _ := c.Encrypt([]byte("payload"))

	if err := c.SetKey("fedcba9876543210fedcba9876543210"); err != nil {
		t.Fatalf("set key: %v", err)
	}

	// Rotation is supposed to invalidate anything written under the old key.
	if _, err := c.Decrypt(sealed); err == nil {
		t.Fatal("old ciphertext should not decrypt after rotation")
	}

	fresh, _ := c.Encrypt([]byte("payload"))
	if _, err := c.Decrypt(fresh); err != nil {
		t.Fatalf("new key should work: %v", err)
	}
}

func TestWirePrefix(t *testing.T) {
	c, _ := crypto.New("0123456789abcdef0123456789abcdef")

	sealed, _ := c.Encrypt([]byte("x"))

	if !strings.HasPrefix(string(sealed), "enc:v1:") {
		t.Fatalf("missing version prefix: %s", sealed)
	}
}

// Compile-time proof that Cipher satisfies the interface the issuer expects.
var _ issuer.Cipher = (*crypto.Cipher)(nil)
var _ issuer.AssociatedDataCipher = (*crypto.Cipher)(nil)
