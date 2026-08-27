package password_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth/password"
)

// A low cost keeps the suite fast; the defaults are exercised separately.
func testHasher() *password.PBKDF2 {
	return &password.PBKDF2{Iterations: 1000, MinLength: 4}
}

func TestHashVerifyRoundTrip(t *testing.T) {
	h := testHasher()

	encoded, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if err := h.Verify(encoded, "correct horse battery staple"); err != nil {
		t.Fatalf("verify: %v", err)
	}

	if err := h.Verify(encoded, "wrong"); !errors.Is(err, password.ErrMismatch) {
		t.Fatalf("err = %v, want ErrMismatch", err)
	}
}

func TestHashIsSalted(t *testing.T) {
	h := testHasher()

	a, _ := h.Hash("same password")
	b, _ := h.Hash("same password")

	if a == b {
		t.Fatal("two hashes of the same password must differ")
	}
}

func TestEncodedFormat(t *testing.T) {
	h := testHasher()

	encoded, _ := h.Hash("abcdefgh")

	if !strings.HasPrefix(encoded, "$pbkdf2-sha256$i=1000$") {
		t.Fatalf("unexpected format: %s", encoded)
	}

	if n := strings.Count(encoded, "$"); n != 4 {
		t.Fatalf("expected 4 separators, got %d in %s", n, encoded)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	h := testHasher()

	bad := []string{
		"",
		"plaintext",
		"$pbkdf2-sha256$1000$salt$hash",    // params not "i="
		"$pbkdf2-sha256$i=0$c2FsdA$aGFzaA", // zero iterations
		"$pbkdf2-sha256$i=1000$!!!$aGFzaA",
		"$pbkdf2-sha256$i=1000$c2FsdA$",
	}

	for _, v := range bad {
		if err := h.Verify(v, "x"); !errors.Is(err, password.ErrInvalidHash) {
			t.Errorf("Verify(%q) = %v, want ErrInvalidHash", v, err)
		}
	}
}

func TestVerifyRejectsUnknownScheme(t *testing.T) {
	h := testHasher()

	err := h.Verify("$bcrypt$i=10$c2FsdA$aGFzaA", "x")
	if !errors.Is(err, password.ErrUnknownScheme) {
		t.Errorf("err = %v, want ErrUnknownScheme", err)
	}
}

func TestMinLength(t *testing.T) {
	h := &password.PBKDF2{Iterations: 1000, MinLength: 8}

	if _, err := h.Hash("short"); !errors.Is(err, password.ErrTooShort) {
		t.Errorf("err = %v, want ErrTooShort", err)
	}

	// A policy change must not lock existing users out.
	lenient := &password.PBKDF2{Iterations: 1000, MinLength: 4}

	encoded, err := lenient.Hash("shrt")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if err := h.Verify(encoded, "shrt"); err != nil {
		t.Errorf("a stricter MinLength must not invalidate existing hashes: %v", err)
	}
}

func TestMaxLength(t *testing.T) {
	h := testHasher()

	long := strings.Repeat("a", password.MaxLength+1)

	if _, err := h.Hash(long); !errors.Is(err, password.ErrTooLong) {
		t.Errorf("hash err = %v, want ErrTooLong", err)
	}

	if err := h.Verify("$pbkdf2-sha256$i=1000$c2FsdA$aGFzaA", long); !errors.Is(err, password.ErrTooLong) {
		t.Errorf("verify err = %v, want ErrTooLong", err)
	}
}

func TestNeedsRehash(t *testing.T) {
	weak := &password.PBKDF2{Iterations: 1000, MinLength: 4}
	strong := &password.PBKDF2{Iterations: 5000, SaltLength: 16, KeyLength: 32, MinLength: 4}

	encoded, _ := weak.Hash("abcdefgh")

	if !strong.NeedsRehash(encoded) {
		t.Error("a hash below the current cost should need a rehash")
	}

	if weak.NeedsRehash(encoded) {
		t.Error("a hash at the current cost should not need a rehash")
	}

	if !strong.NeedsRehash("garbage") {
		t.Error("an unparseable hash should need a rehash")
	}
}

// The dummy exists so a missing user costs the same as a wrong password.
func TestDummyVerifiesAsMismatch(t *testing.T) {
	h := password.New()

	if err := h.Verify(password.Dummy, "anything"); !errors.Is(err, password.ErrMismatch) {
		t.Fatalf("err = %v, want ErrMismatch", err)
	}
}

func TestDefaultsAreExpensive(t *testing.T) {
	h := password.New()

	encoded, err := h.Hash("abcdefgh")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if !strings.Contains(encoded, "i=600000") {
		t.Errorf("default iteration count is too low: %s", encoded)
	}

	if err := h.Verify(encoded, "abcdefgh"); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
