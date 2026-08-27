package totp

import (
	"bytes"
	"encoding/base32"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestGenerate_RFC6238Vectors uses the test fixture from RFC 6238 Appendix B.
// Every conforming TOTP implementation must reproduce these codes exactly.
//
// The RFC publishes 8-digit outputs; we replay them with Config{Digits: 8}
// to match. Real deployments use 6 digits — which corresponds to the same
// modulo of the same HMAC output, taking the rightmost 6 digits of the
// 8-digit values.
func TestGenerate_RFC6238Vectors(t *testing.T) {
	// RFC 6238 §B.1: secret is the ASCII string "12345678901234567890"
	// (20 bytes), repeated/extended for SHA256/SHA512 — the RFC includes
	// pre-extended secrets for those algorithms in §B.2/B.3 (corrected
	// erratum 2866). We test SHA1 here; SHA256/SHA512 vectors are
	// covered by a separate table-driven block below.
	sha1Secret := SecretFromBytes([]byte("12345678901234567890"))

	cases := []struct {
		t    int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	cfg := Config{
		Period:    30 * time.Second,
		Digits:    8,
		Algorithm: AlgorithmSHA1,
	}

	for _, c := range cases {
		got, err := cfg.Generate(sha1Secret, time.Unix(c.t, 0))
		if err != nil {
			t.Fatalf("Generate(t=%d): %v", c.t, err)
		}
		if got != c.want {
			t.Errorf("RFC6238 SHA1 t=%d: got %q want %q", c.t, got, c.want)
		}
	}
}

// TestGenerate_RFC6238Vectors_SHA256_SHA512 covers the SHA256 and SHA512
// rows of the RFC 6238 fixture. The secret bytes are the "K_i" values
// from erratum 2866 — the ASCII string repeated to fill 32/64 bytes.
func TestGenerate_RFC6238Vectors_SHA256_SHA512(t *testing.T) {
	// "12345678901234567890123456789012" - 32 bytes for SHA256.
	sha256Secret := SecretFromBytes([]byte("12345678901234567890123456789012"))
	// 64 bytes for SHA512.
	sha512Secret := SecretFromBytes([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	// Values from RFC 6238 erratum 2866 (the published RFC table is wrong
	// for SHA256/SHA512). t=2_000_000_000 and t=20_000_000_000 rows are
	// distinct — the latter is "20 billion seconds since epoch", much
	// further into the future than the former.
	cases := []struct {
		t    int64
		alg  Algorithm
		want string
		sec  *Secret
	}{
		{59, AlgorithmSHA256, "46119246", sha256Secret},
		{59, AlgorithmSHA512, "90693936", sha512Secret},
		{1111111109, AlgorithmSHA256, "68084774", sha256Secret},
		{1111111109, AlgorithmSHA512, "25091201", sha512Secret},
		{2000000000, AlgorithmSHA256, "90698825", sha256Secret},
		{2000000000, AlgorithmSHA512, "38618901", sha512Secret},
		{20000000000, AlgorithmSHA256, "77737706", sha256Secret},
		{20000000000, AlgorithmSHA512, "47863826", sha512Secret},
	}

	for _, c := range cases {
		cfg := Config{
			Period:    30 * time.Second,
			Digits:    8,
			Algorithm: c.alg,
		}
		got, err := cfg.Generate(c.sec, time.Unix(c.t, 0))
		if err != nil {
			t.Fatalf("Generate(alg=%s t=%d): %v", c.alg, c.t, err)
		}
		if got != c.want {
			t.Errorf("RFC6238 %s t=%d: got %q want %q", c.alg, c.t, got, c.want)
		}
	}
}

// TestVerify_AcceptsCurrentWindow asserts the happy path: a code
// generated at time T verifies at time T.
func TestVerify_AcceptsCurrentWindow(t *testing.T) {
	sec, _ := NewSecret(bytes.NewReader(make([]byte, 32)), 20)
	now := time.Unix(1_700_000_000, 0)
	cfg := Default()

	code, err := cfg.Generate(sec, now)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !cfg.Verify(sec, code, now) {
		t.Errorf("Verify same-window: rejected freshly generated code %q", code)
	}
}

// TestVerify_AcceptsAdjacentWindowWithinSkew exercises clock-drift
// tolerance. With Skew=1 a code generated 30s ago must still verify.
func TestVerify_AcceptsAdjacentWindowWithinSkew(t *testing.T) {
	sec, _ := NewSecret(bytes.NewReader(make([]byte, 32)), 20)
	pastT := time.Unix(1_700_000_000, 0)
	nowT := pastT.Add(30 * time.Second)
	cfg := Default() // Skew = 1

	pastCode, _ := cfg.Generate(sec, pastT)
	if !cfg.Verify(sec, pastCode, nowT) {
		t.Errorf("Verify Skew=1: rejected 30s-old code (clock drift not tolerated)")
	}

	// Two windows out — outside the default Skew=1 — must NOT verify.
	wayOldT := pastT.Add(-60 * time.Second) // 2 windows back
	wayOldCode, _ := cfg.Generate(sec, wayOldT)
	if cfg.Verify(sec, wayOldCode, nowT) {
		t.Errorf("Verify Skew=1: accepted 60s-old code (skew window too wide)")
	}
}

// TestVerify_RejectsWrongCode is the obvious negative case.
func TestVerify_RejectsWrongCode(t *testing.T) {
	sec, _ := NewSecret(bytes.NewReader(make([]byte, 32)), 20)
	now := time.Unix(1_700_000_000, 0)
	cfg := Default()

	if cfg.Verify(sec, "000000", now) {
		t.Errorf("Verify accepted all-zero code (likely accidental match — adjust the random seed)")
	}
	if cfg.Verify(sec, "999999", now) {
		t.Errorf("Verify accepted all-nines code")
	}
}

// TestVerify_RejectsMalformedInput covers garbage user input. Verify
// must return false rather than panic for non-digit / wrong-length
// strings — the typical case is the user pasting "  123456 \n" or
// hitting paste while focused on the wrong field.
func TestVerify_RejectsMalformedInput(t *testing.T) {
	sec := SecretFromBytes([]byte("12345678901234567890"))
	now := time.Unix(59, 0)
	cfg := Config{Period: 30 * time.Second, Digits: 8, Algorithm: AlgorithmSHA1}

	bads := []string{
		"",
		"1234567",    // too short
		"123456789",  // too long
		"94287082 ",  // trailing whitespace handled by TrimSpace, OK
		"94287082\n", // newline — TrimSpace handles
		"94287O82",   // letter O instead of digit 0
		"hello",
		"--------",
	}
	// The first four are expected to verify after trimming; we want to
	// confirm trimming, so split into two sub-tests.

	if !cfg.Verify(sec, "94287082", now) {
		t.Fatal("setup sanity: known-good code failed to verify")
	}
	if !cfg.Verify(sec, "94287082 ", now) {
		t.Error("Verify did not trim trailing whitespace")
	}
	if !cfg.Verify(sec, "94287082\n", now) {
		t.Error("Verify did not trim trailing newline")
	}

	rejectsExpected := []string{"", "1234567", "123456789", "94287O82", "hello", "--------"}
	for _, b := range rejectsExpected {
		if cfg.Verify(sec, b, now) {
			t.Errorf("Verify accepted malformed input %q", b)
		}
	}

	// And one more: ensure no panic on absurdly long input.
	long := strings.Repeat("9", 10000)
	if cfg.Verify(sec, long, now) {
		t.Errorf("Verify accepted 10k-char input")
	}
	_ = bads
}

// TestVerify_NilSecret confirms the package's input-poison-tolerant
// contract: nil/empty secret yields false, no panic.
func TestVerify_NilSecret(t *testing.T) {
	cfg := Default()
	if cfg.Verify(nil, "123456", time.Now()) {
		t.Error("Verify accepted nil secret")
	}
	empty := SecretFromBytes(nil)
	if cfg.Verify(empty, "123456", time.Now()) {
		t.Error("Verify accepted empty secret")
	}
}

// TestSecret_Base32_RoundTrip is the contract authenticator apps rely
// on: the base32 string we hand the user (via the QR code) must decode
// back to the same secret bytes. Without this, the user's app
// generates codes for a different secret than what we stored.
func TestSecret_Base32_RoundTrip(t *testing.T) {
	original, _ := NewSecret(bytes.NewReader(make([]byte, 32)), 20)
	encoded := original.Base32()
	parsed, err := SecretFromBase32(encoded)
	if err != nil {
		t.Fatalf("SecretFromBase32: %v", err)
	}
	if !bytes.Equal(original.Bytes(), parsed.Bytes()) {
		t.Errorf("round-trip mismatch:\n original: %x\n decoded:  %x", original.Bytes(), parsed.Bytes())
	}
}

// TestSecret_Base32_NoPadding asserts the encoding contract: the
// emitted base32 string must NOT carry "=" padding chars. Google
// Authenticator's manual-entry screen rejects padded input on some
// versions; we always emit unpadded for compatibility.
func TestSecret_Base32_NoPadding(t *testing.T) {
	for _, n := range []int{10, 16, 20, 32, 64} {
		sec := SecretFromBytes(make([]byte, n))
		b32 := sec.Base32()
		if strings.Contains(b32, "=") {
			t.Errorf("Base32(%d-byte secret) contains padding: %q", n, b32)
		}
	}
}

// TestSecret_Base32_TolerantParse documents that hand-typed input is
// normalized (case + whitespace + optional padding stripped) before
// decoding. Without this, users hitting "type the secret manually" on
// a small phone screen produce false "invalid secret" errors.
func TestSecret_Base32_TolerantParse(t *testing.T) {
	original, _ := NewSecret(bytes.NewReader(make([]byte, 32)), 20)
	b32 := original.Base32()

	// Lowercase, with spaces every 4 chars (some apps emit this format).
	hand := strings.ToLower(b32)
	var spaced strings.Builder
	for i, r := range hand {
		if i > 0 && i%4 == 0 {
			spaced.WriteByte(' ')
		}
		spaced.WriteRune(r)
	}

	parsed, err := SecretFromBase32(spaced.String())
	if err != nil {
		t.Fatalf("SecretFromBase32(spaced+lowercase): %v", err)
	}
	if !bytes.Equal(original.Bytes(), parsed.Bytes()) {
		t.Errorf("tolerant parse round-trip mismatch")
	}

	// Same input with explicit "=" padding (also valid input form).
	padded := strings.ToUpper(b32)
	for len(padded)%8 != 0 {
		padded += "="
	}
	parsedPadded, err := SecretFromBase32(padded)
	if err != nil {
		t.Fatalf("SecretFromBase32(padded): %v", err)
	}
	if !bytes.Equal(original.Bytes(), parsedPadded.Bytes()) {
		t.Errorf("padded round-trip mismatch")
	}
}

// TestURL_Format asserts the otpauth URI matches the documented format
// (https://github.com/google/google-authenticator/wiki/Key-Uri-Format).
// Authenticator apps are picky here — extra slashes, missing query
// params, or wrong encoding break the QR scan.
func TestURL_Format(t *testing.T) {
	sec := SecretFromBytes([]byte("12345678901234567890"))
	uri := sec.URL(KeyURIParams{
		Issuer:  "Pika",
		Account: "alice@example.com",
		Config:  Default(),
	})

	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("URL prefix wrong: %q", uri)
	}

	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("URL not parseable: %v", err)
	}

	// Path should be "Pika:alice@example.com" (the "@" is path-encoded
	// to "%40" by net/url; verify by decoding).
	wantLabel := "/Pika:alice@example.com"
	if got, _ := url.PathUnescape(parsed.Path); got != wantLabel {
		t.Errorf("label: got %q want %q", got, wantLabel)
	}

	q := parsed.Query()
	if q.Get("issuer") != "Pika" {
		t.Errorf("issuer query: got %q", q.Get("issuer"))
	}
	if q.Get("secret") != sec.Base32() {
		t.Errorf("secret query: got %q want %q", q.Get("secret"), sec.Base32())
	}
	if q.Get("algorithm") != "SHA1" {
		t.Errorf("algorithm query: got %q", q.Get("algorithm"))
	}
	if q.Get("digits") != "6" {
		t.Errorf("digits query: got %q", q.Get("digits"))
	}
	if q.Get("period") != "30" {
		t.Errorf("period query: got %q", q.Get("period"))
	}
}

// TestURL_EmptyAccount documents the "fail loud" choice: rather than
// emit a URI with a blank label (which provisions cleanly but renders
// as an unlabeled entry that users can't distinguish), we return "".
func TestURL_EmptyAccount(t *testing.T) {
	sec, _ := NewSecret(bytes.NewReader(make([]byte, 32)), 20)
	if uri := sec.URL(KeyURIParams{Issuer: "Pika", Account: ""}); uri != "" {
		t.Errorf("URL with empty account should be empty, got %q", uri)
	}
}

// TestURL_NoIssuer covers the legal-but-uncommon case: an otpauth URI
// without an issuer is well-formed; the authenticator UI just shows
// only the account label. We omit the issuer query param too in that
// case (the spec recommends but doesn't require).
func TestURL_NoIssuer(t *testing.T) {
	sec, _ := NewSecret(bytes.NewReader(make([]byte, 32)), 20)
	uri := sec.URL(KeyURIParams{Account: "alice"})
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("URL not parseable: %v", err)
	}
	if got, _ := url.PathUnescape(parsed.Path); got != "/alice" {
		t.Errorf("label: got %q want %q", got, "/alice")
	}
	if _, present := parsed.Query()["issuer"]; present {
		t.Errorf("issuer query present despite empty Issuer")
	}
}

// TestNewSecret_ReadsBytes asserts the random reader integration. A
// fixed reader produces a deterministic secret — important so the
// constructor isn't hiding subtle "always 20 bytes regardless of
// reader" bugs that surface as repeated-secret pairings across users.
func TestNewSecret_ReadsBytes(t *testing.T) {
	fixed := bytes.Repeat([]byte{0xAB}, 32)
	sec, err := NewSecret(bytes.NewReader(fixed), 20)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	if got := sec.Bytes(); len(got) != 20 || !bytes.Equal(got, fixed[:20]) {
		t.Errorf("secret didn't take 20 bytes from reader: got %x", got)
	}

	// Zero/negative byteLen → default 20.
	sec2, err := NewSecret(bytes.NewReader(fixed), 0)
	if err != nil {
		t.Fatalf("NewSecret(0): %v", err)
	}
	if len(sec2.Bytes()) != 20 {
		t.Errorf("default byteLen: got %d want 20", len(sec2.Bytes()))
	}
}

// TestNewSecret_ShortReader surfaces a read error rather than silently
// truncating the secret. Without this check, a misbehaving reader
// (e.g. an /dev/urandom stub returning EOF early) would yield a
// weak/short secret.
func TestNewSecret_ShortReader(t *testing.T) {
	short := bytes.NewReader([]byte{0x01, 0x02, 0x03}) // only 3 bytes
	if _, err := NewSecret(short, 20); err == nil {
		t.Error("NewSecret with short reader should error")
	}
}

// TestSecretFromBase32_InvalidInput sanity-checks the parser fails
// loudly on input that isn't valid base32 (e.g. "1" — base32 has no
// digits-only alphabet for that character).
func TestSecretFromBase32_InvalidInput(t *testing.T) {
	if _, err := SecretFromBase32("1"); err == nil {
		t.Error("SecretFromBase32 accepted invalid input")
	}
	if _, err := SecretFromBase32("not-valid-base32!"); err == nil {
		t.Error("SecretFromBase32 accepted clearly-invalid input")
	}
}

// TestVerify_ZeroSkewStrict documents that Skew=0 rejects even a 1-period
// drift — useful when callers want maximum strictness (e.g. high-value
// admin actions) and accept the user-friendliness trade-off.
func TestVerify_ZeroSkewStrict(t *testing.T) {
	sec, _ := NewSecret(bytes.NewReader(make([]byte, 32)), 20)
	cfg := Default()
	cfg.Skew = 0

	t1 := time.Unix(1_700_000_000, 0)
	t2 := t1.Add(30 * time.Second) // exactly one window later

	code, _ := cfg.Generate(sec, t1)
	if cfg.Verify(sec, code, t2) {
		t.Errorf("Skew=0 accepted code from previous window")
	}
	if !cfg.Verify(sec, code, t1) {
		t.Errorf("Skew=0 rejected same-window code")
	}
}

// TestConfig_WithDefaults exercises the per-field defaulting so callers
// can construct a Config{Skew: 2} and trust the other fields to
// auto-fill.
func TestConfig_WithDefaults(t *testing.T) {
	c := Config{Skew: 2}.withDefaults()
	if c.Period != 30*time.Second {
		t.Errorf("Period default not applied: %v", c.Period)
	}
	if c.Digits != 6 {
		t.Errorf("Digits default not applied: %d", c.Digits)
	}
	if c.Algorithm != AlgorithmSHA1 {
		t.Errorf("Algorithm default not applied: %q", c.Algorithm)
	}
	if c.Skew != 2 {
		t.Errorf("Skew override clobbered by defaults: %d", c.Skew)
	}

	// Skew=0 must STAY 0 (it's a valid explicit choice, not "unset").
	c2 := Config{Period: time.Minute}.withDefaults()
	if c2.Skew != 0 {
		t.Errorf("Skew=0 overridden by defaults: %d", c2.Skew)
	}
}

// TestSecret_BytesDefensiveCopy guarantees the caller can't mutate
// internal secret state by holding onto the slice we return.
func TestSecret_BytesDefensiveCopy(t *testing.T) {
	sec := SecretFromBytes([]byte{1, 2, 3, 4, 5})
	got := sec.Bytes()
	got[0] = 99
	// Re-fetch and verify mutation didn't leak.
	if again := sec.Bytes(); again[0] != 1 {
		t.Errorf("Bytes() did not return a defensive copy: internal state mutated to %v", again)
	}
}

// Validate the package exports a sane base32 alphabet (smoke test that
// our encoding stays standard, not URL-safe or hex). Authenticator apps
// expect standard base32; URL-safe encoding would silently break them.
func TestEncoding_StandardBase32(t *testing.T) {
	sec := SecretFromBytes([]byte{0xFF, 0x00, 0xAB})
	got := sec.Base32()
	expect := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte{0xFF, 0x00, 0xAB})
	if got != expect {
		t.Errorf("encoding diverges from standard base32:\n got:    %q\n expect: %q", got, expect)
	}
}
