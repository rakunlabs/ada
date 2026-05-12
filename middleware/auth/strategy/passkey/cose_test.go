package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// encodeCOSEKey is a test-only helper that builds the deterministic
// CBOR shape an authenticator would emit for a given public key.
// Mirrors the COSE_Key labels in cose.go.
func encodeCOSEKey(t *testing.T, alg, kty int, fields map[int]any) []byte {
	t.Helper()
	// We hand-roll a minimal CBOR encoder here rather than depending
	// on a third-party lib. The test only emits maps with small
	// integer keys and a few byte-string/integer values — exactly
	// what's covered by the cases below.
	out := []byte{}
	// map header: a + N pairs (assuming N < 24 — true for all COSE
	// labels we encode).
	all := map[int]any{coseLabelKty: kty, coseLabelAlg: alg}
	for k, v := range fields {
		all[k] = v
	}
	if len(all) >= 24 {
		t.Fatalf("test helper supports ≤23 entries, got %d", len(all))
	}
	out = append(out, byte(0xa0|len(all)))
	// Stable-ish iteration: we only test correctness, not byte
	// equality, so iteration order doesn't matter for the decoder.
	for k, v := range all {
		out = append(out, encodeCBORInt(k)...)
		switch vv := v.(type) {
		case int:
			out = append(out, encodeCBORInt(vv)...)
		case []byte:
			out = append(out, encodeCBORBytes(vv)...)
		default:
			t.Fatalf("test helper does not encode %T", v)
		}
	}
	return out
}

func encodeCBORInt(n int) []byte {
	if n >= 0 && n < 24 {
		return []byte{byte(n)}
	}
	if n >= 24 && n < 256 {
		return []byte{0x18, byte(n)}
	}
	if n < 0 {
		v := -1 - n
		if v < 24 {
			return []byte{byte(0x20 | v)}
		}
		if v < 256 {
			return []byte{0x38, byte(v)}
		}
		if v < 65536 {
			return []byte{0x39, byte(v >> 8), byte(v)}
		}
	}
	// Wider ranges not needed for tests.
	panic("encodeCBORInt: value out of test range")
}

func encodeCBORBytes(b []byte) []byte {
	switch {
	case len(b) < 24:
		return append([]byte{byte(0x40 | len(b))}, b...)
	case len(b) < 256:
		return append([]byte{0x58, byte(len(b))}, b...)
	default:
		// 16-bit length.
		return append([]byte{0x59, byte(len(b) >> 8), byte(len(b))}, b...)
	}
}

func TestParseCOSE_ES256_roundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xb := priv.X.FillBytes(make([]byte, 32))
	yb := priv.Y.FillBytes(make([]byte, 32))

	blob := encodeCOSEKey(t, algES256, coseKtyEC2, map[int]any{
		coseLabelCrv: coseCrvP256,
		coseLabelX:   xb,
		coseLabelY:   yb,
	})

	pk, err := parseCOSEPublicKey(blob)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pk.Algorithm != algES256 {
		t.Errorf("alg: got %d, want %d", pk.Algorithm, algES256)
	}
	if pk.EC2 == nil || pk.EC2.X.Cmp(priv.X) != 0 || pk.EC2.Y.Cmp(priv.Y) != 0 {
		t.Error("decoded EC2 key does not match input")
	}
}

func TestParseCOSE_ES256_rejectsAlgCurveMismatch(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	xb := priv.X.FillBytes(make([]byte, 32))
	yb := priv.Y.FillBytes(make([]byte, 32))

	// P-256 curve but claim ES384 — must be rejected.
	blob := encodeCOSEKey(t, algES384, coseKtyEC2, map[int]any{
		coseLabelCrv: coseCrvP256,
		coseLabelX:   xb,
		coseLabelY:   yb,
	})
	if _, err := parseCOSEPublicKey(blob); err == nil {
		t.Error("expected alg/curve mismatch to fail")
	}
}

func TestParseCOSE_ES256_rejectsOffCurvePoint(t *testing.T) {
	// All-ones coordinates are not on P-256.
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	for i := range xb {
		xb[i] = 0xff
		yb[i] = 0xff
	}
	blob := encodeCOSEKey(t, algES256, coseKtyEC2, map[int]any{
		coseLabelCrv: coseCrvP256,
		coseLabelX:   xb,
		coseLabelY:   yb,
	})
	if _, err := parseCOSEPublicKey(blob); err == nil {
		t.Error("expected off-curve point to be rejected")
	}
}

func TestParseCOSE_RS256_roundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	nb := priv.N.Bytes()
	eb := []byte{0x01, 0x00, 0x01} // 65537

	blob := encodeCOSEKey(t, algRS256, coseKtyRSA, map[int]any{
		coseLabelN: nb,
		coseLabelE: eb,
	})
	pk, err := parseCOSEPublicKey(blob)
	if err != nil {
		t.Fatalf("parse rsa: %v", err)
	}
	if pk.RSA == nil || pk.RSA.E != 65537 || pk.RSA.N.Cmp(priv.N) != 0 {
		t.Errorf("decoded RSA key mismatch: e=%d n.bits=%d", pk.RSA.E, pk.RSA.N.BitLen())
	}
}

func TestParseCOSE_RS256_rejectsEvenExponent(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	nb := priv.N.Bytes()
	blob := encodeCOSEKey(t, algRS256, coseKtyRSA, map[int]any{
		coseLabelN: nb,
		coseLabelE: []byte{0x04}, // e=4 — even, rejected.
	})
	if _, err := parseCOSEPublicKey(blob); err == nil {
		t.Error("expected even exponent to be rejected")
	}
}

func TestParseCOSE_RS256_rejectsShortModulus(t *testing.T) {
	blob := encodeCOSEKey(t, algRS256, coseKtyRSA, map[int]any{
		coseLabelN: []byte{0x01, 0x02, 0x03},
		coseLabelE: []byte{0x01, 0x00, 0x01},
	})
	if _, err := parseCOSEPublicKey(blob); err == nil {
		t.Error("expected short modulus to be rejected")
	}
}

func TestParseCOSE_rejectsUnknownKty(t *testing.T) {
	blob := encodeCOSEKey(t, algES256, 99, nil)
	if _, err := parseCOSEPublicKey(blob); err == nil {
		t.Error("expected unsupported kty to fail")
	}
}

func TestParseCOSE_rejectsTrailingBytes(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	xb := priv.X.FillBytes(make([]byte, 32))
	yb := priv.Y.FillBytes(make([]byte, 32))
	blob := encodeCOSEKey(t, algES256, coseKtyEC2, map[int]any{
		coseLabelCrv: coseCrvP256,
		coseLabelX:   xb,
		coseLabelY:   yb,
	})
	// Append junk.
	blob = append(blob, 0xff, 0xff)
	if _, err := parseCOSEPublicKey(blob); err == nil {
		t.Error("expected trailing-bytes rejection")
	}
}

func TestAlgorithmName(t *testing.T) {
	cases := []struct {
		alg  int
		want string
	}{
		{algES256, "ES256"},
		{algRS256, "RS256"},
		{algEdDSA, "EdDSA"},
		{-99999, "unknown(-99999)"},
	}
	for _, c := range cases {
		if got := algorithmName(c.alg); got != c.want {
			t.Errorf("algorithmName(%d) = %q, want %q", c.alg, got, c.want)
		}
	}
}
