package passkey

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// COSE_Key parameter labels from RFC 9052 §7.1 + §13.1.1 (EC2) + §13.2.1
// (RSA) + §13.2 (OKP). We only handle the parameters used by WebAuthn
// public-key credentials.
const (
	coseLabelKty = 1 // Key type
	coseLabelAlg = 3 // Algorithm
	// EC2-specific (kty=2):
	coseLabelCrv = -1 // Curve
	coseLabelX   = -2 // X coordinate
	coseLabelY   = -3 // Y coordinate
	// RSA-specific (kty=3):
	coseLabelN = -1 // Modulus
	coseLabelE = -2 // Exponent
	// OKP (kty=1) reuses the same crv and x labels as EC2; there is
	// no y coordinate (Ed25519 uses a compressed encoding).
)

// COSE key types we accept (RFC 9053 §7.1).
const (
	coseKtyOKP = 1 // Octet key pair (Ed25519)
	coseKtyEC2 = 2 // Elliptic-curve (P-256/384/521)
	coseKtyRSA = 3 // RSA
)

// COSE curve identifiers (RFC 9053 §7.1).
const (
	coseCrvP256    = 1
	coseCrvP384    = 2
	coseCrvP521    = 3
	coseCrvEd25519 = 6
)

// COSE algorithm identifiers (RFC 9053 §2). WebAuthn additionally
// supports RS1 and PS-* — we accept the ones an authenticator actually
// emits today.
const (
	algES256 = -7
	algES384 = -35
	algES512 = -36
	algRS256 = -257
	algRS384 = -258
	algRS512 = -259
	algPS256 = -37
	algPS384 = -38
	algPS512 = -39
	algEdDSA = -8
)

const (
	minRSAModulusBits = 2048
	maxRSAModulusBits = 8192
	maxRSAExponent    = 1<<31 - 1
)

// CredentialAlgorithm bundles a COSE-numeric alg with the
// human-friendly name we surface in API responses. Callers (e.g. the
// registration ceremony) advertise the set they accept and the
// authenticator picks one.
type CredentialAlgorithm struct {
	COSE int    // numeric COSE alg (e.g. -7)
	Name string // short label for logs/API ("ES256")
}

// DefaultAlgorithms lists the public-key algorithms an authenticator
// may use when registering a credential with this package. The order
// matters: the authenticator picks the first one it supports, so the
// most-widely-deployed and most-recommended algorithms come first.
//
// ES256 is the de-facto WebAuthn default (every modern authenticator
// supports it). EdDSA is offered next because recent YubiKeys, Apple
// platform authenticators, and Android keystore credentials can emit
// Ed25519 with a smaller signature and faster verification — but
// rolling it ahead of ES256 would be a needless compatibility break
// for older keys. RS256 stays in the list to cover Windows Hello on
// pre-2020 builds and old YubiKey 4 series. Stronger ES* are accepted
// on the verification path even though the default offer list doesn't
// include them — see algorithmName for the verify-time table.
var DefaultAlgorithms = []CredentialAlgorithm{
	{COSE: algES256, Name: "ES256"},
	{COSE: algEdDSA, Name: "EdDSA"},
	{COSE: algRS256, Name: "RS256"},
}

// publicKey is the parsed form of a COSE_Key blob. Exactly one of EC2,
// RSA, or Ed25519 is populated. Algorithm holds the COSE alg identifier.
type publicKey struct {
	Algorithm int
	EC2       *ecdsa.PublicKey
	RSA       *rsa.PublicKey
	Ed25519   ed25519.PublicKey
}

// parseCOSEPublicKey decodes a CBOR-encoded COSE_Key into a typed
// public key. It tolerates either signed or unsigned integer encoding
// for positive labels (different encoders may emit either) by going
// through cborMapGet's coercion helpers.
//
// Returned errors are deliberately generic so a malicious client can't
// probe for whether a particular label was missing or just typed
// wrong — the WebAuthn flow treats every COSE failure as "registration
// failed" anyway.
func parseCOSEPublicKey(blob []byte) (*publicKey, error) {
	v, n, err := decodeCBOR(blob)
	if err != nil {
		return nil, fmt.Errorf("cose: decode cbor: %w", err)
	}
	if n != len(blob) {
		// Trailing bytes after a COSE_Key are suspicious — the format
		// is fixed-shape and any trailing data signals an encoder
		// bug or an attack attempt.
		return nil, errors.New("cose: trailing bytes after key")
	}

	m, ok := cborMap(v)
	if !ok {
		return nil, errors.New("cose: not a map")
	}

	kty, err := mapInt(m, coseLabelKty)
	if err != nil {
		return nil, fmt.Errorf("cose: kty: %w", err)
	}
	alg, err := mapInt(m, coseLabelAlg)
	if err != nil {
		return nil, fmt.Errorf("cose: alg: %w", err)
	}

	switch kty {
	case coseKtyEC2:
		return parseEC2Key(m, int(alg))
	case coseKtyRSA:
		return parseRSAKey(m, int(alg))
	case coseKtyOKP:
		return parseOKPKey(m, int(alg))
	default:
		return nil, fmt.Errorf("cose: unsupported kty %d", kty)
	}
}

// parseOKPKey extracts an Ed25519 (OKP) public key. WebAuthn-emitted
// OKP keys carry alg=EdDSA, crv=Ed25519, and a single 32-byte x
// coordinate (the compressed Edwards point). Per RFC 9053 §13.2 the
// y label is not present for OKP keys. We reject any other curve
// even when alg is EdDSA because Ed448 (crv=7) is structurally
// similar but uses 57-byte coordinates and a different verification
// procedure — accepting it silently would be a downgrade vector.
func parseOKPKey(m map[any]any, alg int) (*publicKey, error) {
	if alg != algEdDSA {
		return nil, fmt.Errorf("alg %d not supported for OKP keys (want EdDSA)", alg)
	}
	crv, err := mapInt(m, coseLabelCrv)
	if err != nil {
		return nil, fmt.Errorf("crv: %w", err)
	}
	if crv != coseCrvEd25519 {
		return nil, fmt.Errorf("unsupported OKP curve %d (only Ed25519 is accepted)", crv)
	}
	xb, err := mapBytes(m, coseLabelX)
	if err != nil {
		return nil, fmt.Errorf("x: %w", err)
	}
	if len(xb) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519 public key length %d (want %d)", len(xb), ed25519.PublicKeySize)
	}
	// Copy so the caller can't mutate the CBOR-decoded backing
	// slice and trip us up on subsequent verifies.
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(key, xb)
	return &publicKey{
		Algorithm: alg,
		Ed25519:   key,
	}, nil
}

// parseEC2Key extracts a P-256/P-384/P-521 ECDSA public key. Coordinate
// integers are stored as fixed-length big-endian byte strings per
// RFC 9052 §13.1.1 (length == curve byte size). We reject mismatched
// lengths to prevent a forged short-coordinate from being silently
// zero-padded into a valid-looking key.
func parseEC2Key(m map[any]any, alg int) (*publicKey, error) {
	crv, err := mapInt(m, coseLabelCrv)
	if err != nil {
		return nil, fmt.Errorf("crv: %w", err)
	}

	var (
		curve     elliptic.Curve
		ecdhCurve ecdh.Curve
		coordSize int
	)

	switch crv {
	case coseCrvP256:
		curve, ecdhCurve = elliptic.P256(), ecdh.P256()
		coordSize = 32
	case coseCrvP384:
		curve, ecdhCurve = elliptic.P384(), ecdh.P384()
		coordSize = 48
	case coseCrvP521:
		curve, ecdhCurve = elliptic.P521(), ecdh.P521()
		coordSize = 66
	default:
		return nil, fmt.Errorf("unsupported curve %d", crv)
	}

	// Cross-check the alg field against the curve. An authenticator
	// MUST pair ES256 with P-256, ES384 with P-384, ES512 with P-521;
	// anything else is either a bug or an injection attempt.
	wantAlg := map[elliptic.Curve]int{
		elliptic.P256(): algES256,
		elliptic.P384(): algES384,
		elliptic.P521(): algES512,
	}[curve]
	if alg != wantAlg {
		return nil, fmt.Errorf("alg %d does not match curve %d", alg, crv)
	}

	xb, err := mapBytes(m, coseLabelX)
	if err != nil {
		return nil, fmt.Errorf("x: %w", err)
	}
	yb, err := mapBytes(m, coseLabelY)
	if err != nil {
		return nil, fmt.Errorf("y: %w", err)
	}
	if len(xb) != coordSize || len(yb) != coordSize {
		return nil, fmt.Errorf("coordinate length mismatch (got x=%d y=%d, want %d)", len(xb), len(yb), coordSize)
	}

	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)

	// Point-on-curve check is essential. Without it, a malicious
	// authenticator (or a forged COSE_Key) could submit a point not
	// on the curve, which some signature verification paths accept
	// silently and use to recover an arbitrary "valid" signature.
	//
	// Done through crypto/ecdh: elliptic.IsOnCurve is deprecated and, on some
	// curves, was only ever a partial check.
	uncompressed := make([]byte, 1+2*coordSize)
	uncompressed[0] = 4
	copy(uncompressed[1:1+coordSize], xb)
	copy(uncompressed[1+coordSize:], yb)

	if _, err := ecdhCurve.NewPublicKey(uncompressed); err != nil {
		return nil, fmt.Errorf("public key point is not on the named curve: %w", err)
	}

	return &publicKey{
		Algorithm: alg,
		EC2:       &ecdsa.PublicKey{Curve: curve, X: x, Y: y},
	}, nil
}

// parseRSAKey extracts an RSA public key. WebAuthn RSA keys carry the
// modulus n (big-endian byte string) and the public exponent e (also
// big-endian byte string, never an integer). The exponent must be
// odd and within sane bounds. Moduli outside 2048-8192 bits and exponents
// larger than a signed 32-bit integer are non-standard and needlessly costly.
func parseRSAKey(m map[any]any, alg int) (*publicKey, error) {
	nb, err := mapBytes(m, coseLabelN)
	if err != nil {
		return nil, fmt.Errorf("n: %w", err)
	}
	eb, err := mapBytes(m, coseLabelE)
	if err != nil {
		return nil, fmt.Errorf("e: %w", err)
	}
	if len(nb) > maxRSAModulusBits/8 {
		return nil, fmt.Errorf("rsa modulus too large (%d bytes)", len(nb))
	}
	if len(eb) == 0 || len(eb) > 4 {
		return nil, fmt.Errorf("rsa exponent length %d outside [1,4]", len(eb))
	}

	n := new(big.Int).SetBytes(nb)
	if bits := n.BitLen(); bits < minRSAModulusBits || bits > maxRSAModulusBits {
		return nil, fmt.Errorf("rsa modulus size %d bits outside [%d,%d]", bits, minRSAModulusBits, maxRSAModulusBits)
	}
	if n.Bit(0) == 0 {
		return nil, errors.New("rsa modulus must be odd")
	}

	bigE := new(big.Int).SetBytes(eb)
	if !bigE.IsInt64() || bigE.Int64() > maxRSAExponent {
		return nil, errors.New("rsa exponent too large")
	}
	e := bigE.Int64()
	if e < 3 || e%2 == 0 {
		return nil, fmt.Errorf("rsa exponent %d is invalid (must be odd and ≥3)", e)
	}

	// alg must be one of the RSA family. We don't enforce a single
	// alg here because the registration ceremony will surface the
	// authenticator's choice; we just rule out obvious nonsense.
	switch alg {
	case algRS256, algRS384, algRS512, algPS256, algPS384, algPS512:
		// OK.
	default:
		return nil, fmt.Errorf("alg %d not a supported RSA algorithm", alg)
	}

	return &publicKey{
		Algorithm: alg,
		RSA:       &rsa.PublicKey{N: n, E: int(e)},
	}, nil
}

// mapInt reads an integer-valued COSE field, accepting either signed
// or unsigned CBOR encoding. Missing or wrong-typed keys yield a
// clear error.
func mapInt(m map[any]any, label int) (int64, error) {
	raw, ok := cborMapGet(m, int64(label))
	if !ok {
		return 0, fmt.Errorf("label %d missing", label)
	}
	v, ok := cborInt(raw)
	if !ok {
		return 0, fmt.Errorf("label %d not an integer (got %T)", label, raw)
	}
	return v, nil
}

// mapBytes reads a byte-string COSE field.
func mapBytes(m map[any]any, label int) ([]byte, error) {
	raw, ok := cborMapGet(m, int64(label))
	if !ok {
		return nil, fmt.Errorf("label %d missing", label)
	}
	b, ok := cborBytes(raw)
	if !ok {
		return nil, fmt.Errorf("label %d not a byte string (got %T)", label, raw)
	}
	return b, nil
}

// ecdsaSignature is the ASN.1 DER shape WebAuthn (and X.509) uses to
// encode ECDSA signatures: SEQUENCE { r INTEGER, s INTEGER }.
type ecdsaSignature struct {
	R, S *big.Int
}

// parseECDSASignature decodes a DER-encoded ECDSA signature into its
// (r, s) components. We accept only strict DER — anything looser
// would allow signature malleability (the same logical signature with
// two byte-level encodings).
func parseECDSASignature(sig []byte) (r, s *big.Int, err error) {
	var parsed ecdsaSignature
	rest, err := asn1.Unmarshal(sig, &parsed)
	if err != nil {
		return nil, nil, fmt.Errorf("decode ecdsa signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, nil, errors.New("trailing bytes in ecdsa signature")
	}
	if parsed.R == nil || parsed.S == nil || parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
		return nil, nil, errors.New("ecdsa signature contains zero or negative component")
	}
	return parsed.R, parsed.S, nil
}

// algorithmName returns the short label for a COSE alg identifier,
// or "unknown(<n>)" when we don't recognize it. Used in error
// messages and audit logs.
func algorithmName(alg int) string {
	switch alg {
	case algES256:
		return "ES256"
	case algES384:
		return "ES384"
	case algES512:
		return "ES512"
	case algRS256:
		return "RS256"
	case algRS384:
		return "RS384"
	case algRS512:
		return "RS512"
	case algPS256:
		return "PS256"
	case algPS384:
		return "PS384"
	case algPS512:
		return "PS512"
	case algEdDSA:
		return "EdDSA"
	default:
		return fmt.Sprintf("unknown(%d)", alg)
	}
}
