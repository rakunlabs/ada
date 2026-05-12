// Package passkey implements WebAuthn (FIDO2) registration and assertion
// for the ada auth middleware. This file contains the minimal CBOR
// (RFC 8949) decoder needed to parse the WebAuthn data structures —
// CBOR is used for the attestation object (registration response) and
// for the COSE_Key carried inside authenticator data.
//
// We deliberately implement only the subset of CBOR that WebAuthn
// emits in practice:
//
//   - Major types 0-5 (unsigned int, negative int, byte string,
//     text string, array, map). Tagged values (major type 6) are
//     accepted but their payload is returned as the inner value with
//     no semantic post-processing — WebAuthn doesn't rely on any tag
//     semantics. Major type 7 covers true/false/null/floats; we
//     accept the simple values and reject floats (no WebAuthn field
//     uses them).
//   - Definite-length encoding only. Indefinite-length strings, arrays
//     or maps are rejected. Authenticators never emit them and
//     accepting them is an attack-surface increase for no benefit.
//   - No half-precision floats. No simple-value extensions beyond
//     true/false/null.
//
// The decoder produces Go-native values (uint64, int64, []byte, string,
// []any, map[any]any, bool, nil). Map keys can be integers OR strings —
// the COSE_Key encoding uses integer keys, while clientDataJSON parsing
// elsewhere uses strings. Callers that expect a typed shape walk the
// returned values via the Helper methods below.
package passkey

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// CBOR major types from RFC 8949 §3.
const (
	cborMajorUint   = 0
	cborMajorNegInt = 1
	cborMajorBytes  = 2
	cborMajorText   = 3
	cborMajorArray  = 4
	cborMajorMap    = 5
	cborMajorTag    = 6
	cborMajorSimple = 7
)

// Simple-value codes we accept inside major type 7.
const (
	cborSimpleFalse = 20
	cborSimpleTrue  = 21
	cborSimpleNull  = 22
	// undef is intentionally rejected — WebAuthn never emits it and
	// distinguishing it from null in Go-native shape would force every
	// caller to handle two "absent" sentinels.
)

// errCBOR wraps every decoder error so the caller can distinguish
// malformed input from upstream validation errors. The wrapped value
// is informational only — never use it to branch in security-critical
// paths.
type errCBOR struct {
	msg string
	off int // byte offset where parsing failed; -1 if unknown
}

func (e *errCBOR) Error() string {
	if e.off >= 0 {
		return fmt.Sprintf("cbor: %s at offset %d", e.msg, e.off)
	}
	return "cbor: " + e.msg
}

func cborErr(off int, format string, args ...any) error {
	return &errCBOR{msg: fmt.Sprintf(format, args...), off: off}
}

// ErrTruncated is returned when the input ends before a value
// completes. Distinguishable from other CBOR errors so callers can
// surface "truncated input" specifically; the typical cause is a
// client implementation bug or a clipped transmission.
var ErrTruncated = errors.New("cbor: input truncated")

// decodeCBOR parses a single CBOR data item from data and returns the
// decoded value along with the number of bytes consumed. Strict mode:
// trailing bytes after the data item are not detected here; callers
// that require all-bytes-consumed semantics check (n == len(data))
// themselves. The WebAuthn spec sometimes concatenates a CBOR object
// with non-CBOR trailing bytes (e.g. extensions in authenticator
// data) so detecting trailing bytes is the caller's responsibility.
func decodeCBOR(data []byte) (any, int, error) {
	if len(data) == 0 {
		return nil, 0, ErrTruncated
	}
	v, n, err := decodeItem(data, 0, 0)
	return v, n, err
}

// decodeItem is the recursive workhorse. depth caps recursion so a
// pathological input can't blow the stack — 32 is well above anything
// WebAuthn emits (attestation objects max out at depth 4-5).
func decodeItem(data []byte, off, depth int) (any, int, error) {
	const maxDepth = 32
	if depth > maxDepth {
		return nil, off, cborErr(off, "max nesting depth exceeded")
	}

	if off >= len(data) {
		return nil, off, ErrTruncated
	}

	ib := data[off]
	major := ib >> 5
	minor := ib & 0x1f
	off++

	arg, n, err := readArgument(data, off, minor)
	if err != nil {
		return nil, off, err
	}
	off += n

	switch major {
	case cborMajorUint:
		return arg, off, nil

	case cborMajorNegInt:
		// Negative integers in CBOR encode -1-N. The smallest
		// representable value is -2^64; that overflows int64 but no
		// WebAuthn field uses it. Returning int64 is fine for the
		// COSE algorithm/curve constants we care about, which are
		// always tiny.
		if arg > math.MaxInt64 {
			return nil, off, cborErr(off, "negative int overflows int64")
		}
		return int64(-1) - int64(arg), off, nil

	case cborMajorBytes:
		if minor == 31 {
			return nil, off, cborErr(off, "indefinite-length byte string not supported")
		}
		end := off + int(arg)
		if end > len(data) || end < off {
			return nil, off, ErrTruncated
		}
		// Copy so callers can't accidentally mutate the input. CBOR
		// payloads in attestation flow are small (≤16 KiB for a
		// reasonable authenticator) so the allocation is fine.
		out := make([]byte, int(arg))
		copy(out, data[off:end])
		return out, end, nil

	case cborMajorText:
		if minor == 31 {
			return nil, off, cborErr(off, "indefinite-length text string not supported")
		}
		end := off + int(arg)
		if end > len(data) || end < off {
			return nil, off, ErrTruncated
		}
		// Strict UTF-8 is enforced by Go's string conversion semantics
		// only in `strings` helpers, not by string() itself; for our
		// usage (COSE_Key keys are integers, only RP-controlled
		// metadata is text) we don't enforce it explicitly. The
		// WebAuthn flow doesn't expose decoded text strings to
		// untrusted code paths.
		return string(data[off:end]), end, nil

	case cborMajorArray:
		if minor == 31 {
			return nil, off, cborErr(off, "indefinite-length array not supported")
		}
		out := make([]any, 0, int(arg))
		for i := uint64(0); i < arg; i++ {
			v, n, err := decodeItem(data, off, depth+1)
			if err != nil {
				return nil, off, err
			}
			out = append(out, v)
			off = n
		}
		return out, off, nil

	case cborMajorMap:
		if minor == 31 {
			return nil, off, cborErr(off, "indefinite-length map not supported")
		}
		// COSE_Key uses small integer keys; attestation object uses
		// short string keys. Both must be hashable. We use any-keyed
		// map and let the caller cast — sub-100 entries in practice
		// so the allocation overhead is negligible.
		out := make(map[any]any, int(arg))
		for i := uint64(0); i < arg; i++ {
			k, kn, err := decodeItem(data, off, depth+1)
			if err != nil {
				return nil, off, err
			}
			off = kn
			// Reject map keys that aren't hashable. Slices/maps as keys
			// would panic on assignment; explicit rejection gives a
			// useful error.
			switch k.(type) {
			case uint64, int64, string, bool, nil:
				// fine
			case []byte:
				// Byte-string keys are theoretically legal but
				// WebAuthn never emits them; we reject to keep the
				// decoder shape predictable.
				return nil, off, cborErr(off, "byte-string map keys not supported")
			default:
				return nil, off, cborErr(off, "unsupported map key type %T", k)
			}
			v, vn, err := decodeItem(data, off, depth+1)
			if err != nil {
				return nil, off, err
			}
			off = vn
			// Reject duplicate keys. RFC 8949 §5.6 says decoders
			// "should" detect them; for security-sensitive maps
			// (COSE_Key) we treat them as an error so an attacker
			// can't smuggle a shadowed value past the parser.
			if _, dup := out[k]; dup {
				return nil, off, cborErr(off, "duplicate map key %v", k)
			}
			out[k] = v
		}
		return out, off, nil

	case cborMajorTag:
		// We don't act on tag semantics — return the inner value
		// directly. WebAuthn's attestation flow uses tag 0/1 (string
		// date / epoch date) for some optional metadata which we
		// don't consume.
		inner, n, err := decodeItem(data, off, depth+1)
		if err != nil {
			return nil, off, err
		}
		return inner, n, nil

	case cborMajorSimple:
		switch minor {
		case cborSimpleFalse:
			return false, off, nil
		case cborSimpleTrue:
			return true, off, nil
		case cborSimpleNull:
			return nil, off, nil
		case 25, 26, 27:
			// Half/single/double float — rejected. No WebAuthn field
			// uses floats; accepting them is unnecessary attack
			// surface.
			return nil, off, cborErr(off, "floating-point values not supported")
		case 24:
			// One-byte simple value with code in [32,255]. Reject —
			// not used by WebAuthn.
			return nil, off, cborErr(off, "extension simple values not supported")
		case 31:
			return nil, off, cborErr(off, "indefinite-length break not allowed")
		default:
			return nil, off, cborErr(off, "unknown simple value %d", minor)
		}
	}

	return nil, off, cborErr(off, "unknown major type %d", major)
}

// readArgument decodes the integer argument of a CBOR head byte.
// minor in [0,23] is the argument itself; 24/25/26/27 indicate a
// following 1/2/4/8-byte big-endian unsigned integer. 28-30 are
// reserved and rejected. 31 is "indefinite length" — the caller
// branches on minor==31 before calling here for arrays/maps/strings.
func readArgument(data []byte, off int, minor byte) (uint64, int, error) {
	switch {
	case minor < 24:
		return uint64(minor), 0, nil
	case minor == 24:
		if off+1 > len(data) {
			return 0, 0, ErrTruncated
		}
		return uint64(data[off]), 1, nil
	case minor == 25:
		if off+2 > len(data) {
			return 0, 0, ErrTruncated
		}
		return uint64(binary.BigEndian.Uint16(data[off:])), 2, nil
	case minor == 26:
		if off+4 > len(data) {
			return 0, 0, ErrTruncated
		}
		return uint64(binary.BigEndian.Uint32(data[off:])), 4, nil
	case minor == 27:
		if off+8 > len(data) {
			return 0, 0, ErrTruncated
		}
		return binary.BigEndian.Uint64(data[off:]), 8, nil
	case minor == 31:
		// Indefinite-length marker — the caller handles this by
		// inspecting minor itself before invoking us.
		return 0, 0, nil
	default:
		// 28-30 are reserved.
		return 0, 0, cborErr(off, "reserved argument %d", minor)
	}
}

// cborInt coerces a decoded CBOR number (uint64 or int64) to int64.
// Useful for COSE_Key parsing where the algorithm identifier is a
// small negative integer (e.g. -7 for ES256).
func cborInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case uint64:
		if x > math.MaxInt64 {
			return 0, false
		}
		return int64(x), true
	}
	return 0, false
}

// cborBytes returns v as []byte or false on type mismatch.
func cborBytes(v any) ([]byte, bool) {
	b, ok := v.([]byte)
	return b, ok
}

// cborString returns v as string or false on type mismatch.
func cborString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// cborMap returns v as the decoded map shape or false on type
// mismatch.
func cborMap(v any) (map[any]any, bool) {
	m, ok := v.(map[any]any)
	return m, ok
}

// cborMapGet looks up a key in a decoded map. Maps may use either int
// or uint integer keys depending on the encoder, so for an int64 key
// we also try the uint64 form. Returns (value, true) if found.
func cborMapGet(m map[any]any, key any) (any, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	// COSE encoders sometimes emit positive integers as uint64 and
	// negative ones as int64; lookups by raw int constants must
	// tolerate both shapes.
	switch k := key.(type) {
	case int64:
		if k >= 0 {
			if v, ok := m[uint64(k)]; ok {
				return v, true
			}
		}
	case int:
		if k >= 0 {
			if v, ok := m[uint64(k)]; ok {
				return v, true
			}
		}
		if v, ok := m[int64(k)]; ok {
			return v, true
		}
	case uint64:
		if k <= math.MaxInt64 {
			if v, ok := m[int64(k)]; ok {
				return v, true
			}
		}
	}
	return nil, false
}
