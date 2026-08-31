package passkey

import (
	"bytes"
	"errors"
	"testing"
)

func TestDecodeCBOR_unsignedInt(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want uint64
	}{
		// RFC 8949 appendix A vectors.
		{"0", []byte{0x00}, 0},
		{"10", []byte{0x0a}, 10},
		{"23", []byte{0x17}, 23},
		{"24", []byte{0x18, 0x18}, 24},
		{"100", []byte{0x18, 0x64}, 100},
		{"1000", []byte{0x19, 0x03, 0xe8}, 1000},
		{"1_000_000", []byte{0x1a, 0x00, 0x0f, 0x42, 0x40}, 1_000_000},
		{"1_000_000_000_000", []byte{0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00}, 1_000_000_000_000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, n, err := decodeCBOR(c.in)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if got, ok := v.(uint64); !ok || got != c.want {
				t.Fatalf("got %v (%T), want %d", v, v, c.want)
			}
			if n != len(c.in) {
				t.Errorf("consumed %d bytes, want %d", n, len(c.in))
			}
		})
	}
}

func TestDecodeCBOR_negativeInt(t *testing.T) {
	cases := []struct {
		in   []byte
		want int64
	}{
		// -1, -10, -100, -1000
		{[]byte{0x20}, -1},
		{[]byte{0x29}, -10},
		{[]byte{0x38, 0x63}, -100},
		{[]byte{0x39, 0x03, 0xe7}, -1000},
		// COSE algorithm constants we'll see in practice
		{[]byte{0x26}, -7},               // ES256
		{[]byte{0x39, 0x01, 0x00}, -257}, // RS256
	}
	for _, c := range cases {
		v, _, err := decodeCBOR(c.in)
		if err != nil {
			t.Fatalf("decode error for %x: %v", c.in, err)
		}
		got, ok := v.(int64)
		if !ok || got != c.want {
			t.Errorf("input %x: got %v (%T), want %d", c.in, v, v, c.want)
		}
	}
}

func TestDecodeCBOR_bytesAndText(t *testing.T) {
	// h'' (empty bytes)
	v, _, err := decodeCBOR([]byte{0x40})
	if err != nil || !bytes.Equal(v.([]byte), []byte{}) {
		t.Errorf("empty bytes: got %v, err %v", v, err)
	}
	// h'01020304'
	v, _, err = decodeCBOR([]byte{0x44, 0x01, 0x02, 0x03, 0x04})
	if err != nil || !bytes.Equal(v.([]byte), []byte{1, 2, 3, 4}) {
		t.Errorf("bytes: got %v, err %v", v, err)
	}
	// "IETF" (text)
	v, _, err = decodeCBOR([]byte{0x64, 'I', 'E', 'T', 'F'})
	if err != nil || v.(string) != "IETF" {
		t.Errorf("text: got %v, err %v", v, err)
	}
}

func TestDecodeCBOR_arrayAndMap(t *testing.T) {
	// [1, 2, 3]
	v, _, err := decodeCBOR([]byte{0x83, 0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("array decode: %v", err)
	}
	arr := v.([]any)
	if len(arr) != 3 || arr[0].(uint64) != 1 || arr[2].(uint64) != 3 {
		t.Errorf("array shape wrong: %v", arr)
	}

	// {1: 2, 3: 4}
	v, _, err = decodeCBOR([]byte{0xa2, 0x01, 0x02, 0x03, 0x04})
	if err != nil {
		t.Fatalf("map decode: %v", err)
	}
	m := v.(map[any]any)
	if len(m) != 2 || m[uint64(1)].(uint64) != 2 || m[uint64(3)].(uint64) != 4 {
		t.Errorf("map shape wrong: %v", m)
	}

	// Lookup helper handles int/uint coercion.
	if got, ok := cborMapGet(m, int64(1)); !ok || got.(uint64) != 2 {
		t.Errorf("cborMapGet int64 lookup failed: got %v ok %v", got, ok)
	}
}

func TestDecodeCBOR_simpleValues(t *testing.T) {
	cases := []struct {
		in   byte
		want any
	}{
		{0xf4, false}, // false
		{0xf5, true},  // true
		{0xf6, nil},   // null
	}
	for _, c := range cases {
		v, _, err := decodeCBOR([]byte{c.in})
		if err != nil {
			t.Fatalf("decode %#x: %v", c.in, err)
		}
		if v != c.want {
			t.Errorf("%#x: got %v, want %v", c.in, v, c.want)
		}
	}
}

func TestDecodeCBOR_rejectsAdditionalInformation31ForEveryMajorType(t *testing.T) {
	for major := byte(0); major < 8; major++ {
		input := []byte{major<<5 | 31}
		if _, _, err := decodeCBOR(input); err == nil {
			t.Errorf("major type %d accepted additional information 31", major)
		}
	}
}

func TestDecodeCBOR_rejectsFloats(t *testing.T) {
	// 0xf9 (half-float), 0xfa (single), 0xfb (double)
	for _, b := range []byte{0xf9, 0xfa, 0xfb} {
		buf := append([]byte{b}, 0, 0, 0, 0, 0, 0, 0, 0)
		_, _, err := decodeCBOR(buf)
		if err == nil {
			t.Errorf("expected error for float prefix %#x", b)
		}
	}
}

func TestDecodeCBOR_rejectsDuplicateMapKeys(t *testing.T) {
	// {1: 2, 1: 3}
	_, _, err := decodeCBOR([]byte{0xa2, 0x01, 0x02, 0x01, 0x03})
	if err == nil {
		t.Error("expected error for duplicate map key")
	}
}

func TestDecodeCBOR_truncated(t *testing.T) {
	// {1: <missing>}
	_, _, err := decodeCBOR([]byte{0xa1, 0x01})
	if !errors.Is(err, ErrTruncated) && err == nil {
		t.Errorf("expected truncation error, got %v", err)
	}
	// nil-safe empty input
	if _, _, err := decodeCBOR(nil); err == nil {
		t.Error("nil input should error")
	}
}

func TestDecodeCBOR_taggedValue(t *testing.T) {
	// Tag(2) 0x42 0x01 0x02 — should return inner value (the bytes)
	// without any tag-specific transformation.
	v, _, err := decodeCBOR([]byte{0xc2, 0x42, 0x01, 0x02})
	if err != nil {
		t.Fatalf("tagged decode: %v", err)
	}
	if !bytes.Equal(v.([]byte), []byte{1, 2}) {
		t.Errorf("tagged inner mismatch: %v", v)
	}
}

func TestDecodeCBOR_rejectsHugeLengthsWithoutPanic(t *testing.T) {
	huge := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for _, major := range []byte{0x5b, 0x7b, 0x9b, 0xbb} {
		input := append([]byte{major}, huge...)
		if _, _, err := decodeCBOR(input); err == nil {
			t.Errorf("decodeCBOR(%x) unexpectedly succeeded", input)
		}
	}
}

func TestDecodeCBOR_enforcesAllocationLimits(t *testing.T) {
	cases := [][]byte{
		{0x5a, 0x00, 0x10, 0x00, 0x01}, // byte string: 1 MiB + 1
		{0x7a, 0x00, 0x10, 0x00, 0x01}, // text string: 1 MiB + 1
		{0x99, 0x04, 0x01},             // array: 1025 items
		{0xb9, 0x04, 0x01},             // map: 1025 pairs
	}
	for _, input := range cases {
		if _, _, err := decodeCBOR(input); err == nil {
			t.Errorf("decodeCBOR(%x) unexpectedly succeeded", input)
		}
	}
}

func TestDecodeCBOR_rejectsImplausibleCollections(t *testing.T) {
	cases := [][]byte{
		{0x98, 0x18}, // 24 array items, no item bytes
		{0xb8, 0x18}, // 24 map pairs, no key/value bytes
	}
	for _, input := range cases {
		if _, _, err := decodeCBOR(input); !errors.Is(err, ErrTruncated) {
			t.Errorf("decodeCBOR(%x) error = %v, want ErrTruncated", input, err)
		}
	}
}

func TestCBORUintToInt_rejectsOverflow(t *testing.T) {
	if _, ok := cborUintToInt(^uint64(0)); ok {
		t.Fatal("cborUintToInt(MaxUint64) unexpectedly succeeded")
	}
}
