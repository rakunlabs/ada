package securecookie_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rakunlabs/ada/utils/securecookie"
)

func newCodec(t *testing.T, opts ...securecookie.Option) *securecookie.Codec {
	t.Helper()

	hashKey := securecookie.GenerateRandomKey(32)
	blockKey := securecookie.GenerateRandomKey(32)

	return securecookie.New(hashKey, blockKey, opts...)
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	c := newCodec(t)

	in := map[string]any{"user": "ada", "n": int64(42)}
	encoded, err := c.Encode("session", in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	out := map[string]any{}
	if err := c.Decode("session", encoded, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if out["user"] != "ada" || out["n"] != int64(42) {
		t.Fatalf("round-trip mismatch: %#v", out)
	}
}

func TestEncodeDecode_SignOnly(t *testing.T) {
	c := securecookie.New(securecookie.GenerateRandomKey(32), nil)

	encoded, err := c.Encode("s", "hello")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	var out string
	if err := c.Decode("s", encoded, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out != "hello" {
		t.Fatalf("got %q", out)
	}
}

func TestDecode_JSONSerializer(t *testing.T) {
	opt := securecookie.WithSerializer(securecookie.JSONSerializer{})
	c := securecookie.New(securecookie.GenerateRandomKey(32), nil, opt)

	type payload struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}

	encoded, err := c.Encode("s", payload{Name: "ada", Age: 7})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	var out payload
	if err := c.Decode("s", encoded, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Name != "ada" || out.Age != 7 {
		t.Fatalf("got %#v", out)
	}
}

func TestDecode_TamperedMAC(t *testing.T) {
	c := newCodec(t)

	encoded, err := c.Encode("s", "secret")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Flip a character in the middle of the token.
	b := []byte(encoded)
	mid := len(b) / 2
	if b[mid] == 'A' {
		b[mid] = 'B'
	} else {
		b[mid] = 'A'
	}

	var out string
	err = c.Decode("s", string(b), &out)
	if err == nil {
		t.Fatal("expected error on tampered value")
	}
}

func TestDecode_WrongName(t *testing.T) {
	c := newCodec(t)

	encoded, err := c.Encode("name-a", "v")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	var out string
	if err := c.Decode("name-b", encoded, &out); !errors.Is(err, securecookie.ErrMACInvalid) {
		t.Fatalf("want ErrMACInvalid, got %v", err)
	}
}

func TestDecode_WrongKey(t *testing.T) {
	c1 := newCodec(t)
	c2 := newCodec(t)

	encoded, err := c1.Encode("s", "v")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	var out string
	if err := c2.Decode("s", encoded, &out); !errors.Is(err, securecookie.ErrMACInvalid) {
		t.Fatalf("want ErrMACInvalid, got %v", err)
	}
}

func TestDecode_Expired(t *testing.T) {
	base := time.Unix(1_000_000, 0)
	clock := base

	c := securecookie.New(
		securecookie.GenerateRandomKey(32), nil,
		securecookie.WithMaxAge(60),
		securecookie.WithNow(func() time.Time { return clock }),
	)

	encoded, err := c.Encode("s", "v")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	clock = base.Add(120 * time.Second)

	var out string
	if err := c.Decode("s", encoded, &out); !errors.Is(err, securecookie.ErrTimestampExpired) {
		t.Fatalf("want ErrTimestampExpired, got %v", err)
	}
}

func TestDecode_TooNew(t *testing.T) {
	base := time.Unix(1_000_000, 0)
	clock := base

	c := securecookie.New(
		securecookie.GenerateRandomKey(32), nil,
		securecookie.WithMinAge(60),
		securecookie.WithNow(func() time.Time { return clock }),
	)

	encoded, err := c.Encode("s", "v")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Decode immediately: value is younger than minAge.
	var out string
	if err := c.Decode("s", encoded, &out); !errors.Is(err, securecookie.ErrTimestampTooNew) {
		t.Fatalf("want ErrTimestampTooNew, got %v", err)
	}
}

func TestEncode_ValueTooLong(t *testing.T) {
	c := securecookie.New(securecookie.GenerateRandomKey(32), nil, securecookie.WithMaxLength(16))

	if _, err := c.Encode("s", "this value is definitely longer than sixteen bytes"); !errors.Is(err, securecookie.ErrValueTooLong) {
		t.Fatalf("want ErrValueTooLong, got %v", err)
	}
}

func TestNew_InvalidBlockKey(t *testing.T) {
	_, err := securecookie.NewWithError(securecookie.GenerateRandomKey(32), securecookie.GenerateRandomKey(13))
	if !errors.Is(err, securecookie.ErrInvalidBlockKeySize) {
		t.Fatalf("want ErrInvalidBlockKeySize, got %v", err)
	}
}

func TestNew_MissingHashKey(t *testing.T) {
	if _, err := securecookie.NewWithError(nil, nil); !errors.Is(err, securecookie.ErrHashKeyRequired) {
		t.Fatalf("want ErrHashKeyRequired, got %v", err)
	}
}

func TestCodecs_Rotation(t *testing.T) {
	oldHash := securecookie.GenerateRandomKey(32)
	oldBlock := securecookie.GenerateRandomKey(32)
	newHash := securecookie.GenerateRandomKey(32)
	newBlock := securecookie.GenerateRandomKey(32)

	old := securecookie.New(oldHash, oldBlock)

	// A value signed with the old key.
	encoded, err := old.Encode("s", "legacy")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// New deployment: new key first, old key kept for decoding.
	rotated := securecookie.CodecsFromPairs(nil,
		newHash, newBlock,
		oldHash, oldBlock,
	)

	var out string
	if err := rotated.Decode("s", encoded, &out); err != nil {
		t.Fatalf("decode legacy: %v", err)
	}
	if out != "legacy" {
		t.Fatalf("got %q", out)
	}

	// Newly encoded value uses the new key and still decodes.
	fresh, err := rotated.Encode("s", "current")
	if err != nil {
		t.Fatalf("encode current: %v", err)
	}

	out = ""
	if err := rotated.Decode("s", fresh, &out); err != nil {
		t.Fatalf("decode current: %v", err)
	}
	if out != "current" {
		t.Fatalf("got %q", out)
	}
}

func TestCodecs_Empty(t *testing.T) {
	var cs securecookie.Codecs

	if _, err := cs.Encode("s", "v"); !errors.Is(err, securecookie.ErrNoCodecs) {
		t.Fatalf("want ErrNoCodecs, got %v", err)
	}

	var out string
	if err := cs.Decode("s", "x", &out); !errors.Is(err, securecookie.ErrNoCodecs) {
		t.Fatalf("want ErrNoCodecs, got %v", err)
	}
}

// largestPayload returns the largest n for which a session-shaped value holding
// an n-byte string still encodes under the codec's max length.
func largestPayload(t *testing.T, c *securecookie.Codec) int {
	t.Helper()

	encodes := func(n int) bool {
		_, err := c.Encode("session", map[string]any{"v": strings.Repeat("a", n)})
		if err != nil && !errors.Is(err, securecookie.ErrValueTooLong) {
			t.Fatalf("encode %d bytes: %v", n, err)
		}

		return err == nil
	}

	lo, hi := 0, 1
	for encodes(hi) {
		lo = hi
		hi *= 2
		if hi > 1<<20 {
			t.Fatal("payload did not hit the max length")
		}
	}

	// Invariant: encodes(lo) is true, encodes(hi) is false.
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		if encodes(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}

	return lo
}

// TestDefaultMaxLength_UsablePayload checks the approximate reference figures
// documented for this specific session-shaped value and codec configuration.
func TestDefaultMaxLength_UsablePayload(t *testing.T) {
	hashKey := securecookie.GenerateRandomKey(32)
	blockKey := securecookie.GenerateRandomKey(32)

	tests := []struct {
		name     string
		codec    *securecookie.Codec
		measured int
	}{
		{name: "sign-only", codec: securecookie.New(hashKey, nil), measured: 2224},
		{name: "encrypted", codec: securecookie.New(hashKey, blockKey), measured: 2208},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := largestPayload(t, tt.codec)
			t.Logf("largest tested string = %d bytes with a %d-byte encoded-value limit", got, securecookie.DefaultMaxLength)

			// Allow serializer-level changes while keeping the reference useful.
			if got < tt.measured-32 || got > tt.measured+32 {
				t.Fatalf("usable payload = %d, want ~%d (documented figure is stale)", got, tt.measured)
			}

			// The budget really is on the encoded value, not the payload.
			encoded, err := tt.codec.Encode("session", map[string]any{"v": strings.Repeat("a", got)})
			if err != nil {
				t.Fatalf("encode at limit: %v", err)
			}
			if len(encoded) > securecookie.DefaultMaxLength {
				t.Fatalf("encoded %d bytes, above the %d limit", len(encoded), securecookie.DefaultMaxLength)
			}
			// One byte more is rejected on the way out.
			if _, err := tt.codec.Encode("session", map[string]any{"v": strings.Repeat("a", got+1)}); !errors.Is(err, securecookie.ErrValueTooLong) {
				t.Fatalf("encode above limit: want ErrValueTooLong, got %v", err)
			}

			// An oversized value is rejected on the way back in too.
			big := securecookie.New(hashKey, nil, securecookie.WithMaxLength(0))
			oversized, err := big.Encode("session", map[string]any{"v": strings.Repeat("a", got+256)})
			if err != nil {
				t.Fatalf("encode oversized: %v", err)
			}
			out := map[string]any{}
			if err := securecookie.New(hashKey, nil).Decode("session", oversized, &out); !errors.Is(err, securecookie.ErrValueTooLong) {
				t.Fatalf("decode oversized: want ErrValueTooLong, got %v", err)
			}
		})
	}
}

func TestSetMaxLength(t *testing.T) {
	hashKey := securecookie.GenerateRandomKey(32)
	c := securecookie.New(hashKey, nil)

	payload := map[string]any{"v": strings.Repeat("a", 4000)}

	if _, err := c.Encode("session", payload); !errors.Is(err, securecookie.ErrValueTooLong) {
		t.Fatalf("default limit: want ErrValueTooLong, got %v", err)
	}

	c.SetMaxLength(16 * 1024)

	encoded, err := c.Encode("session", payload)
	if err != nil {
		t.Fatalf("encode after SetMaxLength: %v", err)
	}
	if len(encoded) <= securecookie.DefaultMaxLength {
		t.Fatalf("encoded %d bytes, expected to exceed the default limit", len(encoded))
	}

	out := map[string]any{}
	if err := c.Decode("session", encoded, &out); err != nil {
		t.Fatalf("decode after SetMaxLength: %v", err)
	}
	if out["v"] != payload["v"] {
		t.Fatal("round-trip mismatch")
	}

	// 0 disables the check entirely.
	c.SetMaxLength(0)
	if _, err := c.Encode("session", map[string]any{"v": strings.Repeat("a", 1<<16)}); err != nil {
		t.Fatalf("encode with the check disabled: %v", err)
	}

	// Lowering it below the default works as well.
	c.SetMaxLength(64)
	if _, err := c.Encode("session", map[string]any{"v": "short but not that short"}); !errors.Is(err, securecookie.ErrValueTooLong) {
		t.Fatalf("lowered limit: want ErrValueTooLong, got %v", err)
	}

	// Preserve WithMaxLength's established behavior for negative limits.
	negative := securecookie.New(hashKey, nil, securecookie.WithMaxLength(-1))
	if _, err := negative.Encode("session", "value"); !errors.Is(err, securecookie.ErrValueTooLong) {
		t.Fatalf("negative option: want ErrValueTooLong, got %v", err)
	}
	c.SetMaxLength(-1)
	if _, err := c.Encode("session", "value"); !errors.Is(err, securecookie.ErrValueTooLong) {
		t.Fatalf("negative setter: want ErrValueTooLong, got %v", err)
	}
}

func TestGenerateRandomKey(t *testing.T) {
	a := securecookie.GenerateRandomKey(32)
	b := securecookie.GenerateRandomKey(32)

	if len(a) != 32 || len(b) != 32 {
		t.Fatalf("unexpected lengths: %d %d", len(a), len(b))
	}
	if string(a) == string(b) {
		t.Fatal("two random keys should not be equal")
	}
}
