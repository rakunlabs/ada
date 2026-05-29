package securecookie_test

import (
	"errors"
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
