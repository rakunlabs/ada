package securecookie

import "errors"

var (
	// ErrHashKeyRequired is returned when New is called without a hash key.
	ErrHashKeyRequired = errors.New("securecookie: hash key is required")

	// ErrInvalidBlockKeySize is returned when the block key length is not a
	// valid AES key size (16, 24 or 32 bytes).
	ErrInvalidBlockKeySize = errors.New("securecookie: block key must be 16, 24 or 32 bytes")

	// ErrNoCodecs is returned when a Codecs slice is empty.
	ErrNoCodecs = errors.New("securecookie: no codecs configured")

	// ErrMACInvalid is returned when the message authentication code does not
	// match, meaning the value was tampered with or signed with another key.
	ErrMACInvalid = errors.New("securecookie: the value MAC is invalid")

	// ErrTimestampExpired is returned when the value is older than the
	// configured max age.
	ErrTimestampExpired = errors.New("securecookie: expired timestamp")

	// ErrTimestampTooNew is returned when the value timestamp is newer than the
	// configured min age (clock skew or replay).
	ErrTimestampTooNew = errors.New("securecookie: timestamp is too new")

	// ErrValueTooLong is returned when the encoded value exceeds the configured
	// max length.
	ErrValueTooLong = errors.New("securecookie: the value is too long")

	// ErrDecode is returned when the encoded value cannot be parsed.
	ErrDecode = errors.New("securecookie: error decoding value")
)
