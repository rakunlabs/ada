package securecookie

import "crypto/rand"

// GenerateRandomKey returns a cryptographically secure random key of the given
// length in bytes. Common lengths are 32 or 64 for hash keys and 16, 24 or 32
// for block (AES) keys. It panics if the system random source fails, which
// should never happen in practice.
func GenerateRandomKey(length int) []byte {
	k := make([]byte, length)
	if _, err := rand.Read(k); err != nil {
		panic("securecookie: failed to read random key: " + err.Error())
	}

	return k
}
