package sessions

import (
	"net/http"

	"github.com/rakunlabs/ada/utils/securecookie"
)

// CookieStore stores the entire session, including its values, in the cookie
// itself. The payload is signed and (when a block key is supplied) encrypted by
// securecookie, so it cannot be read or tampered with by the client.
//
// Because everything lives in the cookie, total size is limited. By default,
// the codecs cap the encoded cookie value at securecookie.DefaultMaxLength.
// That limit excludes the cookie name and attributes, so it does not guarantee
// that the complete cookie fits every user agent's limit.
//
// Serialization, signing, encryption, and base64 encoding add variable
// overhead. In the reference configuration documented by DefaultMaxLength, a
// session-shaped value containing one string reached the limit at about 2.2 KB,
// but applications must measure their own value shapes and codec configuration.
// Save and load return securecookie.ErrValueTooLong when the encoded value is
// over the configured limit.
//
// Use MaxLength to change that budget, or a server-side store for large
// payloads.
type CookieStore struct {
	// Codecs sign and encrypt the cookie payload. The first codec is used for
	// encoding; all are tried when decoding, which enables key rotation.
	Codecs securecookie.Codecs

	// Options is the template applied to every session created by this store.
	Options *Options
}

// NewCookieStore returns a CookieStore using the given key pairs. Each pair is
// (hashKey, blockKey): the hash key authenticates the cookie (use 32 or 64
// random bytes) and the optional block key encrypts it (16, 24 or 32 bytes).
//
//	store := sessions.NewCookieStore(
//		securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32),
//	)
//
// Pass several pairs to rotate keys: the first pair signs new cookies, the rest
// are accepted when decoding old ones.
func NewCookieStore(keyPairs ...[]byte) *CookieStore {
	store := &CookieStore{
		Codecs: securecookie.CodecsFromPairs(nil, keyPairs...),
		Options: &Options{
			Path:     "/",
			MaxAge:   securecookie.DefaultMaxAge,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
	}

	store.MaxAge(store.Options.MaxAge)

	return store
}

// MaxAge sets the max age for both the session cookie and the underlying codecs
// so the cookie's lifetime and the signature's validity window stay in sync.
// Call it at setup time.
func (s *CookieStore) MaxAge(age int) {
	s.Options.MaxAge = age

	for _, c := range s.Codecs {
		c.SetMaxAge(age)
	}
}

// MaxLength sets the maximum length in bytes of the encoded cookie value on
// every codec, for both saving and loading. Zero disables the check; a negative
// value rejects all encoded values. Call it during setup, before the store's
// codecs are used concurrently.
//
// The default is securecookie.DefaultMaxLength. Raising it can produce cookies
// that user agents refuse to store; it is useful only when the client and
// intermediaries are known to permit the resulting complete cookie size.
func (s *CookieStore) MaxLength(n int) {
	for _, c := range s.Codecs {
		c.SetMaxLength(n)
	}
}

// Get returns the session for name, reusing a request-cached instance when a
// registry is installed (see Middleware).
func (s *CookieStore) Get(r *http.Request, name string) (*Session, error) {
	if reg := GetRegistry(r); reg != nil {
		if sess, err, ok := reg.get(s, name); ok {
			return sess, err
		}
	}

	sess, err := s.New(r, name)

	if reg := GetRegistry(r); reg != nil {
		reg.set(s, name, sess, err)
	}

	return sess, err
}

// New loads the session from the request cookie. If the cookie is missing or
// cannot be decoded, it returns a fresh empty session (with IsNew=true); a
// decode failure is also returned as the error.
func (s *CookieStore) New(r *http.Request, name string) (*Session, error) {
	sess := NewSession(s, name)
	sess.Options = s.Options.clone()

	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return sess, nil
	}

	if err := s.Codecs.Decode(name, cookie.Value, &sess.Values); err != nil {
		return sess, err
	}

	sess.IsNew = false

	return sess, nil
}

// Save encodes the session values into the response cookie. If Options.MaxAge is
// negative the cookie is deleted instead.
func (s *CookieStore) Save(r *http.Request, w http.ResponseWriter, sess *Session) error {
	if sess.Options.MaxAge < 0 {
		http.SetCookie(w, newCookie(sess.name, "", sess.Options))

		return nil
	}

	encoded, err := s.Codecs.Encode(sess.name, sess.Values)
	if err != nil {
		return err
	}

	http.SetCookie(w, newCookie(sess.name, encoded, sess.Options))

	return nil
}
