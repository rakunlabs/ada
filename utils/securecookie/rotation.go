package securecookie

import "errors"

// Codecs is an ordered set of codecs used for key rotation. Encoding always
// uses the first codec; decoding tries each codec in turn until one succeeds.
//
// To rotate keys, prepend a Codec built from the new key pair and keep the old
// ones around long enough for existing cookies to expire, then drop them.
type Codecs []*Codec

// Encode encodes value with the first codec.
func (cs Codecs) Encode(name string, value any) (string, error) {
	if len(cs) == 0 {
		return "", ErrNoCodecs
	}

	return cs[0].Encode(name, value)
}

// Decode tries each codec in order and returns the first successful result. If
// all fail, it returns the last error (joined for inspection with errors.Is).
func (cs Codecs) Decode(name, encoded string, dst any) error {
	if len(cs) == 0 {
		return ErrNoCodecs
	}

	var errs []error
	for _, c := range cs {
		err := c.Decode(name, encoded, dst)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// CodecsFromPairs returns a Codecs built from a sequence of key pairs. Each pair
// is (hashKey, blockKey); pass a nil or empty blockKey to disable encryption for
// that pair. The shared opts are applied to every codec.
//
//	codecs := securecookie.CodecsFromPairs(nil,
//		newHashKey, newBlockKey,
//		oldHashKey, oldBlockKey,
//	)
func CodecsFromPairs(opts []Option, keyPairs ...[]byte) Codecs {
	cs := make(Codecs, 0, (len(keyPairs)+1)/2)

	for i := 0; i < len(keyPairs); i += 2 {
		var blockKey []byte
		if i+1 < len(keyPairs) {
			blockKey = keyPairs[i+1]
		}

		cs = append(cs, New(keyPairs[i], blockKey, opts...))
	}

	return cs
}
