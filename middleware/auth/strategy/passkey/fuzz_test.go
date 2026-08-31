package passkey

import "testing"

func fuzzNoPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("parser panicked: %v", recovered)
		}
	}()
	fn()
}

func FuzzDecodeCBOR(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa1, 0x01, 0x02})
	f.Add([]byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	for major := byte(0); major < 8; major++ {
		f.Add([]byte{major<<5 | 31})
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzNoPanic(t, func() {
			_, _, _ = decodeCBOR(data)
		})
	})
}

func FuzzParseCOSEPublicKey(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa2, 0x01, 0x02, 0x03, 0x26})
	f.Add([]byte{0xa4, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00, 0x20, 0x41, 0x01, 0x21, 0x41, 0x03})
	f.Add([]byte{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzNoPanic(t, func() {
			_, _ = parseCOSEPublicKey(data)
		})
	})
}

func FuzzParseAttestationObject(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e', 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a', 0x40, 0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0})
	f.Add([]byte{0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzNoPanic(t, func() {
			_, _ = parseAttestationObject(data)
		})
	})
}

func FuzzParseAuthenticatorData(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 37))
	attested := make([]byte, 65)
	attested[32] = flagAttestedCredentialData
	attested[54] = 1
	attested[55] = 1
	copy(attested[56:], []byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add(attested)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzNoPanic(t, func() {
			_, _ = parseAuthenticatorData(data)
		})
	})
}
