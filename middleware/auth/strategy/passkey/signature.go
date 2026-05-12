package passkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

// verifySignature checks an authenticator-provided signature against
// the stored credential public key. The signed message is the
// authenticatorData blob concatenated with the SHA-256 hash of the
// clientDataJSON — see WebAuthn §7.2 step 17 for the construction.
//
// Returns nil on success, a wrapped error on any failure. We
// deliberately do not distinguish "wrong signature" from "wrong key
// type" in the returned error message; the caller treats every
// signature failure as "passkey verification failed" so the client
// never learns which check tripped.
func verifySignature(pk *publicKey, signedMessage, signature []byte) error {
	// Ed25519 (PureEdDSA, RFC 8032) signs the raw message — there is
	// no separate hashForAlgorithm step. Branch early so we don't
	// even build a digest the verifier won't use.
	if pk.Ed25519 != nil {
		return verifyEd25519(pk.Ed25519, signedMessage, signature)
	}

	h, hashed, err := hashForAlgorithm(pk.Algorithm, signedMessage)
	if err != nil {
		return err
	}

	switch {
	case pk.EC2 != nil:
		return verifyECDSA(pk.EC2, hashed, signature)
	case pk.RSA != nil:
		return verifyRSA(pk.RSA, pk.Algorithm, h, hashed, signature)
	}
	return errors.New("signature: no key material on parsed public key")
}

// hashForAlgorithm picks the digest the COSE algorithm requires and
// returns both the crypto.Hash enum (for RSA-PSS) and the digest of
// the message. We accept the SHA-2 family — SHA-1 is rejected even
// though RS1 (-65535) technically exists, because no modern
// authenticator emits it and accepting it would be a downgrade
// vector.
func hashForAlgorithm(alg int, msg []byte) (crypto.Hash, []byte, error) {
	var h hash.Hash
	var chash crypto.Hash
	switch alg {
	case algES256, algRS256, algPS256:
		s := sha256.Sum256(msg)
		return crypto.SHA256, s[:], nil
	case algES384, algRS384, algPS384:
		h = sha512.New384()
		chash = crypto.SHA384
	case algES512, algRS512, algPS512:
		h = sha512.New()
		chash = crypto.SHA512
	default:
		return 0, nil, fmt.Errorf("signature: unsupported alg %s", algorithmName(alg))
	}
	h.Write(msg)
	return chash, h.Sum(nil), nil
}

// verifyECDSA checks an ECDSA signature in DER form. We require
// strict DER (no trailing bytes, no negative or zero components) to
// prevent signature malleability — see parseECDSASignature.
func verifyECDSA(key *ecdsa.PublicKey, hashed, sig []byte) error {
	r, s, err := parseECDSASignature(sig)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if !ecdsa.Verify(key, hashed, r, s) {
		return errors.New("signature: ecdsa verify failed")
	}
	return nil
}

// verifyEd25519 checks an Ed25519 signature using the stdlib
// implementation. Per RFC 8032 the wire signature is exactly 64
// bytes; rejecting any other length up front gives a clearer error
// than the generic ed25519.Verify "signature is invalid" path.
func verifyEd25519(key ed25519.PublicKey, signedMessage, sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature: ed25519 length %d (want %d)", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(key, signedMessage, sig) {
		return errors.New("signature: ed25519 verify failed")
	}
	return nil
}

// verifyRSA dispatches between PKCS#1v1.5 and PSS depending on the
// algorithm identifier. WebAuthn allows both; the COSE alg field is
// the authoritative signal.
func verifyRSA(key *rsa.PublicKey, alg int, h crypto.Hash, hashed, sig []byte) error {
	switch alg {
	case algRS256, algRS384, algRS512:
		if err := rsa.VerifyPKCS1v15(key, h, hashed, sig); err != nil {
			return fmt.Errorf("signature: rsa pkcs1v15: %w", err)
		}
		return nil
	case algPS256, algPS384, algPS512:
		// PSS salt length matches digest length per RFC 8017 §9.1
		// and WebAuthn implementations. SaltLengthAuto would also
		// work but is less predictable.
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
		if err := rsa.VerifyPSS(key, h, hashed, sig, opts); err != nil {
			return fmt.Errorf("signature: rsa-pss: %w", err)
		}
		return nil
	}
	return fmt.Errorf("signature: unsupported rsa alg %s", algorithmName(alg))
}
