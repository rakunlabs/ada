package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Header is the protected header of a compact JWS.
type Header struct {
	Alg  string          `json:"alg"`
	Kid  string          `json:"kid"`
	Typ  string          `json:"typ"`
	Crit json.RawMessage `json:"crit"`
}

// Verify checks a compact JWS against the key set and returns its claims.
//
// It verifies the signature and nothing else. A token that comes back from
// this function is authentic; whether it was meant for you is a separate
// question, answered by the claim checks in claims.go.
func Verify(ctx context.Context, ks *KeySet, token string) (map[string]any, error) {
	_, claims, err := VerifyWithHeader(ctx, ks, token)

	return claims, err
}

// VerifyWithHeader is Verify, also returning the protected header. Callers
// that pin `typ` (RFC 9068 requires `at+jwt` for access tokens) need it.
func VerifyWithHeader(ctx context.Context, ks *KeySet, token string) (Header, map[string]any, error) {
	var hdr Header

	if ks == nil {
		return hdr, nil, ErrNoKeySet
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return hdr, nil, errors.New("jwt: token is not a compact JWS")
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return hdr, nil, fmt.Errorf("jwt: decode jws header: %w", err)
	}

	if err := json.Unmarshal(headerRaw, &hdr); err != nil {
		return hdr, nil, fmt.Errorf("jwt: decode jws header: %w", err)
	}
	// OIDC forbids crit; this verifier implements no critical extensions.
	// RawMessage also detects prohibited null, empty and malformed values.
	if hdr.Crit != nil {
		return hdr, nil, errors.New("jwt: jws crit header is not supported")
	}

	// "none" is a signature algorithm only in the sense that a blank cheque is
	// a payment method.
	if hdr.Alg == "" || strings.EqualFold(hdr.Alg, "none") {
		return hdr, nil, fmt.Errorf("%w: %q", ErrUnsupportedAlg, hdr.Alg)
	}

	key, err := ks.Key(ctx, hdr.Kid)
	if err != nil {
		return hdr, nil, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return hdr, nil, fmt.Errorf("jwt: decode signature: %w", err)
	}

	signed := []byte(parts[0] + "." + parts[1])

	if err := VerifySignature(hdr.Alg, key, signed, sig); err != nil {
		return hdr, nil, err
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return hdr, nil, fmt.Errorf("jwt: decode payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return hdr, nil, fmt.Errorf("jwt: decode payload json: %w", err)
	}

	return hdr, claims, nil
}

// VerifySignature checks a JWS signature for alg against key.
func VerifySignature(alg string, key crypto.PublicKey, signed, sig []byte) error {
	hashed, hash, err := digest(alg, signed)
	if err != nil {
		return err
	}

	switch {
	case strings.HasPrefix(alg, "RS"):
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: %s needs an RSA key", ErrUnsupportedAlg, alg)
		}

		if err := rsa.VerifyPKCS1v15(pub, hash, hashed, sig); err != nil {
			return ErrBadSignature
		}

		return nil

	case strings.HasPrefix(alg, "PS"):
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: %s needs an RSA key", ErrUnsupportedAlg, alg)
		}

		// RFC 7518 §3.5 pins the salt length to the hash length.
		opts := &rsa.PSSOptions{SaltLength: hash.Size(), Hash: hash}
		if err := rsa.VerifyPSS(pub, hash, hashed, sig, opts); err != nil {
			return ErrBadSignature
		}

		return nil

	case strings.HasPrefix(alg, "ES"):
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: %s needs an EC key", ErrUnsupportedAlg, alg)
		}

		// JWS uses the fixed-width R||S encoding, not DER.
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return ErrBadSignature
		}

		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])

		if !ecdsa.Verify(pub, hashed, r, s) {
			return ErrBadSignature
		}

		return nil

	case alg == "EdDSA":
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: EdDSA needs an Ed25519 key", ErrUnsupportedAlg)
		}

		if !ed25519.Verify(pub, signed, sig) {
			return ErrBadSignature
		}

		return nil
	}

	return fmt.Errorf("%w: %q", ErrUnsupportedAlg, alg)
}

// digest returns the message digest for alg. EdDSA hashes internally, so it
// gets the message unchanged.
func digest(alg string, signed []byte) ([]byte, crypto.Hash, error) {
	switch alg {
	case "EdDSA":
		return signed, 0, nil
	case "RS256", "PS256", "ES256":
		sum := sha256.Sum256(signed)

		return sum[:], crypto.SHA256, nil
	case "RS384", "PS384", "ES384":
		sum := sha512.Sum384(signed)

		return sum[:], crypto.SHA384, nil
	case "RS512", "PS512", "ES512":
		sum := sha512.Sum512(signed)

		return sum[:], crypto.SHA512, nil
	}

	return nil, 0, fmt.Errorf("%w: %q", ErrUnsupportedAlg, alg)
}
