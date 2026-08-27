package oauth2

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Errors returned while verifying an ID token.
var (
	ErrNoKeySet       = errors.New("oauth2: no JWKS endpoint configured")
	ErrUnknownKey     = errors.New("oauth2: signing key not found in JWKS")
	ErrBadSignature   = errors.New("oauth2: id_token signature invalid")
	ErrUnsupportedAlg = errors.New("oauth2: unsupported id_token algorithm")
)

// keySet caches an IdP's JSON Web Key Set.
//
// Keys rotate, so an unknown `kid` triggers a refetch — throttled, because an
// attacker who can present arbitrary unsigned tokens would otherwise turn the
// verifier into a request amplifier pointed at the IdP.
type keySet struct {
	uri    string
	client *http.Client

	minRefresh time.Duration

	mu          sync.RWMutex
	keys        map[string]crypto.PublicKey
	lastFetched time.Time
}

func newKeySet(uri string, client *http.Client) *keySet {
	return &keySet{
		uri:        uri,
		client:     client,
		minRefresh: time.Minute,
		keys:       make(map[string]crypto.PublicKey),
	}
}

// key returns the public key for kid, fetching the JWKS if needed.
//
// An empty kid is allowed only when the set holds exactly one key: picking one
// of several at random would let a token signed by the weakest key stand in
// for any other.
func (k *keySet) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	if key, ok := k.lookup(kid); ok {
		return key, nil
	}

	if err := k.refresh(ctx); err != nil {
		return nil, err
	}

	if key, ok := k.lookup(kid); ok {
		return key, nil
	}

	return nil, fmt.Errorf("%w: kid=%q", ErrUnknownKey, kid)
}

func (k *keySet) lookup(kid string) (crypto.PublicKey, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if kid != "" {
		key, ok := k.keys[kid]

		return key, ok
	}

	if len(k.keys) != 1 {
		return nil, false
	}

	for _, key := range k.keys {
		return key, true
	}

	return nil, false
}

func (k *keySet) refresh(ctx context.Context) error {
	k.mu.Lock()
	if time.Since(k.lastFetched) < k.minRefresh {
		k.mu.Unlock()

		return fmt.Errorf("%w: refresh throttled", ErrUnknownKey)
	}

	k.lastFetched = time.Now()
	k.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.uri, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("oauth2: fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("oauth2: read jwks: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("oauth2: jwks: %s", strings.TrimSpace(string(body)))
	}

	keys, err := parseJWKS(body)
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		return errors.New("oauth2: jwks contains no usable key")
	}

	k.mu.Lock()
	k.keys = keys
	k.mu.Unlock()

	return nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func parseJWKS(body []byte) (map[string]crypto.PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}

	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("oauth2: decode jwks: %w", err)
	}

	out := make(map[string]crypto.PublicKey, len(set.Keys))

	for _, k := range set.Keys {
		// "enc" keys are for encryption, not signatures. Using one to verify
		// would be a category error even if the maths happened to work.
		if k.Use != "" && k.Use != "sig" {
			continue
		}

		key, err := k.publicKey()
		if err != nil {
			continue
		}

		out[k.Kid] = key
	}

	return out, nil
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64uint(k.N)
		if err != nil {
			return nil, err
		}

		e, err := b64uint(k.E)
		if err != nil {
			return nil, err
		}

		if n.BitLen() < 2048 {
			return nil, errors.New("oauth2: rsa modulus below 2048 bits")
		}

		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 || e.Int64()%2 == 0 {
			return nil, errors.New("oauth2: implausible rsa exponent")
		}

		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil

	case "EC":
		var (
			curve     elliptic.Curve
			ecdhCurve ecdh.Curve
		)

		switch k.Crv {
		case "P-256":
			curve, ecdhCurve = elliptic.P256(), ecdh.P256()
		case "P-384":
			curve, ecdhCurve = elliptic.P384(), ecdh.P384()
		case "P-521":
			curve, ecdhCurve = elliptic.P521(), ecdh.P521()
		default:
			return nil, fmt.Errorf("oauth2: unsupported curve %q", k.Crv)
		}

		x, err := b64uint(k.X)
		if err != nil {
			return nil, err
		}

		y, err := b64uint(k.Y)
		if err != nil {
			return nil, err
		}

		// Point validation via crypto/ecdh rather than the deprecated
		// elliptic.IsOnCurve. An off-curve point is not a formatting quibble:
		// signature verification against one can leak the private key of a
		// peer that reuses it.
		size := (curve.Params().BitSize + 7) / 8

		if len(x.Bytes()) > size || len(y.Bytes()) > size {
			return nil, errors.New("oauth2: ec coordinate too large for curve")
		}

		uncompressed := make([]byte, 1+2*size)
		uncompressed[0] = 4
		x.FillBytes(uncompressed[1 : 1+size])
		y.FillBytes(uncompressed[1+size:])

		if _, err := ecdhCurve.NewPublicKey(uncompressed); err != nil {
			return nil, fmt.Errorf("oauth2: invalid ec point: %w", err)
		}

		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil

	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("oauth2: unsupported OKP curve %q", k.Crv)
		}

		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}

		if len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("oauth2: bad ed25519 key size")
		}

		return ed25519.PublicKey(raw), nil
	}

	return nil, fmt.Errorf("oauth2: unsupported key type %q", k.Kty)
}

func b64uint(s string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("oauth2: decode jwk field: %w", err)
	}

	return new(big.Int).SetBytes(raw), nil
}

// jwtHeader is the protected header of a compact JWS.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// verifyJWT checks a compact JWS against the key set and returns its claims.
func verifyJWT(ctx context.Context, ks *keySet, token string) (map[string]any, error) {
	if ks == nil {
		return nil, ErrNoKeySet
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("oauth2: id_token is not a compact JWS")
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oauth2: decode jws header: %w", err)
	}

	var hdr jwtHeader
	if err := json.Unmarshal(headerRaw, &hdr); err != nil {
		return nil, fmt.Errorf("oauth2: decode jws header: %w", err)
	}

	// "none" is a signature algorithm only in the sense that a blank cheque is
	// a payment method.
	if hdr.Alg == "" || strings.EqualFold(hdr.Alg, "none") {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlg, hdr.Alg)
	}

	key, err := ks.key(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oauth2: decode signature: %w", err)
	}

	signed := []byte(parts[0] + "." + parts[1])

	if err := verifySignature(hdr.Alg, key, signed, sig); err != nil {
		return nil, err
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oauth2: decode payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("oauth2: decode payload json: %w", err)
	}

	return claims, nil
}

func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) error {
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
