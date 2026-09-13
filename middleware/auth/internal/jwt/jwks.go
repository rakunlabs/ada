// Package jwt verifies compact JWS tokens against a remote JSON Web Key Set.
//
// It exists because two very different callers need exactly the same
// primitive: the OAuth2 strategy verifying an id_token it just received from
// an IdP, and the bearer strategy verifying an access token a client
// presented on a protected route. Duplicating a signature verifier is how
// one copy quietly stops rejecting `alg: none`.
//
// The package is internal on purpose. It is a building block with sharp
// edges — it verifies signatures and nothing else. Claim policy (issuer,
// audience, expiry) belongs to the caller, which is the only party that
// knows what the token was supposed to be for.
package jwt

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/internal/bodylimit"
)

// DefaultMaxJWKSBytes caps a JWKS response. A key set is a handful of
// kilobytes; anything larger is either a misconfiguration or an attempt to
// make the verifier allocate on command.
const DefaultMaxJWKSBytes int64 = 1 << 20

// Errors returned while resolving a key or verifying a signature.
var (
	ErrNoKeySet       = errors.New("jwt: no JWKS endpoint configured")
	ErrUnknownKey     = errors.New("jwt: signing key not found in JWKS")
	ErrMissingKeyID   = errors.New("jwt: token has no kid and JWKS contains multiple keys")
	ErrBadSignature   = errors.New("jwt: signature invalid")
	ErrUnsupportedAlg = errors.New("jwt: unsupported algorithm")
)

// KeySet caches an issuer's JSON Web Key Set.
//
// Keys rotate, so an unknown `kid` triggers a refetch — throttled, because an
// attacker who can present arbitrary unsigned tokens would otherwise turn the
// verifier into a request amplifier pointed at the issuer.
type KeySet struct {
	// MinRefresh is the cooldown after a successful fetch. Set before first
	// use; changing it afterwards races with in-flight lookups.
	MinRefresh time.Duration
	// RetryRefresh is the (shorter) cooldown after a failed fetch, so a
	// transient outage does not lock the verifier out for a full MinRefresh.
	RetryRefresh time.Duration
	// Now overrides the clock. Set before first use.
	Now func() time.Time

	uri      string
	client   *http.Client
	maxBytes int64

	mu         sync.RWMutex
	keys       map[string]crypto.PublicKey
	usableKeys int

	refreshMu   sync.Mutex
	refreshing  *refreshCall
	lastFetched time.Time
	lastAttempt time.Time
}

type refreshCall struct {
	done chan struct{}
	err  error
}

// NewKeySet returns a key set that fetches uri with client.
//
// maxBytes caps the JWKS response; pass 0 for DefaultMaxJWKSBytes.
func NewKeySet(uri string, client *http.Client, maxBytes int64) *KeySet {
	if client == nil {
		client = http.DefaultClient
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxJWKSBytes
	}

	return &KeySet{
		MinRefresh:   time.Minute,
		RetryRefresh: 2 * time.Second,
		Now:          time.Now,
		uri:          uri,
		client:       client,
		maxBytes:     maxBytes,
		keys:         make(map[string]crypto.PublicKey),
	}
}

// SetKeys replaces the cached keys.
//
// Use it to pre-seed a set from keys obtained out of band, or to pin a static
// key in a deployment with no JWKS endpoint. It does not affect the refresh
// cooldown: a later lookup for an unknown kid will still try the endpoint.
func (k *KeySet) SetKeys(keys map[string]crypto.PublicKey) {
	replacement := make(map[string]crypto.PublicKey, len(keys))
	for kid, key := range keys {
		replacement[kid] = key
	}

	k.mu.Lock()
	k.keys = replacement
	k.usableKeys = len(replacement)
	k.mu.Unlock()
}

// Key returns the public key for kid, fetching the JWKS if needed.
//
// An empty kid is allowed only when the set holds exactly one key: picking one
// of several at random would let a token signed by the weakest key stand in
// for any other.
func (k *KeySet) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	if kid == "" && k.keyCount() > 1 {
		return nil, ErrMissingKeyID
	}

	if key, ok := k.lookup(kid); ok {
		return key, nil
	}

	if err := k.Refresh(ctx); err != nil {
		return nil, err
	}

	if kid == "" && k.keyCount() > 1 {
		return nil, ErrMissingKeyID
	}
	if key, ok := k.lookup(kid); ok {
		return key, nil
	}

	return nil, fmt.Errorf("%w: kid=%q", ErrUnknownKey, kid)
}

func (k *KeySet) keyCount() int {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.usableKeys > 0 {
		return k.usableKeys
	}

	return len(k.keys)
}

func (k *KeySet) lookup(kid string) (crypto.PublicKey, bool) {
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

// Refresh refetches the key set, collapsing concurrent callers onto one
// request and refusing to run more often than the configured cooldown.
func (k *KeySet) Refresh(ctx context.Context) error {
	k.refreshMu.Lock()
	if call := k.refreshing; call != nil {
		k.refreshMu.Unlock()

		select {
		case <-call.done:
			return call.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	now := k.now()
	last, cooldown := k.lastFetched, k.MinRefresh
	if k.lastAttempt.After(k.lastFetched) {
		last, cooldown = k.lastAttempt, k.RetryRefresh
	}
	if !last.IsZero() && now.Sub(last) < cooldown {
		k.refreshMu.Unlock()

		return fmt.Errorf("%w: refresh throttled", ErrUnknownKey)
	}

	call := &refreshCall{done: make(chan struct{})}
	k.refreshing = call
	k.refreshMu.Unlock()

	keys, usableKeys, err := k.fetch(ctx)
	completed := k.now()
	if err == nil {
		k.mu.Lock()
		k.keys = keys
		k.usableKeys = usableKeys
		k.mu.Unlock()
	}

	k.refreshMu.Lock()
	if err != nil {
		k.lastAttempt = completed
	} else {
		k.lastFetched = completed
		k.lastAttempt = time.Time{}
	}
	call.err = err
	k.refreshing = nil
	close(call.done)
	k.refreshMu.Unlock()

	return err
}

func (k *KeySet) now() time.Time {
	if k.Now != nil {
		return k.Now()
	}

	return time.Now()
}

func (k *KeySet) fetch(ctx context.Context) (map[string]crypto.PublicKey, int, error) {
	if k.uri == "" {
		return nil, 0, ErrNoKeySet
	}

	if _, hasDeadline := ctx.Deadline(); !hasDeadline && k.client.Timeout <= 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.uri, nil)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("jwt: fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := bodylimit.ReadUpstream(resp.Body, k.maxBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("jwt: read jwks: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("jwt: jwks: %s", strings.TrimSpace(string(body)))
	}

	keys, usableKeys, err := ParseJWKS(body)
	if err != nil {
		return nil, 0, err
	}

	if len(keys) == 0 {
		return nil, 0, errors.New("jwt: jwks contains no usable key")
	}

	return keys, usableKeys, nil
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

// ParseJWKS decodes a JWKS document into public keys addressed by kid. Keys
// this package cannot verify with are skipped rather than failing the whole
// set: an issuer publishing one exotic key should not disable the others.
func ParseJWKS(body []byte) (map[string]crypto.PublicKey, int, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}

	if err := json.Unmarshal(body, &set); err != nil {
		return nil, 0, fmt.Errorf("jwt: decode jwks: %w", err)
	}

	out := make(map[string]crypto.PublicKey, len(set.Keys))
	usable := 0

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
		usable++
	}

	return out, usable, nil
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
			return nil, errors.New("jwt: rsa modulus below 2048 bits")
		}

		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 || e.Int64()%2 == 0 {
			return nil, errors.New("jwt: implausible rsa exponent")
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
			return nil, fmt.Errorf("jwt: unsupported curve %q", k.Crv)
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
			return nil, errors.New("jwt: ec coordinate too large for curve")
		}

		uncompressed := make([]byte, 1+2*size)
		uncompressed[0] = 4
		x.FillBytes(uncompressed[1 : 1+size])
		y.FillBytes(uncompressed[1+size:])

		if _, err := ecdhCurve.NewPublicKey(uncompressed); err != nil {
			return nil, fmt.Errorf("jwt: invalid ec point: %w", err)
		}

		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil

	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("jwt: unsupported OKP curve %q", k.Crv)
		}

		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}

		if len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("jwt: bad ed25519 key size")
		}

		return ed25519.PublicKey(raw), nil
	}

	return nil, fmt.Errorf("jwt: unsupported key type %q", k.Kty)
}

func b64uint(s string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("jwt: decode jwk field: %w", err)
	}

	return new(big.Int).SetBytes(raw), nil
}
