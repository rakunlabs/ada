package oauth2

import (
	"context"
	"net/http"

	"github.com/rakunlabs/ada/middleware/auth/internal/jwt"
)

// The JWS verifier lives in internal/jwt so the bearer strategy — which
// validates inbound access tokens rather than id_tokens received at login —
// shares one implementation with this one. Two copies of a signature
// verifier is how one of them quietly stops rejecting `alg: none`.
//
// The names below are kept so the rest of this package, and its tests, read
// as before.

// keySet caches an IdP's JSON Web Key Set.
type keySet = jwt.KeySet

// Errors returned while verifying an ID token.
var (
	ErrNoKeySet       = jwt.ErrNoKeySet
	ErrUnknownKey     = jwt.ErrUnknownKey
	ErrMissingKeyID   = jwt.ErrMissingKeyID
	ErrBadSignature   = jwt.ErrBadSignature
	ErrUnsupportedAlg = jwt.ErrUnsupportedAlg
)

func newKeySet(uri string, client *http.Client) *keySet {
	return jwt.NewKeySet(uri, client, maxUpstreamResponseBytes)
}

// verifyJWT checks a compact JWS against the key set and returns its claims.
func verifyJWT(ctx context.Context, ks *keySet, token string) (map[string]any, error) {
	return jwt.Verify(ctx, ks, token)
}
