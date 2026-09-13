package bearer

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/internal/jwt"
)

// verify authenticates the token and applies every claim check.
//
// The order matters only for the quality of the error: signature first, so a
// forged token is never reported as "expired" and a client is never told the
// clock is the problem when the key is.
func (s *Strategy) verify(ctx context.Context, token string) (jwt.Claims, error) {
	raw, err := s.rawClaims(ctx, token)
	if err != nil {
		return nil, err
	}

	claims := jwt.Claims(raw)

	if err := s.checkIssuer(claims); err != nil {
		return nil, err
	}
	if err := s.checkAudience(claims); err != nil {
		return nil, err
	}
	if err := s.checkValidity(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// rawClaims resolves the token to claims via the configured verifier, or by
// verifying its JWS signature against the issuer's key set.
func (s *Strategy) rawClaims(ctx context.Context, token string) (map[string]any, error) {
	if s.verifier != nil {
		claims, err := s.verifier.VerifyToken(ctx, token)
		if err != nil {
			return nil, err
		}
		if claims == nil {
			return nil, ErrMalformedToken
		}

		return claims, nil
	}

	keys, err := s.keySet(ctx)
	if err != nil {
		return nil, err
	}

	header, claims, err := jwt.VerifyWithHeader(ctx, keys, token)
	if err != nil {
		// A signature that does not verify, a key that is not in the set, an
		// algorithm this build refuses — all of them mean the same thing to
		// the caller: this token is not good here. Only a transport failure
		// reaching the JWKS endpoint is ours to own, and that surfaces from
		// keySet above.
		return nil, fmt.Errorf("%w (%v)", ErrMalformedToken, err)
	}

	if s.cfg.RequireAccessTokenType && !strings.EqualFold(header.Typ, "at+jwt") {
		return nil, fmt.Errorf("%w: typ=%q", ErrWrongType, header.Typ)
	}

	return claims, nil
}

// keySet resolves the JWKS, discovering it from the issuer on first use.
func (s *Strategy) keySet(ctx context.Context) (*jwt.KeySet, error) {
	if s.keys != nil {
		return s.keys, nil
	}
	if s.discovery == nil {
		return nil, jwt.ErrNoKeySet
	}

	return s.discovery.keySet(ctx)
}

func (s *Strategy) checkIssuer(claims jwt.Claims) error {
	iss := claims.String("iss")
	if iss == "" {
		return fmt.Errorf("%w: no iss claim", ErrBadIssuer)
	}
	if iss != s.cfg.Issuer {
		// Not echoed into any response — see writeError, which sends a fixed
		// description. Included here for the operator reading logs.
		return fmt.Errorf("%w: got %q", ErrBadIssuer, iss)
	}

	return nil
}

// checkAudience enforces RFC 8707 resource binding.
//
// A token is a bearer credential: whoever holds it can use it. The audience
// claim is the only thing stopping a service that legitimately received a
// token from turning around and spending it here.
func (s *Strategy) checkAudience(claims jwt.Claims) error {
	if s.cfg.DisableAudienceCheck {
		return nil
	}

	audiences := claims.Audience()
	if len(audiences) == 0 {
		return fmt.Errorf("%w: no aud claim", ErrBadAudience)
	}

	for _, want := range s.cfg.Audience {
		if slices.Contains(audiences, want) {
			return nil
		}
	}

	return fmt.Errorf("%w: got %v", ErrBadAudience, audiences)
}

// checkValidity enforces exp and nbf.
//
// exp is required. A token with no expiry is a password that never rotates,
// and accepting one silently converts a short-lived credential model into a
// permanent one the first time an issuer is misconfigured.
func (s *Strategy) checkValidity(claims jwt.Claims) error {
	now := s.now()

	exp, ok := claims.Time("exp")
	if !ok {
		return ErrNoExpiry
	}
	if !now.Add(-s.skew).Before(exp) {
		return fmt.Errorf("%w at %s", ErrExpired, exp.UTC().Format(time.RFC3339))
	}

	if nbf, ok := claims.Time("nbf"); ok {
		if now.Add(s.skew).Before(nbf) {
			return fmt.Errorf("%w until %s", ErrNotYetValid, nbf.UTC().Format(time.RFC3339))
		}
	}

	return nil
}

// buildIdentity maps verified claims onto the normalized identity.
func (s *Strategy) buildIdentity(claims jwt.Claims) (*identity.Identity, error) {
	mapping := s.cfg.Claims

	subject := claims.StringAt(mapping.subject())
	if subject == "" {
		return nil, ErrNoSubject
	}

	id := &identity.Identity{
		Subject:  subject,
		Email:    claims.StringAt(mapping.email()),
		Scopes:   claims.Scopes(),
		Claims:   map[string]any(claims),
		Provider: s.name,
	}

	for _, path := range mapping.names() {
		if name := claims.StringAt(path); name != "" {
			id.Name = name

			break
		}
	}

	if verified, ok := claims.Bool(mapping.emailVerified()); ok {
		id.EmailVerified = verified
	}

	for _, path := range mapping.roles() {
		for _, role := range claims.StringsAt(path) {
			if !slices.Contains(id.Roles, role) {
				id.Roles = append(id.Roles, role)
			}
		}
	}

	if issued, ok := claims.Time("iat"); ok {
		id.IssuedAt = issued
	}
	if expires, ok := claims.Time("exp"); ok {
		id.ExpiresAt = expires
	}

	return id, nil
}
