package oauthserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/resource"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

// ErrInvalidToken is returned by Validate for an unknown, expired or
// revoked token. It wraps strategy.ErrInvalidCredentials so Auth.Require
// answers 401.
var ErrInvalidToken = fmt.Errorf("oauthserver: invalid token: %w", strategy.ErrInvalidCredentials)

// Identity.Claims keys under which a validated token is described. Read them
// back with Info.
const (
	ClaimTokenID  = "oauth_token_id"
	ClaimClientID = "oauth_client_id"
	ClaimResource = "oauth_resource"
	ClaimExtra    = "oauth_extra"
)

// TokenInfo describes the token a request was authenticated with.
type TokenInfo struct {
	ID       string
	ClientID string
	Resource string
	Scopes   []string
	Extra    map[string]any
}

// Info returns the token behind an identity, or nil when the identity was
// authenticated some other way (a session cookie, an API key). Use it in
// handlers to read what Hooks.Authorize attached:
//
//	if info := oauthserver.Info(identity.FromContext(ctx)); info != nil {
//		conn, _ := info.Extra["connection"].(string)
//	}
func Info(id *identity.Identity) *TokenInfo {
	if id == nil {
		return nil
	}

	tokenID, ok := id.Claims[ClaimTokenID].(string)
	if !ok || tokenID == "" {
		return nil
	}

	info := &TokenInfo{ID: tokenID, Scopes: slices.Clone(id.Scopes)}
	info.ClientID, _ = id.Claims[ClaimClientID].(string)
	info.Resource, _ = id.Claims[ClaimResource].(string)
	info.Extra, _ = id.Claims[ClaimExtra].(map[string]any)

	return info
}

// Validate resolves an access token presented by a client.
//
// Only tokens with this server's access prefix are looked up; anything else
// returns strategy.ErrNoCredentials so another strategy (an API key, a JWT
// bearer) can have it.
func (s *Server) Validate(ctx context.Context, raw string) (*Token, *identity.Identity, error) {
	if !strings.HasPrefix(raw, s.cfg.AccessTokenPrefix) {
		return nil, nil, strategy.ErrNoCredentials
	}

	t, err := s.store.TokenByAccess(ctx, HashSecret(raw))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil, ErrInvalidToken
		}

		return nil, nil, fmt.Errorf("oauthserver: load token: %w", err)
	}

	if !t.AccessExpiresAt.IsZero() && s.now().After(t.AccessExpiresAt) {
		return nil, nil, ErrInvalidToken
	}

	id := t.Identity
	if s.cfg.Hooks.Identity != nil {
		id, err = s.cfg.Hooks.Identity(ctx, t)
		switch {
		case errors.Is(err, ErrAccessDenied):
			return nil, nil, ErrInvalidToken
		case err != nil:
			return nil, nil, fmt.Errorf("oauthserver: identity hook: %w", err)
		}
	}

	if id == nil {
		return nil, nil, ErrInvalidToken
	}

	return t, tokenIdentity(t, id, s.cfg.StrategyName), nil
}

// tokenIdentity is the identity a request authenticated by t acts as: the
// user's, with the token's scopes in place of whatever the session had. A
// token approved for "read" must not carry the user's full powers.
func tokenIdentity(t *Token, id *identity.Identity, provider string) *identity.Identity {
	out := *id
	out.Scopes = slices.Clone(t.Scopes)
	out.Roles = slices.Clone(id.Roles)
	out.Provider = provider
	out.IssuedAt = t.CreatedAt
	out.ExpiresAt = t.AccessExpiresAt

	out.Claims = make(map[string]any, len(id.Claims)+4)
	for k, v := range id.Claims {
		out.Claims[k] = v
	}

	out.Claims[ClaimTokenID] = t.ID
	if t.ClientID != "" {
		out.Claims[ClaimClientID] = t.ClientID
	}
	if t.Resource != "" {
		out.Claims[ClaimResource] = t.Resource
	}
	if len(t.Extra) > 0 {
		out.Claims[ClaimExtra] = t.Extra
	}

	return &out
}

// bearerToken reads the Authorization: Bearer header.
func bearerToken(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", len(values) > 1
	}

	scheme, rest, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}

	return strings.TrimSpace(rest), true
}

// Strategy returns an auth strategy that accepts this server's access
// tokens on protected routes. auth.WithOAuthServer registers it for you.
func (s *Server) Strategy() *TokenStrategy {
	return &TokenStrategy{server: s}
}

// TokenStrategy is a strategy.RequestAuthenticator for this server's tokens.
type TokenStrategy struct {
	server   *Server
	resource *resource.Server
}

var (
	_ strategy.RequestAuthenticator = (*TokenStrategy)(nil)
	_ strategy.RequestChallenger    = (*TokenStrategy)(nil)
	_ strategy.ResourceBinder       = (*TokenStrategy)(nil)
)

// Name implements strategy.Authenticator.
func (t *TokenStrategy) Name() string { return t.server.cfg.StrategyName }

// Descriptor implements strategy.Authenticator. The strategy has no login
// widget.
func (t *TokenStrategy) Descriptor() strategy.Descriptor {
	return strategy.Descriptor{Name: t.Name(), Kind: "bearer", Label: "OAuth token", Hidden: true}
}

// Login rejects: tokens are presented on each request, not exchanged for a
// session.
func (t *TokenStrategy) Login(w http.ResponseWriter, _ *http.Request) (*identity.Identity, strategy.Outcome, error) {
	oauthError(w, http.StatusNotFound, "invalid_request", "present the token on each request")

	return nil, strategy.OutcomeFailed, nil
}

// Logout implements strategy.Authenticator.
func (t *TokenStrategy) Logout(context.Context, *identity.Identity) error { return nil }

// AuthenticateRequest implements strategy.RequestAuthenticator. Read the
// token behind the identity with Info.
func (t *TokenStrategy) AuthenticateRequest(ctx context.Context, r *http.Request) (*identity.Identity, error) {
	raw, ok := bearerToken(r)
	if !ok {
		return nil, strategy.ErrNoCredentials
	}

	tok, id, err := t.server.Validate(ctx, raw)
	if err != nil {
		return nil, err
	}

	if !audienceOK(tok, t.resource, r) {
		return nil, ErrInvalidToken
	}

	return id, nil
}

// audienceOK enforces the token's audience (RFC 8707, MCP authorization):
// a token issued for a resource is accepted only on requests for that
// resource or below it. Tokens without a resource (personal tokens, clients
// that named none) are accepted anywhere the route allows.
//
// Without a resource server there is no way to tell which resource a
// request is for, so a resource-bound token is refused rather than let it
// act on every route.
func audienceOK(t *Token, rs *resource.Server, r *http.Request) bool {
	if t.Resource == "" {
		return true
	}

	if rs == nil || !rs.Covers(r) {
		return false
	}

	target := rs.ResourceID(r)

	return target != "" && ResourceCovers(t.Resource, target)
}

// Challenge implements strategy.Challenger.
func (t *TokenStrategy) Challenge() string { return "Bearer" }

// ChallengeRequest implements strategy.RequestChallenger.
func (t *TokenStrategy) ChallengeRequest(r *http.Request) string {
	if t.resource == nil {
		return "Bearer"
	}

	return t.resource.Challenge(r, resource.ChallengeParams{})
}

// SetProtectedResource implements strategy.ResourceBinder.
func (t *TokenStrategy) SetProtectedResource(rs *resource.Server) {
	if t.resource == nil {
		t.resource = rs
	}
}

// RequireToken is a standalone middleware for applications not using
// middleware/auth: it accepts only this server's access tokens and answers
// 401 with a Bearer challenge otherwise. Pass a resource server to include
// the RFC 9728 resource_metadata pointer and to accept tokens issued for a
// resource; with a nil one only tokens without a resource are accepted.
func (s *Server) RequireToken(rs *resource.Server) func(http.Handler) http.Handler {
	challenge := func(r *http.Request, p resource.ChallengeParams) string {
		if rs == nil {
			if p.Error == "" {
				return "Bearer"
			}

			return fmt.Sprintf("Bearer error=%q", p.Error)
		}

		return rs.Challenge(r, p)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := bearerToken(r)
			if !ok {
				w.Header().Set("WWW-Authenticate", challenge(r, resource.ChallengeParams{}))
				oauthError(w, http.StatusUnauthorized, "unauthorized", "a bearer token is required")

				return
			}

			tok, id, err := s.Validate(r.Context(), raw)
			if err == nil && !audienceOK(tok, rs, r) {
				err = ErrInvalidToken
			}

			switch {
			case errors.Is(err, strategy.ErrNoCredentials), errors.Is(err, strategy.ErrInvalidCredentials):
				w.Header().Set("WWW-Authenticate", challenge(r, resource.ChallengeParams{
					Error: resource.ErrorInvalidToken, Description: "the access token is invalid or expired",
				}))
				oauthError(w, http.StatusUnauthorized, resource.ErrorInvalidToken, "the access token is invalid or expired")

				return
			case err != nil:
				slog.Error("oauthserver: validate token", "error", err.Error())
				oauthError(w, http.StatusInternalServerError, "server_error", "cannot validate the token")

				return
			}

			next.ServeHTTP(w, r.WithContext(identity.WithContext(r.Context(), id)))
		})
	}
}
