package oauthserver

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

// refreshReuseGrace is how long after a rotation the previous refresh token
// is merely refused rather than treated as stolen.
const refreshReuseGrace = 30 * time.Second

// TokenResponse is the RFC 6749 §5.1 token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "invalid form")

		return
	}

	client, oerr := s.authenticateClient(r)
	if oerr != nil {
		s.writeClientError(w, oerr)

		return
	}

	switch grant := r.PostForm.Get("grant_type"); grant {
	case GrantCode:
		s.exchangeCode(w, r, client)
	case GrantRefresh:
		if s.cfg.RefreshTTL < 0 {
			oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "refresh tokens are disabled")

			return
		}
		s.refresh(w, r, client)
	case "":
		oauthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

func (s *Server) writeClientError(w http.ResponseWriter, e *Error) {
	if e.Code == "invalid_client" {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
		oauthError(w, http.StatusUnauthorized, e.Code, e.Description)

		return
	}

	oauthError(w, http.StatusBadRequest, e.Code, e.Description)
}

// authenticateClient identifies the client of a token or revocation request.
// It returns nil, nil when the request names no client at all (allowed for a
// public client refreshing a token, RFC 6749 §6).
func (s *Server) authenticateClient(r *http.Request) (*Client, *Error) {
	id, secret, basic := r.BasicAuth()
	if basic {
		var err error
		if id, err = url.QueryUnescape(id); err != nil {
			return nil, &Error{"invalid_client", "malformed client credentials"}
		}
		if secret, err = url.QueryUnescape(secret); err != nil {
			return nil, &Error{"invalid_client", "malformed client credentials"}
		}
		if form := r.PostForm.Get("client_id"); form != "" && form != id {
			return nil, &Error{"invalid_request", "client_id does not match the credentials"}
		}
	} else {
		id = r.PostForm.Get("client_id")
		secret = r.PostForm.Get("client_secret")
	}

	if id == "" {
		return nil, nil
	}

	client, err := s.store.GetClient(r.Context(), id)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			slog.Error("oauthserver: load client", "error", err.Error())

			return nil, &Error{"server_error", "cannot load the client"}
		}

		return nil, &Error{"invalid_client", "unknown client"}
	}

	if client.Public() {
		if secret != "" {
			return nil, &Error{"invalid_client", "public clients have no secret"}
		}

		return client, nil
	}

	if secret == "" || subtle.ConstantTimeCompare([]byte(HashSecret(secret)), []byte(client.SecretHash)) != 1 {
		return nil, &Error{"invalid_client", "client authentication failed"}
	}

	return client, nil
}

func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request, client *Client) {
	f := r.PostForm

	if client == nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client_id is required")

		return
	}

	raw := f.Get("code")
	if raw == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "code is required")

		return
	}

	// The code is consumed before anything is checked: a code presented
	// with the wrong verifier is burnt, so it cannot be brute-forced.
	code, err := s.store.TakeCode(r.Context(), HashSecret(raw))
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			slog.Error("oauthserver: take code", "error", err.Error())
			oauthError(w, http.StatusInternalServerError, "server_error", "cannot load the code")

			return
		}

		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown, used or expired code")

		return
	}

	switch {
	case !code.ExpiresAt.IsZero() && s.now().After(code.ExpiresAt):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown, used or expired code")

		return
	case code.ClientID != client.ID:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the code belongs to another client")

		return
	case code.RedirectURI != f.Get("redirect_uri"):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match")

		return
	case !pkceMatches(f.Get("code_verifier"), code.CodeChallenge):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")

		return
	}

	// RFC 8707 §2.2: a resource on the token request must be one the user
	// approved. A resource the authorization did not name is refused too:
	// it was never shown on the consent page.
	if res := f.Get("resource"); res != "" && (code.Resource == "" || !ResourceCovers(code.Resource, res)) {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource does not match the authorization")

		return
	}

	t := &Token{
		ClientID:      client.ID,
		Name:          client.Name,
		Identity:      code.Identity,
		Scopes:        code.Scopes,
		GrantedScopes: slices.Clone(code.Scopes),
		Resource:      code.Resource,
		Extra:         code.Extra,
	}

	id, oerr := s.currentIdentity(r.Context(), t)
	if oerr != nil {
		s.writeGrantError(w, oerr)

		return
	}
	t.Identity = id

	withRefresh := client.AllowsGrant(GrantRefresh)

	resp, err := s.issue(r.Context(), t, withRefresh)
	if err != nil {
		slog.Error("oauthserver: issue token", "error", err.Error())
		oauthError(w, http.StatusInternalServerError, "server_error", "cannot issue a token")

		return
	}

	writeJSON(w, http.StatusOK, resp, false)
}

func (s *Server) writeGrantError(w http.ResponseWriter, e *Error) {
	status := http.StatusBadRequest
	if e.Code == "server_error" {
		status = http.StatusInternalServerError
	}

	oauthError(w, status, e.Code, e.Description)
}

// currentIdentity runs Hooks.Identity.
func (s *Server) currentIdentity(ctx context.Context, t *Token) (*identity.Identity, *Error) {
	if s.cfg.Hooks.Identity == nil {
		return t.Identity, nil
	}

	id, err := s.cfg.Hooks.Identity(ctx, t)
	switch {
	case errors.Is(err, ErrAccessDenied):
		return nil, &Error{"invalid_grant", "the user can no longer sign in"}
	case err != nil:
		slog.Error("oauthserver: identity hook", "error", err.Error())

		return nil, &Error{"server_error", "cannot load the user"}
	case id == nil:
		return nil, &Error{"invalid_grant", "the user can no longer sign in"}
	}

	return id, nil
}

// lifetimes returns the access and refresh TTLs for t.
func (s *Server) lifetimes(ctx context.Context, t *Token) (time.Duration, time.Duration) {
	access, refresh := s.cfg.AccessTTL, s.cfg.RefreshTTL

	if s.cfg.Hooks.TokenTTL != nil {
		a, r := s.cfg.Hooks.TokenTTL(ctx, t)
		if a > 0 {
			access = a
		}
		if r != 0 {
			refresh = r
		}
	}

	return access, refresh
}

// issue fills t with fresh secrets, stores it and returns the response.
func (s *Server) issue(ctx context.Context, t *Token, withRefresh bool) (*TokenResponse, error) {
	id, err := randomString(16)
	if err != nil {
		return nil, err
	}

	t.ID = id
	t.CreatedAt = s.now()

	accessTTL, refreshTTL := s.lifetimes(ctx, t)
	if refreshTTL < 0 {
		withRefresh = false
	}

	access, refresh, err := s.secrets(t, accessTTL, withRefresh)
	if err != nil {
		return nil, err
	}

	if withRefresh {
		t.RefreshExpiresAt = t.CreatedAt.Add(refreshTTL)
	}

	if err := s.store.SaveToken(ctx, t); err != nil {
		return nil, err
	}

	return s.tokenResponse(t, access, refresh), nil
}

// secrets gives t a new access token and, when asked, a new refresh token.
func (s *Server) secrets(t *Token, accessTTL time.Duration, withRefresh bool) (string, string, error) {
	rawAccess, err := randomString(32)
	if err != nil {
		return "", "", err
	}

	access := s.cfg.AccessTokenPrefix + rawAccess
	t.AccessHash = HashSecret(access)
	t.AccessExpiresAt = s.now().Add(accessTTL)

	if !withRefresh {
		t.RefreshHash = ""
		t.RefreshExpiresAt = time.Time{}

		return access, "", nil
	}

	rawRefresh, err := randomString(32)
	if err != nil {
		return "", "", err
	}

	refresh := s.cfg.RefreshTokenPrefix + rawRefresh
	t.RefreshHash = HashSecret(refresh)

	return access, refresh, nil
}

func (s *Server) tokenResponse(t *Token, access, refresh string) *TokenResponse {
	resp := &TokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		RefreshToken: refresh,
		Scope:        strings.Join(t.Scopes, " "),
	}

	if !t.AccessExpiresAt.IsZero() {
		resp.ExpiresIn = int64(t.AccessExpiresAt.Sub(s.now()).Round(time.Second).Seconds())
	}

	return resp
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request, client *Client) {
	f := r.PostForm

	raw := f.Get("refresh_token")
	if raw == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")

		return
	}

	oldHash := HashSecret(raw)

	t, err := s.store.TokenByRefresh(r.Context(), oldHash)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			slog.Error("oauthserver: load token", "error", err.Error())
			oauthError(w, http.StatusInternalServerError, "server_error", "cannot load the token")

			return
		}

		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown or expired refresh token; sign in again")

		return
	}

	// A confidential client must authenticate (RFC 6749 §6); a public client
	// may omit client_id, but one it names must be the token's.
	owner, err := s.store.GetClient(r.Context(), t.ClientID)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the client of this token is gone")

		return
	}

	// A rotated-out refresh token came back. Right after the rotation that
	// is a client whose two refreshes raced (or a retried request); later,
	// it means two parties hold the grant, and it can no longer be trusted.
	if t.RefreshHash != oldHash && s.now().Sub(t.RotatedAt) < refreshReuseGrace {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token was already used")

		return
	}

	if t.RefreshHash != oldHash {
		slog.Warn("oauthserver: refresh token reuse; revoking the grant", "token_id", t.ID, "client_id", t.ClientID)

		if err := s.store.DeleteToken(r.Context(), t.ID); err != nil && !errors.Is(err, ErrNotFound) {
			slog.Error("oauthserver: revoke reused grant", "error", err.Error())
		}

		oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token was already used; sign in again")

		return
	}

	switch {
	case client == nil && !owner.Public():
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication required")

		return
	case client != nil && client.ID != t.ClientID:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token belongs to another client")

		return
	case !owner.AllowsGrant(GrantRefresh):
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "the client may not refresh tokens")

		return
	case !t.RefreshExpiresAt.IsZero() && s.now().After(t.RefreshExpiresAt):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown or expired refresh token; sign in again")

		return
	}

	// RFC 6749 §6: a refresh may narrow the access token's scopes, never
	// widen them past what the user approved. The approval itself stays, so
	// a later refresh can ask for the rest back.
	granted := t.GrantedScopes
	if len(granted) == 0 {
		granted = t.Scopes
	}
	t.GrantedScopes = slices.Clone(granted)
	t.Scopes = slices.Clone(granted)

	if raw := f.Get("scope"); raw != "" {
		var asked []string

		for _, scope := range strings.Fields(raw) {
			if !validScope(scope) || !slices.Contains(granted, scope) {
				oauthError(w, http.StatusBadRequest, "invalid_scope", "a refresh cannot add scopes")

				return
			}
			if !slices.Contains(asked, scope) {
				asked = append(asked, scope)
			}
		}

		t.Scopes = asked
	}

	id, oerr := s.currentIdentity(r.Context(), t)
	if oerr != nil {
		s.writeGrantError(w, oerr)

		return
	}
	t.Identity = id

	// The refresh token keeps the lifetime of the first sign-in. A
	// TokenTTL hook that now says "no refresh" ends the chain here: this
	// access token is the last.
	until := t.RefreshExpiresAt
	accessTTL, refreshTTL := s.lifetimes(r.Context(), t)

	t.PreviousRefreshHash = oldHash
	t.RotatedAt = s.now()

	access, refresh, err := s.secrets(t, accessTTL, refreshTTL >= 0)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "cannot issue a token")

		return
	}
	if refresh != "" {
		t.RefreshExpiresAt = until
	}

	// Rotation: the old refresh token stops working. Two refreshes racing
	// with the same one get one token; the other signs in again.
	if err := s.store.RotateToken(r.Context(), oldHash, t); err != nil {
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) {
			oauthError(w, http.StatusBadRequest, "invalid_grant", "the refresh token was already used")

			return
		}

		slog.Error("oauthserver: rotate token", "error", err.Error())
		oauthError(w, http.StatusInternalServerError, "server_error", "cannot issue a token")

		return
	}

	writeJSON(w, http.StatusOK, s.tokenResponse(t, access, refresh), false)
}

// handleRevoke is the RFC 7009 revocation endpoint. Revoking either token of
// a pair revokes the whole grant. Unknown tokens are not an error.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "invalid form")

		return
	}

	client, oerr := s.authenticateClient(r)
	if oerr != nil {
		s.writeClientError(w, oerr)

		return
	}

	raw := r.PostForm.Get("token")
	if raw == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "token is required")

		return
	}

	t, err := s.findToken(r.Context(), raw, r.PostForm.Get("token_type_hint"))
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			slog.Error("oauthserver: revoke lookup", "error", err.Error())
			oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "try again")

			return
		}

		w.WriteHeader(http.StatusOK)

		return
	}

	// A client may only revoke its own tokens; a token of another client is
	// answered like an unknown one, so revocation is no oracle.
	// A public client sends no credentials, so holding the token is the
	// proof; a confidential one must authenticate (RFC 7009 §2.1).
	if !s.mayRevoke(r.Context(), client, t) {
		w.WriteHeader(http.StatusOK)

		return
	}

	if err := s.store.DeleteToken(r.Context(), t.ID); err != nil && !errors.Is(err, ErrNotFound) {
		slog.Error("oauthserver: revoke", "error", err.Error())
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "try again")

		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) mayRevoke(ctx context.Context, client *Client, t *Token) bool {
	switch {
	case t.ClientID == "":
		return true
	case client != nil:
		return client.ID == t.ClientID
	}

	owner, err := s.store.GetClient(ctx, t.ClientID)

	return err == nil && owner.Public()
}

func (s *Server) findToken(ctx context.Context, raw, hint string) (*Token, error) {
	hash := HashSecret(raw)

	lookups := []func(context.Context, string) (*Token, error){s.store.TokenByAccess, s.store.TokenByRefresh}
	if hint == "refresh_token" || strings.HasPrefix(raw, s.cfg.RefreshTokenPrefix) {
		slices.Reverse(lookups)
	}

	for _, lookup := range lookups {
		t, err := lookup(ctx, hash)
		if err == nil {
			return t, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}

	return nil, ErrNotFound
}

// ////////////////////////////////////////////////////////////////////////////
// programmatic tokens

// IssueRequest describes a token made by the application itself rather than
// through the OAuth flow: a personal access token a user creates on a
// settings page, or a token for a service account.
type IssueRequest struct {
	// Name labels the token in listings.
	Name     string
	Identity *identity.Identity
	Scopes   []string
	Resource string
	Extra    map[string]any
	// TTL is the token lifetime. Zero means it never expires.
	TTL time.Duration
}

// IssueToken creates a personal access token. It has no refresh token and
// no client. The returned string is the only copy of the token; Token.ID is
// what to show and revoke it by.
func (s *Server) IssueToken(ctx context.Context, req IssueRequest) (string, *Token, error) {
	if req.Identity == nil || req.Identity.Subject == "" {
		return "", nil, fmt.Errorf("oauthserver: issue token: identity with a subject is required")
	}

	for _, scope := range req.Scopes {
		if !validScope(scope) {
			return "", nil, fmt.Errorf("oauthserver: issue token: invalid scope %q", scope)
		}
	}

	if r := []rune(strings.TrimSpace(req.Name)); len(r) > 100 {
		req.Name = string(r[:100])
	}

	id, err := randomString(16)
	if err != nil {
		return "", nil, err
	}

	t := &Token{
		ID:        id,
		Name:      req.Name,
		Identity:  req.Identity,
		Scopes:    slices.Clone(req.Scopes),
		Resource:  req.Resource,
		Extra:     maps.Clone(req.Extra),
		CreatedAt: s.now(),
	}

	access, _, err := s.secrets(t, 0, false)
	if err != nil {
		return "", nil, err
	}

	t.AccessExpiresAt = time.Time{}
	if req.TTL > 0 {
		t.AccessExpiresAt = t.CreatedAt.Add(req.TTL)
	}

	if err := s.store.SaveToken(ctx, t); err != nil {
		return "", nil, err
	}

	return access, t, nil
}

// RevokeToken deletes a token by ID.
func (s *Server) RevokeToken(ctx context.Context, id string) error {
	return s.store.DeleteToken(ctx, id)
}
