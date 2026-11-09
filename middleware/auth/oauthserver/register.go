package oauthserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/rakunlabs/ada/middleware/auth/proxy"
)

// RegistrationRequest is the client metadata of RFC 7591 §2 that this server
// uses. Clients send more; the rest is ignored.
type RegistrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// RegistrationResponse is the RFC 7591 §3.2.1 response.
type RegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at,omitempty"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// RegisterClient validates req and stores a new client, exactly as the
// registration endpoint does but without reusing a same-named client. Use it
// to seed clients when DisableRegistration is set. ClientSecret in the
// response is the only copy of a confidential client's secret.
func (s *Server) RegisterClient(ctx context.Context, req RegistrationRequest) (*RegistrationResponse, error) {
	c, err := s.validateRegistration(req)
	if err != nil {
		return nil, err
	}

	return s.createClient(ctx, c)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegistrationRequest

	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid JSON")

		return
	}

	c, err := s.validateRegistration(req)
	if err != nil {
		if oe := asOAuthError(err); oe != nil {
			oauthError(w, http.StatusBadRequest, oe.Code, oe.Description)

			return
		}

		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())

		return
	}

	// The same application registers again for every person and every
	// sign-in. A public client with the same name and redirects joins the
	// one registered first, so it is listed once. Approval, tokens and
	// remembered consent stay per user.
	if finder, ok := s.store.(ClientFinder); ok && c.Public() {
		same, err := finder.ClientsByName(r.Context(), c.Name)
		if err != nil && !errors.Is(err, ErrNotFound) {
			slog.Error("oauthserver: find clients", "error", err.Error())
		}

		for _, existing := range same {
			if existing.Public() && sameRedirects(existing.RedirectURIs, c.RedirectURIs) && slices.Equal(existing.GrantTypes, c.GrantTypes) {
				joined := *existing
				// The client gets back the redirects it sent, on its own port.
				joined.RedirectURIs = c.RedirectURIs
				writeJSON(w, http.StatusCreated, registrationOf(&joined, ""), false)

				return
			}
		}
	}

	if s.regRate != nil && !s.regRate.allow(s.clientIP(r)) {
		w.Header().Set("Retry-After", "3600")
		oauthError(w, http.StatusTooManyRequests, "invalid_request", "too many registrations; try again later")

		return
	}

	resp, err := s.createClient(r.Context(), c)
	if err != nil {
		slog.Error("oauthserver: register client", "error", err.Error())
		oauthError(w, http.StatusInternalServerError, "server_error", "cannot register the client")

		return
	}

	writeJSON(w, http.StatusCreated, resp, false)
}

// clientIP is the caller's address under the server's proxy policy.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.UnsafeTrustAllForwardedHeaders {
		if ip, err := proxy.UnsafeClientIP(r); err == nil {
			return ip
		}
	}

	ip, err := s.policy.ClientIP(r)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

func (s *Server) validateRegistration(req RegistrationRequest) (*Client, error) {
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > maxRedirectURIs {
		return nil, &Error{"invalid_redirect_uri", "one to ten redirect_uris are required"}
	}

	for _, u := range req.RedirectURIs {
		if !ValidRedirectURI(u) {
			return nil, &Error{"invalid_redirect_uri", "redirect URIs must be https, http on loopback or a private-use scheme, without a fragment"}
		}
	}

	for _, rt := range req.ResponseTypes {
		if rt != ResponseTypeCode {
			return nil, &Error{"invalid_client_metadata", "only the code response type is supported"}
		}
	}

	grants := []string(nil)
	for _, g := range req.GrantTypes {
		if g != GrantCode && g != GrantRefresh {
			return nil, &Error{"invalid_client_metadata", "only authorization_code and refresh_token grants are supported"}
		}
		if !slices.Contains(grants, g) {
			grants = append(grants, g)
		}
	}
	if len(grants) > 0 && !slices.Contains(grants, GrantCode) {
		return nil, &Error{"invalid_client_metadata", "authorization_code grant is required"}
	}

	method := req.TokenEndpointAuthMethod
	switch method {
	case "":
		method = AuthMethodNone
	case AuthMethodNone, AuthMethodBasic, AuthMethodPost:
	default:
		return nil, &Error{"invalid_client_metadata", "unsupported token_endpoint_auth_method"}
	}

	name := strings.TrimSpace(req.ClientName)
	if name == "" {
		name = "OAuth client"
	}
	if r := []rune(name); len(r) > 100 {
		name = string(r[:100])
	}

	return &Client{
		Name:                    name,
		RedirectURIs:            slices.Clone(req.RedirectURIs),
		GrantTypes:              grants,
		TokenEndpointAuthMethod: method,
	}, nil
}

func (s *Server) createClient(ctx context.Context, c *Client) (*RegistrationResponse, error) {
	id, err := randomString(16)
	if err != nil {
		return nil, err
	}

	c.ID = id
	c.CreatedAt = s.now()

	secret := ""
	if !c.Public() {
		secret, err = randomString(32)
		if err != nil {
			return nil, err
		}

		c.SecretHash = HashSecret(secret)
	}

	if err := s.store.CreateClient(ctx, c); err != nil {
		return nil, err
	}

	return registrationOf(c, secret), nil
}

func registrationOf(c *Client, secret string) *RegistrationResponse {
	grants := c.GrantTypes
	if len(grants) == 0 {
		grants = []string{GrantCode, GrantRefresh}
	}

	resp := &RegistrationResponse{
		ClientID:                c.ID,
		ClientSecret:            secret,
		ClientIDIssuedAt:        c.CreatedAt.Unix(),
		ClientName:              c.Name,
		RedirectURIs:            c.RedirectURIs,
		GrantTypes:              grants,
		ResponseTypes:           []string{ResponseTypeCode},
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
	}

	if secret != "" {
		never := int64(0)
		resp.ClientSecretExpiresAt = &never
	}

	return resp
}

// ValidRedirectURI accepts https URIs, http on the loopback interface (where
// CLI clients listen) and private-use schemes such as cursor:// or
// vscode://. Fragments and schemes that execute or embed content are
// rejected.
func ValidRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Fragment != "" || strings.Contains(raw, "#") {
		return false
	}

	switch strings.ToLower(u.Scheme) {
	case "https":
		return u.Host != ""
	case "http":
		return isLoopback(u.Hostname())
	case "javascript", "data", "file", "vbscript", "about", "blob", "ftp", "ws", "wss":
		return false
	}

	return true
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// RedirectMatches compares a registered redirect URI with one a request uses.
// On the loopback interface the port may differ (RFC 8252 §7.3): CLI clients
// listen on a free port each time. Everything else must match exactly.
func RedirectMatches(registered, used string) bool {
	if registered == used {
		return true
	}

	a, err1 := url.Parse(registered)
	b, err2 := url.Parse(used)

	if err1 != nil || err2 != nil || !strings.EqualFold(a.Scheme, "http") || !strings.EqualFold(b.Scheme, "http") {
		return false
	}

	return isLoopback(a.Hostname()) && a.Hostname() == b.Hostname() && a.Path == b.Path && a.RawQuery == b.RawQuery
}

// sameRedirects tells whether two lists of redirect URIs cover one another.
func sameRedirects(a, b []string) bool {
	covers := func(x, y []string) bool {
		for _, u := range y {
			if !slices.ContainsFunc(x, func(r string) bool { return RedirectMatches(r, u) }) {
				return false
			}
		}

		return true
	}

	return covers(a, b) && covers(b, a)
}
