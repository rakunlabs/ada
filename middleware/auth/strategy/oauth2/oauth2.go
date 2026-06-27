// Package oauth2 implements a strategy.Authenticator for OAuth2 providers.
//
// Login does one of three things depending on the request shape:
//
//   - GET without ?code= (initiate)   -> generate state, set state cookie, redirect to AuthURL.
//   - GET with ?code= (callback)      -> validate state, exchange code, build Identity, revoke upstream token.
//   - POST (password flow, opt-in)    -> exchange username/password, build Identity, revoke upstream token.
//
// After Login returns, the upstream OAuth2 token is gone. The session lives in
// our own opaque token world (see middleware/auth/issuer).
package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

// Config holds an OAuth2 provider's endpoints and credentials.
type Config struct {
	ClientID      string   `cfg:"client_id"`
	ClientSecret  string   `cfg:"client_secret"`
	Scopes        []string `cfg:"scopes"`
	AuthURL       string   `cfg:"auth_url"`
	TokenURL      string   `cfg:"token_url"`
	UserInfoURL   string   `cfg:"userinfo_url"`
	RevocationURL string   `cfg:"revocation_url"`
	LogoutURL     string   `cfg:"logout_url"`
	// AuthHeaderStyle selects how the client credentials are presented to the
	// token (and revocation) endpoint. The zero value is Basic
	// (client_secret_basic). Config may set it as a readable string via
	// UnmarshalText, e.g. auth_header_style: client_secret_post. Switch away
	// from Basic when a provider rejects correct credentials with an
	// "invalid_client" / "client_secret does not match" error.
	AuthHeaderStyle AuthHeaderStyle `cfg:"auth_header_style"`

	// IssuerURL is the OIDC issuer URL (e.g. "https://accounts.google.com").
	// When set, the strategy fetches /.well-known/openid-configuration to
	// auto-populate AuthURL, TokenURL, UserInfoURL, RevocationURL, and
	// LogoutURL. Explicitly set fields take precedence over discovered ones.
	IssuerURL string `cfg:"issuer_url"`

	// DisablePKCE disables PKCE (Proof Key for Code Exchange). PKCE is enabled
	// by default for the authorization code flow. Only disable if your IdP
	// does not support it.
	DisablePKCE bool `cfg:"disable_pkce"`

	// PasswordFlow enables POST /auth/login/{name} accepting {username,password}.
	PasswordFlow bool `cfg:"password_flow"`
}

// Options control non-protocol-level behavior of the strategy.
type Options struct {
	Label    string
	Priority int
	Hidden   bool

	// EmailVerifyCheck, when true, skips Identity.Email if email_verified is false.
	EmailVerifyCheck bool

	// XUserClaims maps OIDC claim names that fill Identity fields. Defaults
	// match common providers: subject from "sub", email from "email", name from
	// "name" or "preferred_username".
	XUserClaims XUserClaims

	// InsecureSkipVerify disables TLS verification for token+userinfo+revoke
	// HTTP calls. Use only for local IdP testing.
	InsecureSkipVerify bool

	// HTTPClient overrides the strategy's HTTP client. If nil, a default client
	// is built from InsecureSkipVerify.
	HTTPClient *http.Client

	// CallbackBaseURL is the absolute origin used to construct the redirect_uri
	// (e.g. "https://app.example.com"). When empty, the strategy derives the
	// origin from the request's X-Forwarded-* headers or Host.
	CallbackBaseURL string

	// CallbackBasePath is the path prefix for the callback (e.g. "/auth/callback").
	// The strategy appends "/<name>" to it when building redirect_uri.
	CallbackBasePath string
}

// XUserClaims maps OIDC claim names to Identity fields.
type XUserClaims struct {
	Subject []string // first non-empty wins; defaults to ["sub"]
	Email   []string // defaults to ["email"]
	Name    []string // defaults to ["name", "preferred_username"]
	Roles   []string // defaults to ["roles"]
	Scope   []string // defaults to ["scope"]
}

func (x XUserClaims) withDefaults() XUserClaims {
	if len(x.Subject) == 0 {
		x.Subject = []string{"sub"}
	}
	if len(x.Email) == 0 {
		x.Email = []string{"email"}
	}
	if len(x.Name) == 0 {
		x.Name = []string{"name", "preferred_username"}
	}
	if len(x.Roles) == 0 {
		x.Roles = []string{"roles"}
	}
	if len(x.Scope) == 0 {
		x.Scope = []string{"scope"}
	}

	return x
}

// Strategy implements strategy.Authenticator for an OAuth2 provider.
type Strategy struct {
	name string
	cfg  Config
	opts Options

	client *http.Client

	stateCookie    StateCookie
	verifierCookie StateCookie // stores PKCE code_verifier alongside state
	discovery      *discoveryCache
}

// StateCookie controls the CSRF state cookie set during the code flow.
type StateCookie struct {
	Name     string
	MaxAge   int
	Path     string
	Domain   string
	Secure   bool
	SameSite http.SameSite
	HttpOnly bool
}

func (sc StateCookie) withDefaults(name string) StateCookie {
	if sc.Name == "" {
		sc.Name = "auth_state_" + name
	}
	if sc.MaxAge == 0 {
		sc.MaxAge = 360
	}
	if sc.Path == "" {
		sc.Path = "/"
	}
	if sc.SameSite == 0 {
		sc.SameSite = http.SameSiteLaxMode
	}

	return sc
}

// New returns an OAuth2 strategy. If cfg.IssuerURL is set, OIDC discovery is
// performed immediately to populate missing endpoint URLs.
func New(name string, cfg Config, opts Options) *Strategy {
	opts.XUserClaims = opts.XUserClaims.withDefaults()

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify}, //nolint:gosec // opt-in
			},
			Timeout: 30 * time.Second,
		}
	}

	// OIDC Discovery: auto-populate endpoints from issuer.
	dc := newDiscoveryCache(1 * time.Hour)
	if cfg.IssuerURL != "" {
		doc, err := Discover(context.Background(), client, cfg.IssuerURL)
		if err != nil {
			slog.Warn("oauth2: discovery failed, using explicit config", "strategy", name, "issuer", cfg.IssuerURL, "error", err.Error())
		} else {
			dc.set(doc)
			applyDiscovery(&cfg, doc)
		}
	}

	verifierCookie := StateCookie{
		Name: "auth_pkce_" + name,
	}.withDefaults(name)
	// Override the name since withDefaults would set "auth_state_<name>"
	verifierCookie.Name = "auth_pkce_" + name

	return &Strategy{
		name:           name,
		cfg:            cfg,
		opts:           opts,
		client:         client,
		stateCookie:    StateCookie{}.withDefaults(name),
		verifierCookie: verifierCookie,
		discovery:      dc,
	}
}

// Name returns the strategy's URL key.
func (s *Strategy) Name() string { return s.name }

// SetCallbackBasePath implements strategy.CallbackBinder. It lets the auth
// middleware push its resolved callback base (typically
// "{cfg.Base}login/callback") so the OAuth2 strategy builds redirect_uri
// values that match the mounted routes. An explicit Options.CallbackBasePath
// set by the caller always wins.
//
// This is expected to be called once at Mount time, before any requests are
// served; no synchronization is used.
func (s *Strategy) SetCallbackBasePath(p string) {
	if s.opts.CallbackBasePath != "" {
		return
	}
	s.opts.CallbackBasePath = p
}

// Descriptor returns the UI-facing description.
func (s *Strategy) Descriptor() strategy.Descriptor {
	d := strategy.Descriptor{
		Name:  s.name,
		Kind:  "oauth2",
		Label: s.opts.Label,
		// LoginURL is resolved by the auth middleware from cfg.Base.
		Priority: s.opts.Priority,
		Hidden:   s.opts.Hidden,
	}

	if d.Label == "" {
		d.Label = s.name
	}

	if s.cfg.PasswordFlow {
		d.Kind = "password"
		d.Fields = []strategy.Field{
			{Name: "username", Label: "Username", Type: "text", Required: true},
			{Name: "password", Label: "Password", Type: "password", Required: true},
		}
	}

	return d
}

// Login dispatches to the right flow based on request shape.
func (s *Strategy) Login(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Get("code") != "" {
			return s.handleCallback(w, r)
		}

		return s.handleInitiate(w, r)

	case http.MethodPost:
		if !s.cfg.PasswordFlow {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "password_flow disabled")

			return nil, strategy.OutcomeFailed, nil
		}

		return s.handlePassword(w, r)
	}

	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "unsupported method")

	return nil, strategy.OutcomeFailed, nil
}

// Logout calls LogoutURL if set.
func (s *Strategy) Logout(ctx context.Context, _ *identity.Identity) error {
	if s.cfg.LogoutURL == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.LogoutURL, nil)
	if err != nil {
		return err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}

	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("oauth2 logout: %s", resp.Status)
	}

	return nil
}

// handleInitiate generates state (and PKCE if enabled), sets cookies, and redirects to AuthURL.
func (s *Strategy) handleInitiate(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	state, err := randomState(16)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "state_generate", err.Error())

		return nil, strategy.OutcomeFailed, nil
	}

	s.setStateCookie(w, state)

	// PKCE
	var pkce *pkceParams
	if !s.cfg.DisablePKCE {
		pkce, err = newPKCE()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "pkce_generate", err.Error())

			return nil, strategy.OutcomeFailed, nil
		}

		s.setVerifierCookie(w, pkce.Verifier)
	}

	redirectURI, err := s.callbackURL(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "redirect_uri", err.Error())

		return nil, strategy.OutcomeFailed, nil
	}

	authURL, err := s.buildAuthCodeURL(state, redirectURI, pkce)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "auth_url", err.Error())

		return nil, strategy.OutcomeFailed, nil
	}

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)

	return nil, strategy.OutcomePending, nil
}

// handleCallback validates state, exchanges code (with PKCE verifier), fetches userinfo, builds Identity, revokes.
func (s *Strategy) handleCallback(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")

	if err := s.checkStateCookie(w, r, state); err != nil {
		writeError(w, http.StatusUnauthorized, "state_invalid", "state does not match")

		return nil, strategy.OutcomeFailed, nil
	}

	// Read PKCE verifier
	var codeVerifier string
	if !s.cfg.DisablePKCE {
		codeVerifier = s.readVerifierCookie(r)
		s.clearVerifierCookie(w)
	}

	redirectURI, err := s.callbackURL(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "redirect_uri", err.Error())

		return nil, strategy.OutcomeFailed, nil
	}

	body, err := s.exchangeCode(r.Context(), code, redirectURI, codeVerifier)
	if err != nil {
		writeError(w, http.StatusBadGateway, "code_exchange", err.Error())

		return nil, strategy.OutcomeFailed, nil
	}

	id, accessToken, err := s.identityFromTokenResponse(r.Context(), body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "identity_extract", err.Error())

		return nil, strategy.OutcomeFailed, nil
	}

	s.revoke(r.Context(), accessToken)

	return id, strategy.OutcomeContinue, nil
}

// handlePassword exchanges username/password for a token, extracts identity, revokes.
func (s *Strategy) handlePassword(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())

		return nil, strategy.OutcomeFailed, nil
	}

	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error())

			return nil, strategy.OutcomeFailed, nil
		}

		creds.Username = values.Get("username")
		creds.Password = values.Get("password")
	} else {
		if err := json.Unmarshal(body, &creds); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error())

			return nil, strategy.OutcomeFailed, nil
		}
	}

	tokenBody, err := s.exchangePassword(r.Context(), creds.Username, creds.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", err.Error())

		return nil, strategy.OutcomeFailed, nil
	}

	id, accessToken, err := s.identityFromTokenResponse(r.Context(), tokenBody)
	if err != nil {
		writeError(w, http.StatusBadGateway, "identity_extract", err.Error())

		return nil, strategy.OutcomeFailed, nil
	}

	s.revoke(r.Context(), accessToken)

	return id, strategy.OutcomeContinue, nil
}

// exchangeCode swaps an authorization code for a token response body.
// codeVerifier is the PKCE verifier; empty if PKCE is disabled.
func (s *Strategy) exchangeCode(ctx context.Context, code, redirectURI, codeVerifier string) ([]byte, error) {
	values := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
	}
	if redirectURI != "" {
		values.Set("redirect_uri", redirectURI)
	}
	if codeVerifier != "" {
		values.Set("code_verifier", codeVerifier)
	}

	return s.tokenRequest(ctx, values)
}

// exchangePassword swaps username/password for a token response body.
func (s *Strategy) exchangePassword(ctx context.Context, username, password string) ([]byte, error) {
	values := url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
	}

	if len(s.cfg.Scopes) > 0 {
		values.Set("scope", strings.Join(s.cfg.Scopes, " "))
	}

	return s.tokenRequest(ctx, values)
}

func (s *Strategy) tokenRequest(ctx context.Context, values url.Values) ([]byte, error) {
	// authBody mutates values, so it must run before Encode below.
	authBody(s.cfg.ClientID, s.cfg.ClientSecret, values, s.cfg.AuthHeaderStyle)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}

	authParams(s.cfg.ClientID, s.cfg.ClientSecret, req, s.cfg.AuthHeaderStyle)
	authHeader(req, s.cfg.ClientID, s.cfg.ClientSecret, s.cfg.AuthHeaderStyle)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New(strings.TrimSpace(string(body)))
	}

	return body, nil
}

// tokenResponse is the OAuth2 token endpoint response shape.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

func (s *Strategy) identityFromTokenResponse(ctx context.Context, body []byte) (*identity.Identity, string, error) {
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, "", fmt.Errorf("decode token response: %w", err)
	}

	if tr.AccessToken == "" {
		return nil, "", fmt.Errorf("token response missing access_token")
	}

	claims, err := s.fetchClaims(ctx, tr)
	if err != nil {
		return nil, tr.AccessToken, err
	}

	id := s.identityFromClaims(claims, tr)

	return id, tr.AccessToken, nil
}

// fetchClaims pulls the user's claims either from UserInfoURL (preferred) or
// by JSON-decoding the JWT id_token / access_token. We never verify the JWT;
// the IdP just authenticated us, so we trust the response we got from it.
func (s *Strategy) fetchClaims(ctx context.Context, tr tokenResponse) (map[string]any, error) {
	if s.cfg.UserInfoURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.UserInfoURL, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
		req.Header.Set("Accept", "application/json")

		resp, err := s.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, err
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("userinfo: %s", strings.TrimSpace(string(body)))
		}

		var claims map[string]any
		if err := json.Unmarshal(body, &claims); err != nil {
			return nil, fmt.Errorf("decode userinfo: %w", err)
		}

		return claims, nil
	}

	candidate := tr.IDToken
	if candidate == "" {
		candidate = tr.AccessToken
	}

	return decodeJWTPayload(candidate)
}

// decodeJWTPayload base64-decodes a JWT's claims segment without verifying
// signature. Safe here because the strategy already trusts the response from
// the IdP — we just need the claims, not a verification.
func decodeJWTPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("not a JWT")
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("decode payload json: %w", err)
	}

	return claims, nil
}

func (s *Strategy) identityFromClaims(claims map[string]any, tr tokenResponse) *identity.Identity {
	id := &identity.Identity{
		Provider: s.name,
		Claims:   claims,
		IssuedAt: time.Now(),
		Scopes:   strings.Fields(tr.Scope),
	}

	if id.Subject = firstClaim(claims, s.opts.XUserClaims.Subject); id.Subject == "" {
		id.Subject = firstClaim(claims, []string{"preferred_username", "email"})
	}

	id.Email = firstClaim(claims, s.opts.XUserClaims.Email)

	if v, ok := claims["email_verified"].(bool); ok {
		id.EmailVerified = v
	}

	if s.opts.EmailVerifyCheck && !id.EmailVerified {
		id.Email = ""
	}

	id.Name = firstClaim(claims, s.opts.XUserClaims.Name)

	id.Roles = stringsClaim(claims, s.opts.XUserClaims.Roles)

	if scope := firstClaim(claims, s.opts.XUserClaims.Scope); scope != "" {
		if len(id.Scopes) == 0 {
			id.Scopes = strings.Fields(scope)
		}
	}

	if tr.ExpiresIn > 0 {
		id.ExpiresAt = id.IssuedAt.Add(time.Duration(tr.ExpiresIn) * time.Second)
	}

	return id
}

func firstClaim(claims map[string]any, keys []string) string {
	for _, k := range keys {
		if v, ok := claims[k].(string); ok && v != "" {
			return v
		}
	}

	return ""
}

func stringsClaim(claims map[string]any, keys []string) []string {
	for _, k := range keys {
		raw, ok := claims[k]
		if !ok {
			continue
		}

		switch v := raw.(type) {
		case []any:
			out := make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					out = append(out, s)
				}
			}

			return out
		case []string:
			return v
		case string:
			return strings.Fields(v)
		}
	}

	return nil
}

// revoke best-effort calls RevocationURL to invalidate the upstream token.
func (s *Strategy) revoke(ctx context.Context, accessToken string) {
	if s.cfg.RevocationURL == "" || accessToken == "" {
		return
	}

	values := url.Values{
		"token":           {accessToken},
		"token_type_hint": {"access_token"},
	}

	// authBody mutates values, so it must run before Encode below.
	authBody(s.cfg.ClientID, s.cfg.ClientSecret, values, s.cfg.AuthHeaderStyle)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.RevocationURL, strings.NewReader(values.Encode()))
	if err != nil {
		slog.Warn("oauth2 revoke: build request", "strategy", s.name, "error", err.Error())

		return
	}

	authParams(s.cfg.ClientID, s.cfg.ClientSecret, req, s.cfg.AuthHeaderStyle)
	authHeader(req, s.cfg.ClientID, s.cfg.ClientSecret, s.cfg.AuthHeaderStyle)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		slog.Warn("oauth2 revoke: do", "strategy", s.name, "error", err.Error())

		return
	}

	resp.Body.Close()
}

// buildAuthCodeURL constructs the IdP authorize URL with state, redirect_uri, and optional PKCE.
func (s *Strategy) buildAuthCodeURL(state, redirectURI string, pkce *pkceParams) (string, error) {
	u, err := url.Parse(s.cfg.AuthURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", s.cfg.ClientID)
	q.Set("state", state)
	q.Set("redirect_uri", redirectURI)
	if len(s.cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(s.cfg.Scopes, " "))
	}
	if pkce != nil {
		q.Set("code_challenge", pkce.Challenge)
		q.Set("code_challenge_method", pkce.Method)
	}

	u.RawQuery = q.Encode()

	return u.String(), nil
}

// callbackURL returns the absolute redirect_uri. Origin comes from
// CallbackBaseURL, then X-Forwarded-* headers, then r.Host.
func (s *Strategy) callbackURL(r *http.Request) (string, error) {
	scheme, host := s.opts.callbackOrigin(r)

	basePath := s.opts.CallbackBasePath
	if basePath == "" {
		basePath = "/auth/callback"
	}

	u := &url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   path.Join(basePath, s.name),
	}

	return u.String(), nil
}

func (o Options) callbackOrigin(r *http.Request) (string, string) {
	if o.CallbackBaseURL != "" {
		if u, err := url.Parse(o.CallbackBaseURL); err == nil {
			return u.Scheme, u.Host
		}
	}

	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			return proto, host
		}
	}

	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
		scheme = "http"
	}

	return scheme, r.Host
}

func (s *Strategy) setStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.stateCookie.Name,
		Value:    state,
		Path:     s.stateCookie.Path,
		Domain:   s.stateCookie.Domain,
		MaxAge:   s.stateCookie.MaxAge,
		Secure:   s.stateCookie.Secure,
		HttpOnly: s.stateCookie.HttpOnly,
		SameSite: s.stateCookie.SameSite,
	})
}

func (s *Strategy) checkStateCookie(w http.ResponseWriter, r *http.Request, expected string) error {
	c, err := r.Cookie(s.stateCookie.Name)
	if err != nil {
		return err
	}

	// Always clear after one use.
	http.SetCookie(w, &http.Cookie{
		Name:     s.stateCookie.Name,
		Value:    "",
		Path:     s.stateCookie.Path,
		Domain:   s.stateCookie.Domain,
		MaxAge:   -1,
		Secure:   s.stateCookie.Secure,
		HttpOnly: s.stateCookie.HttpOnly,
		SameSite: s.stateCookie.SameSite,
	})

	if c.Value == "" || c.Value != expected {
		return errors.New("state mismatch")
	}

	return nil
}

func (s *Strategy) setVerifierCookie(w http.ResponseWriter, verifier string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.verifierCookie.Name,
		Value:    verifier,
		Path:     s.verifierCookie.Path,
		Domain:   s.verifierCookie.Domain,
		MaxAge:   s.verifierCookie.MaxAge,
		Secure:   s.verifierCookie.Secure,
		HttpOnly: true,
		SameSite: s.verifierCookie.SameSite,
	})
}

func (s *Strategy) readVerifierCookie(r *http.Request) string {
	c, err := r.Cookie(s.verifierCookie.Name)
	if err != nil {
		return ""
	}

	return c.Value
}

func (s *Strategy) clearVerifierCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.verifierCookie.Name,
		Value:    "",
		Path:     s.verifierCookie.Path,
		Domain:   s.verifierCookie.Domain,
		MaxAge:   -1,
		Secure:   s.verifierCookie.Secure,
		HttpOnly: true,
		SameSite: s.verifierCookie.SameSite,
	})
}

func randomState(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}
