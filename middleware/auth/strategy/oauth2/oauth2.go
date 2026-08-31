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

	"github.com/rakunlabs/ada/middleware/auth/cookie"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
	"github.com/rakunlabs/ada/utils/proxy"
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
	// auto-populate AuthURL, TokenURL, UserInfoURL, RevocationURL, LogoutURL
	// and JWKSURL. Explicitly set fields take precedence over discovered ones.
	IssuerURL string `cfg:"issuer_url"`

	// JWKSURL is the IdP's JSON Web Key Set endpoint, used to verify the
	// id_token signature. Discovered from IssuerURL when left empty.
	JWKSURL string `cfg:"jwks_url"`

	// Audience is the value that must appear in the id_token's aud claim.
	// Defaults to ClientID, which is what OIDC mandates.
	Audience string `cfg:"audience"`

	// SkipIDTokenVerify disables id_token signature and claim verification.
	//
	// Do not set this. It exists for the one legitimate case — an IdP that
	// publishes no key set and is reached only over a trusted channel — and
	// turns the id_token into an unauthenticated assertion of whatever the
	// caller wants. When no key set is reachable and this is false, the
	// strategy refuses to derive an identity from an id_token and requires
	// UserInfoURL instead.
	SkipIDTokenVerify bool `cfg:"skip_id_token_verify"`

	// ClockSkew is the tolerance applied to id_token exp/nbf. Default 60s.
	ClockSkew time.Duration `cfg:"clock_skew"`

	// DisableNonce omits the OIDC nonce from the authorization request.
	//
	// The nonce binds an id_token to the browser session that asked for it.
	// Only turn it off for a provider that rejects the parameter.
	DisableNonce bool `cfg:"disable_nonce"`

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
	// (e.g. "https://app.example.com"). It must contain only an HTTP(S) scheme
	// and host. When empty, the strategy derives the origin from the request.
	CallbackBaseURL string

	// TrustedProxies permits matching immediate peers to supply
	// X-Forwarded-Proto and X-Forwarded-Host. Bare IPs are accepted as
	// single-address prefixes. Forwarded headers from all other peers are
	// ignored in favor of the request's direct Host and TLS state.
	TrustedProxies []string

	// UnsafeTrustAllForwardedHeaders restores the legacy behavior of trusting
	// forwarded origin headers from every peer. Prefer CallbackBaseURL or
	// TrustedProxies.
	UnsafeTrustAllForwardedHeaders bool

	// CallbackBasePath is the path prefix for the callback (e.g. "/auth/callback").
	// The strategy appends "/<name>" to it when building redirect_uri.
	CallbackBasePath string

	// FlowCookie overrides the attributes of the short-lived cookie holding
	// state, nonce and PKCE verifier during an authorization request.
	//
	// The defaults are already the safe ones: HttpOnly, SameSite=Lax, Secure
	// inferred from the request. Set Domain here if the callback lands on a
	// different subdomain than the one that started the flow.
	FlowCookie cookie.Options
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

	flowCookie cookie.Options
	discovery  *discoveryCache

	// keys verifies id_token signatures. Nil when the IdP publishes no key
	// set and none was configured.
	keys *keySet

	// issuer is the value the id_token's iss claim must equal. Taken from the
	// discovery document when available, else from Config.IssuerURL.
	issuer string
}

// New returns an OAuth2 strategy.
//
// Deprecated behaviour note: New swallows discovery failures with a warning so
// a transient IdP outage at boot does not take the process down. Use NewWithContext
// when you want the error.
func New(name string, cfg Config, opts Options) *Strategy {
	s, err := NewWithContext(context.Background(), name, cfg, opts)
	if err != nil {
		slog.Warn("oauth2: discovery failed, using explicit config",
			"strategy", name, "issuer", cfg.IssuerURL, "error", err.Error())
	}

	return s
}

// NewWithContext returns an OAuth2 strategy, performing OIDC discovery under
// the caller's context when cfg.IssuerURL is set.
//
// A discovery failure is reported but never fatal: the returned Strategy is
// always usable with whatever endpoints were configured explicitly.
func NewWithContext(ctx context.Context, name string, cfg Config, opts Options) (*Strategy, error) {
	cfg.Scopes = append([]string(nil), cfg.Scopes...)
	opts.XUserClaims = cloneXUserClaims(opts.XUserClaims.withDefaults())
	opts.TrustedProxies = append([]string(nil), opts.TrustedProxies...)

	if cfg.Audience == "" {
		cfg.Audience = cfg.ClientID
	}

	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = time.Minute
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify}, //nolint:gosec // opt-in
			},
			Timeout: 30 * time.Second,
		}
	}

	s := &Strategy{
		name:       name,
		opts:       opts,
		client:     client,
		flowCookie: defaultFlowCookie(opts.FlowCookie),
		discovery:  newDiscoveryCache(1 * time.Hour),
		issuer:     strings.TrimSuffix(cfg.IssuerURL, "/"),
	}

	var discErr error

	if cfg.IssuerURL != "" {
		doc, err := Discover(ctx, client, cfg.IssuerURL)
		if err != nil {
			discErr = err
		} else {
			s.discovery.set(doc)
			applyDiscovery(&cfg, doc)

			// The document states its own issuer; per OIDC Discovery §4.3 it
			// must match the URL we asked, and it is the value that goes into
			// the iss check.
			if doc.Issuer != "" {
				s.issuer = doc.Issuer
			}
		}
	}

	s.cfg = cfg

	if cfg.JWKSURL != "" {
		s.keys = newKeySet(cfg.JWKSURL, client)
	}

	return s, discErr
}

func cloneXUserClaims(claims XUserClaims) XUserClaims {
	claims.Subject = append([]string(nil), claims.Subject...)
	claims.Email = append([]string(nil), claims.Email...)
	claims.Name = append([]string(nil), claims.Name...)
	claims.Roles = append([]string(nil), claims.Roles...)
	claims.Scope = append([]string(nil), claims.Scope...)

	return claims
}

// Name returns the strategy's URL key.
func (s *Strategy) Name() string { return s.name }

// Discovery returns the cached OIDC discovery document, or nil when discovery
// was not configured, failed, or the cached copy is older than its TTL.
//
// Exposed so a caller can see what the strategy actually resolved — which
// endpoints it will use, and whether a key set was found — instead of
// inferring it from the logs.
func (s *Strategy) Discovery() *DiscoveryDocument {
	return s.discovery.get()
}

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
		q := r.URL.Query()
		if q.Get("code") != "" || q.Get("error") != "" {
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

	_ = resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("oauth2 logout: %s", resp.Status)
	}

	return nil
}

// handleInitiate generates state, nonce and PKCE, stores them in one flow
// cookie, and redirects to AuthURL.
func (s *Strategy) handleInitiate(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	flow := flowState{}

	state, err := randomURLSafe(16)
	if err != nil {
		s.writeInternalError(w, http.StatusInternalServerError, "state_generate", "could not start authorization", err)

		return nil, strategy.OutcomeFailed, nil
	}

	flow.State = state

	if !s.cfg.DisableNonce {
		nonce, err := randomURLSafe(16)
		if err != nil {
			s.writeInternalError(w, http.StatusInternalServerError, "nonce_generate", "could not start authorization", err)

			return nil, strategy.OutcomeFailed, nil
		}

		flow.Nonce = nonce
	}

	var pkce *pkceParams

	if !s.cfg.DisablePKCE {
		pkce, err = newPKCE()
		if err != nil {
			s.writeInternalError(w, http.StatusInternalServerError, "pkce_generate", "could not start authorization", err)

			return nil, strategy.OutcomeFailed, nil
		}

		flow.Verifier = pkce.Verifier
	}

	if err := s.setFlowCookie(w, r, flow); err != nil {
		s.writeInternalError(w, http.StatusInternalServerError, "flow_cookie", "could not start authorization", err)

		return nil, strategy.OutcomeFailed, nil
	}

	redirectURI, err := s.callbackURL(r)
	if err != nil {
		s.writeInternalError(w, http.StatusInternalServerError, "redirect_uri", "could not start authorization", err)

		return nil, strategy.OutcomeFailed, nil
	}

	authURL, err := s.buildAuthCodeURL(flow, redirectURI, pkce)
	if err != nil {
		s.writeInternalError(w, http.StatusInternalServerError, "auth_url", "could not start authorization", err)

		return nil, strategy.OutcomeFailed, nil
	}

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)

	return nil, strategy.OutcomePending, nil
}

// handleCallback validates state, exchanges code (with PKCE verifier), fetches
// userinfo, builds Identity, revokes.
func (s *Strategy) handleCallback(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	q := r.URL.Query()

	flow, err := s.takeFlowCookie(w, r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "state_invalid", "authorization flow expired or cookie missing")

		return nil, strategy.OutcomeFailed, nil
	}

	if err := checkState(flow.State, q.Get("state")); err != nil {
		writeError(w, http.StatusUnauthorized, "state_invalid", "state does not match")

		return nil, strategy.OutcomeFailed, nil
	}

	// Provider denials are callbacks too. Validate and consume the flow before
	// acknowledging one so an attacker cannot inject a plausible denial.
	if e := q.Get("error"); e != "" {
		desc := q.Get("error_description")
		slog.Warn("oauth2 authorization denied", "strategy", s.name, "provider_error", e, "provider_description", desc)
		writeError(w, http.StatusUnauthorized, "authorization_denied", "authorization request was denied")

		return nil, strategy.OutcomeFailed, nil
	}

	// A flow that started with PKCE must finish with it. Letting the verifier
	// go missing would make the protection opt-out by cookie deletion.
	if !s.cfg.DisablePKCE && flow.Verifier == "" {
		writeError(w, http.StatusUnauthorized, "pkce_missing", "code_verifier missing")

		return nil, strategy.OutcomeFailed, nil
	}

	redirectURI, err := s.callbackURL(r)
	if err != nil {
		s.writeInternalError(w, http.StatusInternalServerError, "redirect_uri", "could not complete authorization", err)

		return nil, strategy.OutcomeFailed, nil
	}

	body, err := s.exchangeCode(r.Context(), q.Get("code"), redirectURI, flow.Verifier)
	if err != nil {
		s.writeInternalError(w, http.StatusBadGateway, "code_exchange", "identity provider request failed", err)

		return nil, strategy.OutcomeFailed, nil
	}

	id, accessToken, err := s.identityFromTokenResponse(r.Context(), body, flow.Nonce)
	if err != nil {
		s.writeInternalError(w, http.StatusBadGateway, "identity_extract", "identity provider response was invalid", err)

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
		slog.Warn("oauth2 password exchange failed", "strategy", s.name, "error", err.Error())
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")

		return nil, strategy.OutcomeFailed, nil
	}

	// The password grant has no authorization request and therefore no nonce.
	id, accessToken, err := s.identityFromTokenResponse(r.Context(), tokenBody, "")
	if err != nil {
		s.writeInternalError(w, http.StatusBadGateway, "identity_extract", "identity provider response was invalid", err)

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
	defer func() { _ = resp.Body.Close() }()

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

func (s *Strategy) identityFromTokenResponse(ctx context.Context, body []byte, nonce string) (*identity.Identity, string, error) {
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, "", fmt.Errorf("decode token response: %w", err)
	}

	if tr.AccessToken == "" {
		return nil, "", fmt.Errorf("token response missing access_token")
	}

	claims, err := s.fetchClaims(ctx, tr, nonce)
	if err != nil {
		return nil, tr.AccessToken, err
	}

	id := s.identityFromClaims(claims, tr)

	return id, tr.AccessToken, nil
}

// fetchClaims resolves the user's claims.
//
// An id_token, when present, is always verified: signature against the IdP's
// key set, then iss / aud / exp / nbf / nonce. That is the only thing that
// binds the token to this client and this browser session. The token endpoint
// being reached over TLS proves who *sent* the response, not who it was minted
// for — an id_token issued to a different client of the same IdP travels over
// exactly the same TLS.
//
// Claim source, in order:
//
//  1. UserInfoURL, if configured. Authenticated with the access token, so the
//     response speaks for the user it describes.
//  2. The verified id_token's claims.
//
// With neither — no UserInfoURL and no way to verify the id_token — the login
// fails rather than falling back to an unauthenticated payload.
func (s *Strategy) fetchClaims(ctx context.Context, tr tokenResponse, nonce string) (map[string]any, error) {
	idClaims, err := s.verifyIDToken(ctx, tr.IDToken, nonce)
	if err != nil {
		return nil, err
	}

	if s.cfg.UserInfoURL != "" {
		claims, err := s.fetchUserInfo(ctx, tr.AccessToken)
		if err != nil {
			return nil, err
		}

		// OIDC Core §5.3.2: the userinfo sub must match the id_token sub, or
		// the response describes somebody else.
		if idClaims != nil {
			idSub, _ := idClaims["sub"].(string)
			uiSub, _ := claims["sub"].(string)

			if idSub != "" && uiSub != "" && idSub != uiSub {
				return nil, fmt.Errorf("oauth2: userinfo sub %q does not match id_token sub %q", uiSub, idSub)
			}
		}

		return claims, nil
	}

	if idClaims != nil {
		return idClaims, nil
	}

	if tr.IDToken == "" {
		return nil, errors.New("oauth2: token response has no id_token and no userinfo_url is configured")
	}

	return nil, errors.New("oauth2: cannot verify id_token (no jwks_url) and no userinfo_url is configured")
}

// verifyIDToken returns the verified claims of tr.IDToken, or nil when there
// is no token to verify or verification is deliberately disabled.
func (s *Strategy) verifyIDToken(ctx context.Context, idToken, nonce string) (map[string]any, error) {
	if idToken == "" {
		return nil, nil
	}

	if s.cfg.SkipIDTokenVerify {
		return decodeJWTPayloadUnverified(idToken)
	}

	if s.keys == nil {
		// No key set: we cannot say anything about this token, so we say
		// nothing. fetchClaims decides whether that is fatal.
		return nil, nil
	}

	claims, err := verifyJWT(ctx, s.keys, idToken)
	if err != nil {
		return nil, err
	}

	checks := idTokenChecks{
		Issuer:   s.issuer,
		Audience: s.cfg.Audience,
		Nonce:    nonce,
		Skew:     s.cfg.ClockSkew,
	}

	if err := validateIDToken(claims, checks); err != nil {
		return nil, err
	}

	return claims, nil
}

func (s *Strategy) fetchUserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo: %s", strings.TrimSpace(string(body)))
	}

	// A userinfo endpoint may answer with a signed JWT instead of plain JSON.
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "application/jwt") {
		if s.keys == nil {
			return nil, errors.New("oauth2: signed userinfo response but no jwks_url")
		}

		return verifyJWT(ctx, s.keys, strings.TrimSpace(string(body)))
	}

	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}

	return claims, nil
}

// decodeJWTPayloadUnverified base64-decodes a JWT's claims segment without
// checking the signature. Reachable only via Config.SkipIDTokenVerify.
func decodeJWTPayloadUnverified(token string) (map[string]any, error) {
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

	_ = resp.Body.Close()
}

// buildAuthCodeURL constructs the IdP authorize URL with state, nonce,
// redirect_uri, and optional PKCE.
func (s *Strategy) buildAuthCodeURL(flow flowState, redirectURI string, pkce *pkceParams) (string, error) {
	u, err := url.Parse(s.cfg.AuthURL)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", s.cfg.ClientID)
	q.Set("state", flow.State)
	q.Set("redirect_uri", redirectURI)

	if flow.Nonce != "" {
		q.Set("nonce", flow.Nonce)
	}

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

// callbackURL returns the absolute redirect_uri. A fixed origin wins; otherwise
// forwarded headers are accepted only across the configured proxy boundary.
func (s *Strategy) callbackURL(r *http.Request) (string, error) {
	origin, err := s.opts.callbackOrigin(r)
	if err != nil {
		return "", err
	}

	basePath := s.opts.CallbackBasePath
	if basePath == "" {
		basePath = "/auth/callback"
	}

	u := &url.URL{
		Scheme: origin.Scheme,
		Host:   origin.Host,
		Path:   path.Join(basePath, s.name),
	}

	return u.String(), nil
}

func (o Options) callbackOrigin(r *http.Request) (proxy.Origin, error) {
	if o.CallbackBaseURL != "" {
		origin, err := proxy.ParseOrigin(o.CallbackBaseURL)
		if err != nil {
			return proxy.Origin{}, fmt.Errorf("oauth2: callback base URL: %w", err)
		}

		return origin, nil
	}

	policy, err := proxy.New(o.TrustedProxies...)
	if err != nil {
		return proxy.Origin{}, fmt.Errorf("oauth2: trusted proxies: %w", err)
	}

	if o.UnsafeTrustAllForwardedHeaders {
		return proxy.UnsafeOrigin(r)
	}

	return policy.Origin(r)
}

func (s *Strategy) writeInternalError(w http.ResponseWriter, status int, code, message string, err error) {
	slog.Error("oauth2 request failed", "strategy", s.name, "operation", code, "error", err.Error())
	writeError(w, status, code, message)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}
