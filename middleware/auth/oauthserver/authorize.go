package oauthserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/rakunlabs/ada/middleware/auth/cookie"
	"github.com/rakunlabs/ada/middleware/auth/identity"
)

// csrfCookiePrefix names the consent form cookies. Each authorization
// request gets its own cookie, keyed by a hash of its parameters, so two
// consent tabs do not overwrite each other's token.
const csrfCookiePrefix = "oauth_consent_"

func csrfCookieName(p authorizeParams) string {
	return csrfCookiePrefix + HashSecret(p.values().Encode())[:16]
}

// authorizeParams are the query parameters of an authorization request.
type authorizeParams struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	ResponseType        string `json:"response_type"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Scope               string `json:"scope"`
	Resource            string `json:"resource"`
}

func paramsOf(v url.Values) authorizeParams {
	return authorizeParams{
		ClientID:            v.Get("client_id"),
		RedirectURI:         v.Get("redirect_uri"),
		ResponseType:        v.Get("response_type"),
		State:               v.Get("state"),
		CodeChallenge:       v.Get("code_challenge"),
		CodeChallengeMethod: v.Get("code_challenge_method"),
		Scope:               v.Get("scope"),
		Resource:            v.Get("resource"),
	}
}

func (p authorizeParams) values() url.Values {
	v := url.Values{}
	set := func(k, val string) {
		if val != "" {
			v.Set(k, val)
		}
	}

	set("client_id", p.ClientID)
	set("redirect_uri", p.RedirectURI)
	set("response_type", p.ResponseType)
	set("state", p.State)
	set("code_challenge", p.CodeChallenge)
	set("code_challenge_method", p.CodeChallengeMethod)
	set("scope", p.Scope)
	set("resource", p.Resource)

	return v
}

// userError is shown to the user instead of being sent to the client: the
// redirect URI cannot be trusted yet.
type userError struct{ msg string }

func (e *userError) Error() string { return e.msg }

// check validates an authorization request for the signed-in user.
//
// A *userError means the client or redirect could not be verified. An *Error
// is sent to the verified redirect URI. In both cases the returned request is
// as complete as validation got, so the caller can build the redirect.
func (s *Server) check(ctx context.Context, id *identity.Identity, p authorizeParams) (*AuthorizeRequest, error) {
	if p.ClientID == "" {
		return nil, &userError{"the request names no client"}
	}

	client, err := s.store.GetClient(ctx, p.ClientID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, &userError{"unknown client; register it again"}
		}

		return nil, err
	}

	if p.RedirectURI == "" || !slices.ContainsFunc(client.RedirectURIs, func(u string) bool { return RedirectMatches(u, p.RedirectURI) }) {
		return nil, &userError{"the redirect URI was not registered by this client"}
	}

	req := &AuthorizeRequest{
		Client:              client,
		Identity:            id,
		RedirectURI:         p.RedirectURI,
		State:               p.State,
		CodeChallenge:       p.CodeChallenge,
		CodeChallengeMethod: p.CodeChallengeMethod,
		Resource:            p.Resource,
	}

	switch {
	case p.ResponseType != ResponseTypeCode:
		return req, &Error{"unsupported_response_type", "only the code flow is supported"}
	case !client.AllowsGrant(GrantCode):
		return req, &Error{"unauthorized_client", "the client may not use the code flow"}
	case p.CodeChallenge == "" || p.CodeChallengeMethod != "S256":
		return req, &Error{"invalid_request", "PKCE with S256 is required"}
	case len(p.CodeChallenge) < 43 || len(p.CodeChallenge) > 128:
		return req, &Error{"invalid_request", "malformed code_challenge"}
	}

	if p.Resource != "" && !s.validResource(ctx, p.Resource) {
		return req, &Error{"invalid_target", "unknown resource"}
	}

	scopes, err := s.parseScopes(p.Scope)
	if err != nil {
		return req, err
	}
	req.Scopes = scopes

	if s.cfg.Hooks.Authorize != nil {
		asked := slices.Clone(req.Scopes)

		if err := s.cfg.Hooks.Authorize(ctx, req); err != nil {
			if oe := asOAuthError(err); oe != nil {
				return req, oe
			}

			slog.Error("oauthserver: authorize hook", "error", err.Error())

			return req, &Error{"server_error", "the request could not be authorized"}
		}

		for _, scope := range req.Scopes {
			if !slices.Contains(asked, scope) {
				return req, &Error{"server_error", "authorize hook widened the scopes"}
			}
		}
	}

	return req, nil
}

// validResource reports whether a client may ask a token for resource.
func (s *Server) validResource(ctx context.Context, resource string) bool {
	u, err := url.Parse(resource)
	if err != nil || !u.IsAbs() || u.Fragment != "" || u.RawQuery != "" || u.User != nil {
		return false
	}

	if len(s.cfg.Resources) > 0 {
		return slices.ContainsFunc(s.cfg.Resources, func(base string) bool { return ResourceCovers(base, resource) })
	}

	// No list: the resource must live on this server.
	r, _ := ctx.Value(requestCtxKey{}).(*http.Request)
	if r == nil {
		return false
	}

	iss, err := url.Parse(s.Issuer(r))
	if err != nil || iss.Host == "" {
		return false
	}

	return strings.EqualFold(iss.Scheme, u.Scheme) && strings.EqualFold(iss.Host, u.Host)
}

// ResourceCovers reports whether a token issued for granted may be used on
// target: the same identifier, or a path below it. Trailing slashes are
// ignored.
func ResourceCovers(granted, target string) bool {
	granted = strings.TrimSuffix(granted, "/")
	target = strings.TrimSuffix(target, "/")

	return granted == target || strings.HasPrefix(target, granted+"/")
}

type requestCtxKey struct{}

func (s *Server) withRequest(r *http.Request) context.Context {
	return context.WithValue(r.Context(), requestCtxKey{}, r)
}

// parseScopes splits a scope parameter, applying defaults and the supported
// list.
func (s *Server) parseScopes(raw string) ([]string, error) {
	var scopes []string

	for _, scope := range strings.Fields(raw) {
		if !validScope(scope) {
			return nil, &Error{"invalid_scope", "malformed scope"}
		}
		if len(s.cfg.ScopesSupported) > 0 && !slices.Contains(s.cfg.ScopesSupported, scope) {
			return nil, &Error{"invalid_scope", "unsupported scope " + scope}
		}
		if !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}

	if len(scopes) == 0 {
		scopes = slices.Clone(s.cfg.DefaultScopes)
	}

	return scopes, nil
}

// redirectWith appends parameters to the client's redirect URI.
func redirectWith(redirectURI, state string, v url.Values) string {
	if state != "" {
		v.Set("state", state)
	}

	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}

	return redirectURI + sep + v.Encode()
}

func (s *Server) errorRedirect(r *http.Request, req *AuthorizeRequest, e *Error) string {
	v := url.Values{"error": {e.Code}}
	if e.Description != "" {
		v.Set("error_description", e.Description)
	}
	if iss := s.Issuer(r); iss != "" {
		v.Set("iss", iss)
	}

	return redirectWith(req.RedirectURI, req.State, v)
}

// issueCode stores a code for req and returns the redirect that hands it to
// the client.
func (s *Server) issueCode(r *http.Request, req *AuthorizeRequest) (string, error) {
	code, err := randomString(32)
	if err != nil {
		return "", err
	}

	if err := s.store.SaveCode(r.Context(), &Code{
		Hash:          HashSecret(code),
		ClientID:      req.Client.ID,
		Identity:      req.Identity,
		RedirectURI:   req.RedirectURI,
		CodeChallenge: req.CodeChallenge,
		Scopes:        req.Scopes,
		Resource:      req.Resource,
		Extra:         req.Extra,
		ExpiresAt:     s.now().Add(s.cfg.CodeTTL),
	}); err != nil {
		return "", err
	}

	v := url.Values{"code": {code}}
	v.Set("iss", s.Issuer(r))

	return redirectWith(req.RedirectURI, req.State, v), nil
}

// remembered issues a code at once when the user approved this client before
// for at least these scopes and the same resource. It returns "" to ask.
func (s *Server) remembered(r *http.Request, req *AuthorizeRequest) string {
	cs, ok := s.store.(ConsentStore)
	if !ok {
		return ""
	}

	c, err := cs.GetConsent(r.Context(), req.Identity.Subject, req.Client.ID)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			slog.Warn("oauthserver: load consent", "error", err.Error())
		}

		return ""
	}

	if c.Resource != req.Resource || c.ExtraHash != ExtraHash(req.Extra) {
		return ""
	}
	for _, scope := range req.Scopes {
		if !slices.Contains(c.Scopes, scope) {
			return ""
		}
	}

	next, err := s.issueCode(r, req)
	if err != nil {
		slog.Error("oauthserver: remembered approval", "error", err.Error())

		return ""
	}

	return next
}

// handleAuthorize is the authorization endpoint. GET validates the request
// and shows consent; POST is the consent page answering.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	id := identity.FromContext(r.Context())
	if id == nil || id.Subject == "" {
		s.renderError(w, http.StatusUnauthorized, "sign in first")

		return
	}

	if s.Issuer(r) == "" {
		s.renderError(w, http.StatusBadRequest, "the server address could not be determined; configure the issuer")

		return
	}

	if r.Method == http.MethodPost {
		s.handleApprove(w, r, id)

		return
	}

	req, err := s.check(s.withRequest(r), id, paramsOf(r.URL.Query()))
	if err != nil {
		var ue *userError
		if errors.As(err, &ue) {
			s.renderError(w, http.StatusBadRequest, ue.msg)

			return
		}

		if oe := asOAuthError(err); oe != nil {
			http.Redirect(w, r, s.errorRedirect(r, req, oe), http.StatusFound)

			return
		}

		slog.Error("oauthserver: authorize", "error", err.Error())
		s.renderError(w, http.StatusInternalServerError, "the request could not be checked")

		return
	}

	if next := s.remembered(r, req); next != "" {
		http.Redirect(w, r, next, http.StatusFound)

		return
	}

	if s.cfg.ConsentURL != "" {
		target := s.cfg.ConsentURL
		if strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//") {
			target = s.Issuer(r) + target
		}

		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}

		http.Redirect(w, r, target+sep+r.URL.RawQuery, http.StatusFound)

		return
	}

	token, err := randomString(32)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "the request could not be checked")

		return
	}

	opts := s.csrfCookie(r)
	opts.MaxAge = int(s.cfg.CodeTTL.Seconds()) * 2
	opts.Set(w, r, csrfCookieName(paramsOf(r.URL.Query())), token)

	s.renderConsent(w, r, req, token)
}

// csrfCookie scopes the consent cookie to the public authorize path, which
// differs from the mux path behind a proxy that strips a prefix.
func (s *Server) csrfCookie(r *http.Request) cookie.Options {
	opts := s.cfg.CSRFCookie
	opts.Path = s.Paths().Authorize

	if u, err := url.Parse(s.publicURL(r, s.Paths().Authorize)); err == nil && u.Path != "" {
		opts.Path = u.Path
	}

	return opts
}

// sameOrigin reports whether a browser request comes from this server's own
// origin: Sec-Fetch-Site says so, or (older browsers) Origin equals the
// issuer origin. Requests carrying neither header are not from a browser
// page and cannot ride on a victim's cookies.
func (s *Server) sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
	default:
		return false
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	iss, err := url.Parse(s.Issuer(r))
	if err != nil {
		return false
	}

	return strings.EqualFold(origin, iss.Scheme+"://"+iss.Host)
}

// approveRequest is what a consent page posts back.
type approveRequest struct {
	authorizeParams
	Approve  bool   `json:"approve"`
	Remember bool   `json:"remember"`
	CSRF     string `json:"-"`
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	// A request from another site is refused outright; browsers send this
	// header on every request they make.
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		s.renderError(w, http.StatusForbidden, "cross-site request refused")

		return
	}

	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	asJSON := ct == "application/json"

	var in approveRequest

	if asJSON {
		// A custom consent page posts JSON with the session cookie and no
		// form token. Only the application's own origin may do that: a
		// sibling subdomain is "same-site" and still gets Lax cookies, and a
		// CORS change elsewhere in the app must not turn into forged
		// consent.
		if !s.sameOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"}, false)

			return
		}

		if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"}, false)

			return
		}
	} else {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		if err := r.ParseForm(); err != nil {
			s.renderError(w, http.StatusBadRequest, "invalid form")

			return
		}

		in.authorizeParams = paramsOf(r.PostForm)
		in.Approve = r.PostForm.Get("action") == "approve"
		in.Remember = r.PostForm.Get("remember") != ""

		name := csrfCookieName(in.authorizeParams)

		c, err := r.Cookie(name)
		if err != nil || c.Value == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostForm.Get("csrf"))) != 1 {
			s.renderError(w, http.StatusForbidden, "the consent form expired; start again from the application")

			return
		}

		s.csrfCookie(r).Clear(w, r, name)
	}

	respond := func(next string) {
		if asJSON {
			writeJSON(w, http.StatusOK, map[string]string{"redirect": next}, false)

			return
		}

		http.Redirect(w, r, next, http.StatusSeeOther)
	}

	req, err := s.check(s.withRequest(r), id, in.authorizeParams)
	if err != nil {
		var ue *userError
		switch {
		case errors.As(err, &ue):
			if asJSON {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": ue.msg}, false)
			} else {
				s.renderError(w, http.StatusBadRequest, ue.msg)
			}
		case asOAuthError(err) != nil:
			respond(s.errorRedirect(r, req, asOAuthError(err)))
		default:
			slog.Error("oauthserver: approve", "error", err.Error())
			s.renderError(w, http.StatusInternalServerError, "the request could not be checked")
		}

		return
	}

	if !in.Approve {
		respond(s.errorRedirect(r, req, &Error{"access_denied", "the user declined"}))

		return
	}

	if in.Remember {
		if cs, ok := s.store.(ConsentStore); ok {
			if err := cs.SaveConsent(r.Context(), &Consent{
				Subject:   id.Subject,
				ClientID:  req.Client.ID,
				Scopes:    req.Scopes,
				Resource:  req.Resource,
				ExtraHash: ExtraHash(req.Extra),
				CreatedAt: s.now(),
			}); err != nil {
				slog.Warn("oauthserver: save consent", "error", err.Error())
			}
		}
	}

	next, err := s.issueCode(r, req)
	if err != nil {
		slog.Error("oauthserver: issue code", "error", err.Error())
		s.renderError(w, http.StatusInternalServerError, "the code could not be issued")

		return
	}

	respond(next)
}

// AuthorizeInfo is what a custom consent page shows.
type AuthorizeInfo struct {
	// Client is the client name, ClientID its id.
	Client   string `json:"client,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	// RedirectURI is where the user is sent after answering.
	RedirectURI string   `json:"redirect_uri,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	Resource    string   `json:"resource,omitempty"`
	ServiceName string   `json:"service_name,omitempty"`
	// Extra is what Hooks.Authorize attached, for the page to explain.
	Extra map[string]any `json:"extra,omitempty"`
	// Subject, Name and Email describe the signed-in user.
	Subject string `json:"subject,omitempty"`
	Name    string `json:"name,omitempty"`
	Email   string `json:"email,omitempty"`

	// Redirect is set when no question needs asking: the request failed in
	// a way the client must hear about, or the user approved this client
	// before (Remembered). The page should navigate there.
	Redirect   string `json:"redirect,omitempty"`
	Remembered bool   `json:"remembered,omitempty"`
	// Error is a message for the user.
	Error string `json:"error,omitempty"`
}

// handleAuthorizeInfo tells a custom consent page who asks for what.
func (s *Server) handleAuthorizeInfo(w http.ResponseWriter, r *http.Request) {
	id := identity.FromContext(r.Context())
	if id == nil || id.Subject == "" {
		writeJSON(w, http.StatusUnauthorized, AuthorizeInfo{Error: "sign in first"}, false)

		return
	}

	req, err := s.check(s.withRequest(r), id, paramsOf(r.URL.Query()))
	if err != nil {
		var ue *userError
		switch {
		case errors.As(err, &ue):
			writeJSON(w, http.StatusBadRequest, AuthorizeInfo{Error: ue.msg}, false)
		case asOAuthError(err) != nil:
			oe := asOAuthError(err)
			writeJSON(w, http.StatusOK, AuthorizeInfo{Error: oe.Description, Redirect: s.errorRedirect(r, req, oe)}, false)
		default:
			slog.Error("oauthserver: authorize info", "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, AuthorizeInfo{Error: "the request could not be checked"}, false)
		}

		return
	}

	if next := s.remembered(r, req); next != "" {
		writeJSON(w, http.StatusOK, AuthorizeInfo{Redirect: next, Remembered: true}, false)

		return
	}

	writeJSON(w, http.StatusOK, AuthorizeInfo{
		Client:      req.Client.Name,
		ClientID:    req.Client.ID,
		RedirectURI: req.RedirectURI,
		Scopes:      req.Scopes,
		Resource:    req.Resource,
		ServiceName: s.serviceName(r),
		Extra:       maps.Clone(req.Extra),
		Subject:     id.Subject,
		Name:        id.Name,
		Email:       id.Email,
	}, false)
}

func (s *Server) serviceName(r *http.Request) string {
	if s.cfg.ServiceName != "" {
		return s.cfg.ServiceName
	}

	if u, err := url.Parse(s.Issuer(r)); err == nil && u.Host != "" {
		return u.Host
	}

	return "this application"
}

// pkceMatches checks an S256 code verifier (RFC 7636 §4.6).
func pkceMatches(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}

	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])

	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}
