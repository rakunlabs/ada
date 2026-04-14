// Package session glues an opaque session-ID cookie to an issuer.
//
// On every protected request:
//
//  1. Read the session cookie.
//  2. issuer.Resolve(sessionID) -> Pair.
//  3. If the access token is expired, issuer.Refresh.
//  4. If the refresh token is expired or missing, redirect to login.
//  5. Put the Identity in the request context and call next.
//
// Session never parses JWTs and never calls JWKS. All identity work happens at
// login time inside the strategy.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/issuer"
)

// Session manages the cookie <-> issuer mapping and renders the request side
// of authentication.
type Session struct {
	// Issuer is the token issuer this session uses. Required.
	Issuer issuer.Issuer

	// CookieName is the default session cookie name (e.g. "auth_session").
	CookieName string
	// CookieNameHosts maps host patterns to alternate cookie names.
	CookieNameHosts []HostCookieName

	// Cookie controls Set-Cookie attributes for the session cookie.
	Cookie CookieOptions

	// LoginPath is where unauthenticated requests are redirected.
	LoginPath string
}

// CookieOptions controls the session cookie attributes.
type CookieOptions struct {
	Path     string        `cfg:"path"`
	MaxAge   int           `cfg:"max_age"`
	Domain   string        `cfg:"domain"`
	Secure   bool          `cfg:"secure"`
	HttpOnly bool          `cfg:"http_only"`
	SameSite http.SameSite `cfg:"same_site"`
}

// HostCookieName overrides the cookie name for matching hosts.
type HostCookieName struct {
	Host       string `cfg:"host"`
	Regex      string `cfg:"regex"`
	CookieName string `cfg:"cookie_name"`

	rgx *regexp.Regexp
}

// Init validates configuration and compiles regexes.
func (s *Session) Init() error {
	if s.Issuer == nil {
		return fmt.Errorf("session: nil issuer")
	}
	if s.CookieName == "" {
		s.CookieName = "auth_session"
	}
	if s.Cookie.Path == "" {
		s.Cookie.Path = "/"
	}
	if s.Cookie.SameSite == 0 {
		s.Cookie.SameSite = http.SameSiteLaxMode
	}

	for i, hc := range s.CookieNameHosts {
		if hc.Regex == "" {
			continue
		}

		rgx, err := regexp.Compile(hc.Regex)
		if err != nil {
			return fmt.Errorf("session: cookie_name_hosts[%d].regex: %w", i, err)
		}

		s.CookieNameHosts[i].rgx = rgx
	}

	return nil
}

// CookieNameFor returns the session cookie name for the request, honoring per-
// host overrides and a context-set override.
func (s *Session) CookieNameFor(r *http.Request) string {
	if v := GetCookieName(r.Context()); v != "" {
		return v
	}

	host := r.Host
	for _, hc := range s.CookieNameHosts {
		if hc.rgx != nil {
			if hc.rgx.MatchString(host) {
				return hc.CookieName
			}

			continue
		}

		if hc.Host == host {
			return hc.CookieName
		}
	}

	return s.CookieName
}

// Require returns a middleware that validates the session cookie and injects
// the Identity into the request context. Unauthenticated requests are
// redirected to s.LoginPath (or 401 if the request opted out via
// SetDisableRedirect).
func (s *Session) Require() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := s.resolve(w, r)
			if !ok {
				return
			}

			ctx := identity.WithContext(r.Context(), id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// resolve runs the cookie -> issuer.Resolve -> Refresh sequence. On success it
// returns the live identity. On failure it writes the response (redirect or
// 401) and returns false.
func (s *Session) resolve(w http.ResponseWriter, r *http.Request) (*identity.Identity, bool) {
	cookieName := s.CookieNameFor(r)

	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		s.RedirectToLogin(w, r, true, false)

		return nil, false
	}

	ctx := r.Context()
	pair, err := s.Issuer.Resolve(ctx, cookie.Value)
	if err != nil {
		if errors.Is(err, issuer.ErrNotFound) {
			s.RedirectToLogin(w, r, true, true)

			return nil, false
		}

		slog.Error("session: resolve failed", "error", err.Error())
		s.RedirectToLogin(w, r, true, true)

		return nil, false
	}

	if pair.Access.Expired() {
		newPair, err := s.Issuer.Refresh(ctx, cookie.Value, pair.Refresh.Value)
		if err != nil {
			s.RedirectToLogin(w, r, true, true)

			return nil, false
		}

		pair = newPair
	}

	return pair.Identity, true
}

// IssueCookie writes the session cookie carrying the opaque session ID.
func (s *Session) IssueCookie(w http.ResponseWriter, r *http.Request, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.CookieNameFor(r),
		Value:    sessionID,
		Path:     s.Cookie.Path,
		Domain:   s.Cookie.Domain,
		MaxAge:   s.Cookie.MaxAge,
		Secure:   s.Cookie.Secure,
		HttpOnly: s.Cookie.HttpOnly,
		SameSite: s.Cookie.SameSite,
	})
}

// ClearCookie deletes the session cookie on the client.
func (s *Session) ClearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.CookieNameFor(r),
		Value:    "",
		Path:     s.Cookie.Path,
		Domain:   s.Cookie.Domain,
		MaxAge:   -1,
		Secure:   s.Cookie.Secure,
		HttpOnly: s.Cookie.HttpOnly,
		SameSite: s.Cookie.SameSite,
	})
}

// CurrentSessionID returns the opaque session ID for the request, or "".
func (s *Session) CurrentSessionID(r *http.Request) string {
	c, err := r.Cookie(s.CookieNameFor(r))
	if err != nil {
		return ""
	}

	return c.Value
}

// RedirectToLogin redirects the user to s.LoginPath (or returns 401 if the
// request opted out via SetDisableRedirect).
//
// addRedirectPath, when true, appends ?redirect_path=<original> so the login
// flow can return the user to where they came from.
//
// removeSession, when true, clears the session cookie.
func (s *Session) RedirectToLogin(w http.ResponseWriter, r *http.Request, addRedirectPath, removeSession bool) {
	if removeSession {
		s.ClearCookie(w, r)
	}

	if GetDisableRedirect(r.Context()) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusProxyAuthRequired)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(http.StatusProxyAuthRequired)})

		return
	}

	target := s.LoginPath
	if target == "" {
		target = "/auth/"
	}

	if addRedirectPath {
		target = appendRedirectPath(target, r)
	}

	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}

func appendRedirectPath(loginPath string, r *http.Request) string {
	rp := r.URL.Path
	if r.URL.RawQuery != "" {
		rp = rp + "?" + r.URL.RawQuery
	}

	if rp == "" || rp == "/" {
		return loginPath
	}

	sep := "?"
	if u, err := url.Parse(loginPath); err == nil && u.RawQuery != "" {
		sep = "&"
	}

	return loginPath + sep + "redirect_path=" + url.QueryEscape(rp)
}
