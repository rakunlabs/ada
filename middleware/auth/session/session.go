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
	"strings"

	"github.com/rakunlabs/ada/middleware/auth/cookie"
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

	// ChallengeFn supplies the WWW-Authenticate value sent with the 401
	// that replaces the login redirect for requests opting out via
	// SetDisableRedirect. RFC 9110 §15.5.2 requires a 401 to name a
	// scheme the client can use.
	//
	// It is a function rather than a string because the set of usable
	// schemes follows the registered strategies, which can be swapped at
	// runtime (see Registry.Replace) — a value captured at construction
	// would advertise whatever happened to be configured at boot.
	//
	// Auth wires this to the strategy registry. Leaving it nil, or
	// returning "", omits the header: a cookie-only deployment has no
	// scheme to offer.
	ChallengeFn func() string

	// RejectFn, when set, can veto an otherwise valid session. Auth uses it
	// to refuse a half-authenticated identity that has not cleared its second
	// factor, so a pending session ID pasted into the session cookie is not a
	// way around MFA.
	RejectFn func(*identity.Identity) bool
}

// CookieOptions controls the session cookie attributes.
//
// It is an alias for cookie.Options so the session cookie, the post-login
// success cookie and the OAuth2 flow cookies cannot drift apart in their
// defaults. HttpOnly is on unless DisableHTTPOnly is set, and Secure follows
// the request scheme unless pinned.
type CookieOptions = cookie.Options

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

	s.Cookie = s.Cookie.WithDefaults()
	if err := s.Cookie.Validate(); err != nil {
		return fmt.Errorf("session: %w", err)
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

	if s.RejectFn != nil && s.RejectFn(pair.Identity) {
		s.RedirectToLogin(w, r, true, true)

		return nil, false
	}

	return pair.Identity, true
}

// IssueCookie writes the session cookie carrying the opaque session ID.
func (s *Session) IssueCookie(w http.ResponseWriter, r *http.Request, sessionID string) {
	s.Cookie.Set(w, r, s.CookieNameFor(r), sessionID)
}

// ClearCookie deletes the session cookie on the client.
func (s *Session) ClearCookie(w http.ResponseWriter, r *http.Request) {
	s.Cookie.Clear(w, r, s.CookieNameFor(r))
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
		s.writeUnauthorized(w)

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

// writeUnauthorized answers a request that opted out of the login
// redirect.
//
// The status is 401. Earlier versions sent 407 Proxy Authentication
// Required, which was wrong twice over: this is an origin server, not a
// proxy, and RFC 9110 §15.5.8 pairs 407 with a Proxy-Authenticate header
// that was never sent. Clients keying off the status — the reason a caller
// opts out of the redirect in the first place — saw a code that told them
// to authenticate with an upstream proxy that does not exist.
func (s *Session) writeUnauthorized(w http.ResponseWriter) {
	if s.ChallengeFn != nil {
		if challenge := s.ChallengeFn(); challenge != "" {
			w.Header().Set("WWW-Authenticate", challenge)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "unauthorized",
		"message": "invalid or missing credentials",
	})
}

func appendRedirectPath(loginPath string, r *http.Request) string {
	rp := r.URL.Path
	if r.URL.RawQuery != "" {
		rp = rp + "?" + r.URL.RawQuery
	}

	rp = SafeRedirectPath(rp)
	if rp == "" || rp == "/" {
		return loginPath
	}

	sep := "?"
	if u, err := url.Parse(loginPath); err == nil && u.RawQuery != "" {
		sep = "&"
	}

	return loginPath + sep + "redirect_path=" + url.QueryEscape(rp)
}

// SafeRedirectPath returns raw if it is a same-origin relative target, or ""
// if it is not.
//
// The login flow round-trips this value through a query parameter that anyone
// can craft, and the UI hands it straight to window.location. Without this
// check, /login?redirect_path=https://evil.example/ turns the login page into
// an open redirect that borrows the deployment's own domain for a phishing
// hop.
//
// Accepted: a path starting with a single "/", optionally followed by a query
// and fragment. Everything else is rejected, in particular:
//
//   - absolute URLs, with or without a scheme
//   - protocol-relative "//host/path"
//   - backslash variants, which some browsers normalise to "/"
//   - anything containing a control character, which can smuggle a header
//     break into a Location value
func SafeRedirectPath(raw string) string {
	if raw == "" {
		return ""
	}

	for _, c := range raw {
		if c < 0x20 || c == 0x7f {
			return ""
		}
	}

	// "/\evil.com" and "/\/evil.com" are treated as protocol-relative by
	// some browsers; normalising first makes the prefix test meaningful.
	normalized := strings.ReplaceAll(raw, `\`, "/")

	if !strings.HasPrefix(normalized, "/") || strings.HasPrefix(normalized, "//") {
		return ""
	}

	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	// A relative reference must carry neither an authority nor a scheme.
	if u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return ""
	}

	return raw
}
