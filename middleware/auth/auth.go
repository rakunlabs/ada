// Package auth wires authentication strategies, an opaque-token issuer, and
// the session middleware into a single Auth that can be mounted on an
// ada.Mux. See the design at docs/superpowers/specs/2026-04-15-auth-pluggable-strategies-design.md.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"sync/atomic"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/issuer"
	"github.com/rakunlabs/ada/middleware/auth/issuer/backend"
	"github.com/rakunlabs/ada/middleware/auth/session"
	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

// Mux is the minimal subset of *ada.Mux that Auth depends on. Defining it here
// keeps middleware/auth from importing the parent module while remaining
// drop-in compatible.
type Mux interface {
	GET(pattern string, handler http.HandlerFunc, mw ...func(http.Handler) http.Handler)
	POST(pattern string, handler http.HandlerFunc, mw ...func(http.Handler) http.Handler)
	HandleFunc(pattern string, handler http.HandlerFunc, mw ...func(http.Handler) http.Handler)
}

// Config configures an Auth instance.
type Config struct {
	// Base is the URL prefix for all auth routes. Defaults to "/".
	Base string `cfg:"base"`

	// UI controls the embedded login page.
	UI UIConfig `cfg:"ui"`

	// Cookie controls the session cookie attributes.
	Cookie session.CookieOptions `cfg:"cookie"`

	// CookieName is the session cookie name (default "auth_session").
	CookieName string `cfg:"cookie_name"`

	// CookieNameHosts maps host patterns to alternate cookie names.
	CookieNameHosts []session.HostCookieName `cfg:"cookie_name_hosts"`

	// SuccessCookie is a short-lived cookie set after successful login so the
	// status iframe can detect it from JS. Defaults to "auth_success" with
	// HttpOnly=false and MaxAge=60.
	SuccessCookie SuccessCookie `cfg:"success_cookie"`

	// IssuerConfig controls TTLs and rotation for the default issuer.
	IssuerConfig issuer.Config `cfg:"issuer"`
}

// UIConfig controls the login UI.
type UIConfig struct {
	Title    string `cfg:"title"`
	Subtitle string `cfg:"subtitle"`
	// Icon is a URL or inline SVG data URI for the logo shown above the title.
	// Example: "/static/logo.svg" or "data:image/svg+xml,...".
	// Empty means no icon.
	Icon string `cfg:"icon"`
	// Version is shown at the bottom of the login card (e.g. "v1.2.0").
	// Empty means hidden.
	Version        string `cfg:"version"`
	ExternalFolder bool   `cfg:"external_folder"`
	// SignupFirst, when true, tells the UI to render the signup form on load
	// (for strategies that have a Registrar). Useful for first-run bootstrap
	// flows — flip it back to false once users exist. Ignored when no
	// registered strategy supports signup.
	SignupFirst bool `cfg:"signup_first"`
	// SignupFirstFn, when set, is consulted per request in place of the
	// static SignupFirst field. Useful when the condition is dynamic (e.g.
	// depends on a database query such as "user count == 0"). The function
	// must be safe for concurrent invocation.
	SignupFirstFn func() bool `cfg:"-" json:"-"`

	// Theme maps CSS custom properties to values. Keys may be bare
	// ("primary", "card-bg") or fully qualified ("--auth-primary"); the UI
	// normalizes them to --auth-prefixed properties on :root. Use this for
	// lightweight brand tweaks without shipping a stylesheet. See
	// _ui/src/style/global.css for the full token list.
	Theme map[string]string `cfg:"theme"`

	// CustomCSSURL, when set, is appended to the login page as
	// <link rel="stylesheet">. Use this for arbitrary restyling beyond the
	// Theme token knobs. The URL is used verbatim (make sure your app serves
	// it, e.g. behind a static-file handler).
	CustomCSSURL string `cfg:"custom_css_url"`
}

// SuccessCookie is the post-login indicator cookie (read by the status iframe).
type SuccessCookie struct {
	Name     string        `cfg:"name"`
	MaxAge   int           `cfg:"max_age"`
	Path     string        `cfg:"path"`
	Domain   string        `cfg:"domain"`
	Secure   bool          `cfg:"secure"`
	SameSite http.SameSite `cfg:"same_site"`
}

func (sc SuccessCookie) withDefaults() SuccessCookie {
	if sc.Name == "" {
		sc.Name = "auth_success"
	}
	if sc.MaxAge == 0 {
		sc.MaxAge = 60
	}
	if sc.Path == "" {
		sc.Path = "/"
	}
	if sc.SameSite == 0 {
		sc.SameSite = http.SameSiteLaxMode
	}

	return sc
}

// Auth is the top-level middleware: registers /auth/* routes and exposes
// Require() to guard downstream routes. The session and issuer are owned and
// wired automatically; advanced callers can pass overrides via With*.
type Auth struct {
	cfg Config

	// liveUI is the atomically-swappable UI config, read by handleInfo per
	// request. Initialized from cfg.UI in New and replaced by SetUI.
	liveUI atomic.Pointer[UIConfig]

	registry *strategy.Registry
	session  *session.Session
	issuer   issuer.Issuer
	ui       *uiHandler
	status   *statusHandler

	resolvedPaths paths
}

// paths holds the materialized URL paths (with Base applied).
type paths struct {
	Root     string // /
	UI       string // /login (served as folder when ExternalFolder is false)
	Info     string // /login/info
	Me       string // /login/me
	Login    string // /login/pass/{strategy}
	Register string // /login/register/{strategy}
	Callback string // /login/callback/{strategy}
	Refresh  string // /login/refresh
	Logout   string // /logout
	Status   string // /login/status
}

// New returns an Auth bound to the given config. Strategies must be registered
// via Strategy() before Init().
func New(cfg Config) *Auth {
	cfg.SuccessCookie = cfg.SuccessCookie.withDefaults()

	cfg.Base = "/" + strings.Trim(cfg.Base, "/")

	a := &Auth{
		cfg:      cfg,
		registry: strategy.NewRegistry(),
	}

	uiCopy := cfg.UI
	a.liveUI.Store(&uiCopy)

	a.resolvedPaths = paths{
		Root:     cfg.Base,
		UI:       cfg.Base + "login",
		Info:     cfg.Base + "login/info",
		Me:       cfg.Base + "login/me",
		Login:    cfg.Base + "login/pass/{strategy}",
		Register: cfg.Base + "login/register/{strategy}",
		Callback: cfg.Base + "login/callback/{strategy}",
		Refresh:  cfg.Base + "login/refresh",
		Logout:   cfg.Base + "logout",
		Status:   cfg.Base + "login/status",
	}

	return a
}

// Strategy registers an authenticator. Returns the Auth for chaining.
// Panics on duplicate names; configure once at startup.
func (a *Auth) Strategy(s strategy.Authenticator) *Auth {
	if err := a.registry.Add(s); err != nil {
		panic(fmt.Errorf("auth: register strategy: %w", err))
	}

	return a
}

// WithIssuer overrides the default issuer. Must be called before Init.
func (a *Auth) WithIssuer(i issuer.Issuer) *Auth {
	a.issuer = i

	return a
}

// WithBackend overrides the default issuer backend. Ignored if WithIssuer is
// used. Must be called before Init.
func (a *Auth) WithBackend(b issuer.Backend) *Auth {
	if a.issuer != nil {
		return a
	}

	a.issuer = issuer.NewDefault(b, a.cfg.IssuerConfig)

	return a
}

// WithSessionStore overrides the underlying sessionstore used by the default
// issuer backend. Ignored if WithIssuer or WithBackend is used.
func (a *Auth) WithSessionStore(store sessionstore.Store) *Auth {
	if a.issuer != nil {
		return a
	}

	cookieName := a.cfg.CookieName
	if cookieName == "" {
		cookieName = "auth_session"
	}

	a.issuer = issuer.NewDefault(backend.NewSessionStore(store, cookieName), a.cfg.IssuerConfig)

	return a
}

// Init validates configuration and prepares the middleware. Must be called
// after all Strategy registrations and before Mount/Require.
func (a *Auth) Init(_ context.Context) error {
	if a.issuer == nil {
		// Sensible default: in-memory issuer backend.
		a.issuer = issuer.NewDefault(backend.NewMemory(), a.cfg.IssuerConfig)
	}

	a.session = &session.Session{
		Issuer:          a.issuer,
		CookieName:      a.cfg.CookieName,
		CookieNameHosts: a.cfg.CookieNameHosts,
		Cookie:          a.cfg.Cookie,
		LoginPath:       a.resolvedPaths.Root,
	}

	if err := a.session.Init(); err != nil {
		return fmt.Errorf("auth: session init: %w", err)
	}

	ui, err := newUIHandler(a.cfg)
	if err != nil {
		return fmt.Errorf("auth: ui: %w", err)
	}
	a.ui = ui

	st, err := newStatusHandler()
	if err != nil {
		return fmt.Errorf("auth: status: %w", err)
	}
	a.status = st

	return nil
}

// Require returns a middleware that gates downstream routes behind a valid
// session.
func (a *Auth) Require() func(http.Handler) http.Handler {
	if a.session == nil {
		panic("auth: Require called before Init")
	}

	return a.session.Require()
}

// Mount registers /auth/* routes on the given mux.
func (a *Auth) Mount(mux Mux) {
	if a.session == nil {
		panic("auth: Mount called before Init")
	}

	p := a.resolvedPaths

	mux.GET(p.Info, a.handleInfo)
	mux.GET(p.Me, a.handleMe)
	mux.GET(p.Login, a.handleLogin)
	mux.POST(p.Login, a.handleLogin)
	mux.POST(p.Register, a.handleRegister)
	mux.GET(p.Callback, a.handleLogin)
	mux.POST(p.Refresh, a.handleRefresh)
	mux.POST(p.Logout, a.handleLogout)
	mux.GET(p.Status, a.handleStatus)

	if a.cfg.UI.ExternalFolder {
		// External folder: leave the base path to the parent mux. Nothing to do.
		return
	}

	mux.HandleFunc(strings.TrimSuffix(p.Root, "/")+"/login", func(w http.ResponseWriter, r *http.Request) {
		// redirect to the same path with trailing slash, so the folder handler can serve the index.html for /login.
		http.Redirect(w, r, p.UI+"/", http.StatusFound)
	})
	mux.HandleFunc(strings.TrimSuffix(p.Root, "/")+"/login/*", a.handleUI)
}

// Issuer exposes the issuer for advanced callers (e.g. CLI tools that need to
// revoke sessions out-of-band).
func (a *Auth) Issuer() issuer.Issuer { return a.issuer }

// Session exposes the session for advanced callers.
func (a *Auth) Session() *session.Session { return a.session }

// Registry exposes the strategy registry.
func (a *Auth) Registry() *strategy.Registry { return a.registry }

// SetUI replaces the UI configuration read by handleInfo. The update is
// atomic: in-flight /login/info requests observe either the old or the new
// value, never a partial mix. Intended for settings-driven hot reload.
//
// Note: ExternalFolder is excluded from the swap — it affects route mounting
// and is fixed at Init time.
func (a *Auth) SetUI(cfg UIConfig) {
	// Preserve ExternalFolder from the original cfg — it drives mounting.
	cfg.ExternalFolder = a.cfg.UI.ExternalFolder
	uiCopy := cfg
	a.liveUI.Store(&uiCopy)
}

// currentUI returns the live UI snapshot. Always non-nil after New.
func (a *Auth) currentUI() UIConfig {
	if p := a.liveUI.Load(); p != nil {
		return *p
	}
	return a.cfg.UI
}

// /////////////////////////////////////////////////////////////////////////////
// Handlers
// /////////////////////////////////////////////////////////////////////////////

// infoResponse is the JSON returned by GET /auth/info.
type infoResponse struct {
	Title        string                `json:"title"`
	Subtitle     string                `json:"subtitle,omitempty"`
	Icon         string                `json:"icon,omitempty"`
	Version      string                `json:"version,omitempty"`
	SignupFirst  bool                  `json:"signup_first,omitempty"`
	Theme        map[string]string     `json:"theme,omitempty"`
	CustomCSSURL string                `json:"custom_css_url,omitempty"`
	Strategies   []strategy.Descriptor `json:"strategies"`
}

func (a *Auth) handleInfo(w http.ResponseWriter, _ *http.Request) {
	ui := a.currentUI()
	signupFirst := ui.SignupFirst
	if ui.SignupFirstFn != nil {
		signupFirst = ui.SignupFirstFn()
	}
	resp := infoResponse{
		Title:        ui.Title,
		Subtitle:     ui.Subtitle,
		Icon:         toIconSrc(ui.Icon),
		Version:      ui.Version,
		SignupFirst:  signupFirst,
		Theme:        ui.Theme,
		CustomCSSURL: ui.CustomCSSURL,
		Strategies:   a.registry.Descriptors(),
	}
	if resp.Title == "" {
		resp.Title = "Sign in"
	}

	for i := range resp.Strategies {
		// Apply Base prefix to the LoginURL and (if present) RegisterURL.
		resp.Strategies[i].LoginURL = path.Join(a.cfg.Base, "login", "pass", resp.Strategies[i].Name)

		if resp.Strategies[i].Register != nil {
			resp.Strategies[i].Register.URL = path.Join(a.cfg.Base, "login", "register", resp.Strategies[i].Name)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (a *Auth) handleMe(w http.ResponseWriter, r *http.Request) {
	id, ok := a.identity(w, r)
	if !ok {
		return
	}

	writeJSON(w, http.StatusOK, id)
}

func (a *Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("strategy")
	if name == "" {
		writeError(w, http.StatusNotFound, "unknown_strategy", "no strategy in path")

		return
	}

	auth := a.registry.Get(name)
	if auth == nil {
		writeError(w, http.StatusNotFound, "unknown_strategy", "strategy not registered")

		return
	}

	id, outcome, err := auth.Login(w, r)
	if err != nil {
		slog.Error("auth: strategy login error", "strategy", name, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "login_failed", err.Error())

		return
	}

	switch outcome {
	case strategy.OutcomePending, strategy.OutcomeFailed:
		// Strategy already wrote the response.
		return

	case strategy.OutcomeContinue:
		// fall through to issue session
	default:
		writeError(w, http.StatusInternalServerError, "unknown_outcome", "strategy returned unknown outcome")

		return
	}

	if id == nil {
		writeError(w, http.StatusInternalServerError, "no_identity", "strategy returned no identity")

		return
	}

	pair, err := a.issuer.Issue(r.Context(), id)
	if err != nil {
		slog.Error("auth: issue session", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "issue_failed", err.Error())

		return
	}

	a.session.IssueCookie(w, r, pair.SessionID)
	a.setSuccessCookie(w)

	a.respondAfterLogin(w, r, name)
}

func (a *Auth) handleRegister(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("strategy")
	if name == "" {
		writeError(w, http.StatusNotFound, "unknown_strategy", "no strategy in path")

		return
	}

	auth := a.registry.Get(name)
	if auth == nil {
		writeError(w, http.StatusNotFound, "unknown_strategy", "strategy not registered")

		return
	}

	reg, ok := auth.(strategy.Registerer)
	if !ok {
		writeError(w, http.StatusNotFound, "signup_disabled", "strategy does not support signup")

		return
	}

	id, outcome, err := reg.Register(w, r)
	if err != nil {
		slog.Error("auth: strategy register error", "strategy", name, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "register_failed", err.Error())

		return
	}

	switch outcome {
	case strategy.OutcomePending, strategy.OutcomeFailed:
		return
	case strategy.OutcomeContinue:
		// fall through to issue session
	default:
		writeError(w, http.StatusInternalServerError, "unknown_outcome", "strategy returned unknown outcome")

		return
	}

	if id == nil {
		writeError(w, http.StatusInternalServerError, "no_identity", "strategy returned no identity")

		return
	}

	pair, err := a.issuer.Issue(r.Context(), id)
	if err != nil {
		slog.Error("auth: issue session", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "issue_failed", err.Error())

		return
	}

	a.session.IssueCookie(w, r, pair.SessionID)
	a.setSuccessCookie(w)

	a.respondAfterLogin(w, r, name)
}

func (a *Auth) handleRefresh(w http.ResponseWriter, r *http.Request) {
	sessionID := a.session.CurrentSessionID(r)
	if sessionID == "" {
		writeError(w, http.StatusUnauthorized, "no_session", "no session cookie")

		return
	}

	pair, err := a.issuer.Resolve(r.Context(), sessionID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "no_session", err.Error())

		return
	}

	newPair, err := a.issuer.Refresh(r.Context(), sessionID, pair.Refresh.Value)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "refresh_failed", err.Error())

		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": newPair.SessionID,
		"identity":   newPair.Identity,
	})
}

func (a *Auth) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := a.session.CurrentSessionID(r)
	if sessionID == "" {
		w.WriteHeader(http.StatusNoContent)

		return
	}

	pair, _ := a.issuer.Resolve(r.Context(), sessionID)

	if pair != nil && pair.Identity != nil {
		if auth := a.registry.Get(pair.Identity.Provider); auth != nil {
			if err := auth.Logout(r.Context(), pair.Identity); err != nil {
				slog.Warn("auth: strategy logout", "strategy", pair.Identity.Provider, "error", err.Error())
			}
		}
	}

	if err := a.issuer.Revoke(r.Context(), sessionID); err != nil {
		slog.Warn("auth: revoke session", "error", err.Error())
	}

	a.session.ClearCookie(w, r)
	a.removeSuccessCookie(w)

	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) handleStatus(w http.ResponseWriter, r *http.Request) {
	a.status.serve(w, r, a.cfg.SuccessCookie.Name)
}

func (a *Auth) handleUI(w http.ResponseWriter, r *http.Request) {
	a.ui.serve(w, r)
}

// /////////////////////////////////////////////////////////////////////////////
// Helpers
// /////////////////////////////////////////////////////////////////////////////

func (a *Auth) identity(w http.ResponseWriter, r *http.Request) (*identity.Identity, bool) {
	if id := identity.FromContext(r.Context()); id != nil {
		return id, true
	}

	// Resolve directly if Require() was not in the chain.
	sessionID := a.session.CurrentSessionID(r)
	if sessionID == "" {
		writeError(w, http.StatusUnauthorized, "no_session", "no session cookie")

		return nil, false
	}

	pair, err := a.issuer.Resolve(r.Context(), sessionID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "no_session", err.Error())

		return nil, false
	}

	return pair.Identity, true
}

func (a *Auth) respondAfterLogin(w http.ResponseWriter, r *http.Request, strategyName string) {
	redirectPath := r.URL.Query().Get("redirect_path")

	// JSON callers (typically the local strategy form) get a JSON OK; browsers
	// coming through OAuth2 callback get the close-popup script (matches today).
	if r.Method == http.MethodPost && wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{
			"strategy":      strategyName,
			"redirect_path": redirectPath,
		})

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write([]byte("<script>window.close();</script>")); err != nil {
		slog.Debug("auth: write close-popup", "error", err.Error())
	}
}

func wantsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")

	return strings.Contains(accept, "application/json") ||
		strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
}

func (a *Auth) setSuccessCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cfg.SuccessCookie.Name,
		Value:    "true",
		Path:     a.cfg.SuccessCookie.Path,
		Domain:   a.cfg.SuccessCookie.Domain,
		MaxAge:   a.cfg.SuccessCookie.MaxAge,
		Secure:   a.cfg.SuccessCookie.Secure,
		SameSite: a.cfg.SuccessCookie.SameSite,
		HttpOnly: false,
	})
}

func (a *Auth) removeSuccessCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cfg.SuccessCookie.Name,
		Value:    "",
		Path:     a.cfg.SuccessCookie.Path,
		Domain:   a.cfg.SuccessCookie.Domain,
		MaxAge:   -1,
		Secure:   a.cfg.SuccessCookie.Secure,
		SameSite: a.cfg.SuccessCookie.SameSite,
		HttpOnly: false,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("auth: write json", "error", err.Error())
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{
		"error":   code,
		"message": message,
	})
}

// toIconSrc converts the Icon config value into an <img> src:
//   - starts with "data:" or "http" or "./" → pass through as-is
//   - starts with "<" (inline SVG) → encode as data:image/svg+xml;base64
//   - empty → empty
func toIconSrc(icon string) string {
	icon = strings.TrimSpace(icon)
	if icon == "" {
		return ""
	}

	if strings.HasPrefix(icon, "data:") ||
		strings.HasPrefix(icon, "http://") ||
		strings.HasPrefix(icon, "https://") ||
		strings.HasPrefix(icon, "./") ||
		strings.HasPrefix(icon, "/") {
		return icon
	}

	if strings.HasPrefix(icon, "<") {
		return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(icon))
	}

	// Treat as a relative path in the embedded UI folder.
	return "./" + icon
}
