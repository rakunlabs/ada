// Package auth wires authentication strategies, an opaque-token issuer, and
// the session middleware into a single Auth that can be mounted on an
// ada.Mux. See the design at docs/superpowers/specs/2026-04-15-auth-pluggable-strategies-design.md.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/rakunlabs/ada/middleware/auth/cookie"
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
//
// It is expressed in terms of HandleWithMethod rather than the GET/POST/
// HandleFunc verbs because those are generic on *ada.Mux, and Go interfaces can
// neither declare generic methods nor be satisfied by them. HandleWithMethod is
// the non-generic primitive kept for exactly this purpose; an empty method
// registers a catch-all handler, matching ada.Mux.HandleFunc.
type Mux interface {
	HandleWithMethod(method, pattern string, handler http.HandlerFunc, mw ...func(http.Handler) http.Handler)
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

	// MFA tunes the second-factor step. Only consulted when a SecondFactor is
	// registered via WithSecondFactor.
	MFA MFAConfig `cfg:"mfa"`

	// DisableRequestAuth turns off request-credential authentication in
	// Require(), restoring cookie-only gating.
	//
	// By default Require() lets any strategy implementing
	// strategy.RequestAuthenticator (e.g. apikey) authenticate a protected
	// request straight from its headers. Disable it if a deployment
	// registers such a strategy solely to mint sessions at the login
	// endpoint and wants protected routes to stay browser-only.
	DisableRequestAuth bool `cfg:"disable_request_auth"`
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
	Name     string            `cfg:"name"`
	MaxAge   int               `cfg:"max_age"`
	Path     string            `cfg:"path"`
	Domain   string            `cfg:"domain"`
	Secure   cookie.SecureMode `cfg:"secure"`
	SameSite http.SameSite     `cfg:"same_site"`
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

	if sc.Secure == "" {
		sc.Secure = cookie.SecureAuto
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

	// backend is the storage the default issuer was built on, kept so the
	// short-lived pending-login issuer can share it.
	backend issuer.Backend

	secondFactor  SecondFactor
	pendingIssuer issuer.Issuer

	// deferred holds the first error produced by a chained With* call, so the
	// builder can stay fluent and still fail loudly at Init.
	deferred  error
	closeOnce sync.Once
	closeErr  error
	closing   atomic.Bool
	retiredMu sync.Mutex
	retired   []strategy.Authenticator
	closed    []strategy.Authenticator

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
	MFA      string // /login/mfa
	Logout   string // /logout
	Status   string // /login/status
}

// New returns an Auth bound to the given config. Strategies must be registered
// via Strategy() before Init().
func New(cfg Config) *Auth {
	cfg.SuccessCookie = cfg.SuccessCookie.withDefaults()
	cfg.MFA = cfg.MFA.withDefaults()

	// Normalize Base to always start and end with "/". The path builders
	// below concatenate as `cfg.Base + "login/..."` and expect Base to
	// carry a trailing slash; without this, a non-root Base like
	// "/api/v1/" would yield "/api/v1login/info".
	cfg.Base = "/" + strings.Trim(cfg.Base, "/")
	if !strings.HasSuffix(cfg.Base, "/") {
		cfg.Base += "/"
	}

	a := &Auth{
		cfg:      cfg,
		registry: strategy.NewRegistry(),
	}
	a.registry.SetRemovalHook(a.retainStrategy)

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
		MFA:      cfg.Base + "login/mfa",
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

	a.backend = b
	a.issuer = issuer.NewDefault(b, a.cfg.IssuerConfig)

	return a
}

// WithSessionStore persists sessions in a sessionstore.Store (file, redis)
// instead of process memory. Ignored if WithIssuer or WithBackend is used.
//
// The store must implement sessionstore.DirectStore; both bundled stores do.
// A store that cannot address records by raw session ID is rejected at Init
// rather than silently dropping every write.
//
// Pass WithPairCipher to encrypt the stored pair at rest — strongly
// recommended, since it carries live tokens and the full identity.
func (a *Auth) WithSessionStore(store sessionstore.Store, opts ...backend.SessionStoreOption) *Auth {
	if a.issuer != nil {
		return a
	}

	b, err := backend.NewSessionStore(store, opts...)
	if err != nil {
		if a.deferred == nil {
			a.deferred = fmt.Errorf("auth: session store: %w", err)
		}

		return a
	}

	a.backend = b
	a.issuer = issuer.NewDefault(b, a.cfg.IssuerConfig)

	return a
}

// Init validates configuration and prepares the middleware. Must be called
// after all Strategy registrations and before Mount/Require.
func (a *Auth) Init(_ context.Context) error {
	if a.deferred != nil {
		return a.deferred
	}

	if a.issuer == nil {
		// Sensible default: in-memory issuer backend.
		a.backend = backend.NewMemory()
		a.issuer = issuer.NewDefault(a.backend, a.cfg.IssuerConfig)
	}

	// A parked login gets its own issuer so it expires on the MFA window
	// rather than the session window — minutes, not days.
	if a.secondFactor != nil && a.backend != nil {
		a.pendingIssuer = issuer.NewDefault(a.backend, issuer.Config{
			AccessTTL:  a.cfg.MFA.TTL,
			RefreshTTL: a.cfg.MFA.TTL,
			// Rotation would invalidate the refresh token the attempt counter
			// is written through.
			DisableRefreshRotation: true,
		})
	}

	a.session = &session.Session{
		Issuer:          a.issuer,
		CookieName:      a.cfg.CookieName,
		CookieNameHosts: a.cfg.CookieNameHosts,
		Cookie:          a.cfg.Cookie,
		// Unauthenticated callers are redirected to the login UI, not the
		// bare base prefix.
		LoginPath: a.resolvedPaths.UI,
		// Callers that opted out of the redirect get a 401, which has to
		// name a scheme they can actually use. Read through the registry
		// on each 401 so a Registry.Replace is reflected immediately.
		ChallengeFn: a.registry.Challenge,
		RejectFn:    PendingIdentity,
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
// credential.
//
// Two credential families are accepted, in this order:
//
//  1. Credentials carried on the request itself, resolved by any registered
//     strategy implementing strategy.RequestAuthenticator — an API key
//     header being the usual case. No session is created; the identity is
//     attached to the request context and that is the end of it.
//
//  2. The session cookie, as before. Unauthenticated requests are
//     redirected to the login UI (or answered with 401 when the request
//     opted out via session.SetDisableRedirect).
//
// Order matters. A programmatic client that presents an API key must not
// be answered with a redirect to an interactive login page it cannot
// complete, and a client that presents both a key and a stale cookie
// should be authorized as the key it deliberately sent.
//
// A request that carries request credentials which turn out to be invalid
// is rejected outright rather than falling through to the cookie: silently
// downgrading a rejected token to "anonymous" and then redirecting hides
// the real failure behind a login page.
//
// Set Config.DisableRequestAuth to keep the cookie-only behavior.
func (a *Auth) Require() func(http.Handler) http.Handler {
	if a.session == nil {
		panic("auth: Require called before Init")
	}

	sessionMW := a.session.Require()
	if a.cfg.DisableRequestAuth {
		return sessionMW
	}

	return func(next http.Handler) http.Handler {
		// Build the session chain once, not per request: session.Require
		// allocates a handler and we would otherwise pay for it on every
		// request that falls through to the cookie.
		sessionNext := sessionMW(next)

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := a.registry.AuthenticateRequest(r.Context(), r)

			switch {
			case errors.Is(err, strategy.ErrNoCredentials):
				sessionNext.ServeHTTP(w, r)
			case errors.Is(err, strategy.ErrInvalidCredentials):
				a.writeUnauthorized(w)
			case err != nil:
				slog.Error("auth: request authentication failed", "error", err.Error())
				writeError(w, http.StatusInternalServerError, "auth_error", "authentication error")
			default:
				next.ServeHTTP(w, r.WithContext(identity.WithContext(r.Context(), id)))
			}
		})
	}
}

// writeUnauthorized rejects a request that presented bad credentials.
// WWW-Authenticate advertises the schemes the registered strategies
// actually accept, so a client can discover how to authenticate instead of
// guessing from a bare status code.
func (a *Auth) writeUnauthorized(w http.ResponseWriter) {
	if challenge := a.registry.Challenge(); challenge != "" {
		w.Header().Set("WWW-Authenticate", challenge)
	}

	writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or missing credentials")
}

// Mount registers /auth/* routes on the given mux.
func (a *Auth) Mount(mux Mux) {
	if a.session == nil {
		panic("auth: Mount called before Init")
	}

	p := a.resolvedPaths

	// Propagate the resolved callback base to every strategy that needs it
	// (e.g. OAuth2 to construct redirect_uri). Strategies with an explicit
	// override keep their value; see strategy.CallbackBinder for the contract.
	callbackBase := strings.TrimSuffix(a.cfg.Base, "/") + "/login/callback"
	for _, s := range a.registry.List() {
		if b, ok := s.(strategy.CallbackBinder); ok {
			b.SetCallbackBasePath(callbackBase)
		}
	}

	mux.HandleWithMethod(http.MethodGet, p.Info, a.handleInfo)
	mux.HandleWithMethod(http.MethodGet, p.Me, a.handleMe)
	mux.HandleWithMethod(http.MethodGet, p.Login, a.handleLogin)
	mux.HandleWithMethod(http.MethodPost, p.Login, a.handleLogin)
	mux.HandleWithMethod(http.MethodPost, p.Register, a.handleRegister)
	mux.HandleWithMethod(http.MethodGet, p.Callback, a.handleLogin)
	mux.HandleWithMethod(http.MethodPost, p.Refresh, a.handleRefresh)
	mux.HandleWithMethod(http.MethodPost, p.MFA, a.handleMFA)
	mux.HandleWithMethod(http.MethodPost, p.Logout, a.handleLogout)
	mux.HandleWithMethod(http.MethodGet, p.Status, a.handleStatus)

	if a.cfg.UI.ExternalFolder {
		// External folder: leave the base path to the parent mux. Nothing to do.
		return
	}

	mux.HandleWithMethod("", strings.TrimSuffix(p.Root, "/")+"/login", func(w http.ResponseWriter, r *http.Request) {
		// redirect to the same path with trailing slash, so the folder handler can serve the index.html for /login.
		http.Redirect(w, r, p.UI+"/", http.StatusFound)
	})
	mux.HandleWithMethod("", strings.TrimSuffix(p.Root, "/")+"/login/*", a.handleUI)
}

// Issuer exposes the issuer for advanced callers (e.g. CLI tools that need to
// revoke sessions out-of-band).
func (a *Auth) Issuer() issuer.Issuer { return a.issuer }

// Session exposes the session for advanced callers.
func (a *Auth) Session() *session.Session { return a.session }

// Registry exposes the strategy registry.
func (a *Auth) Registry() *strategy.Registry { return a.registry }

// Close releases resources owned by registered strategies and the configured
// second factor. Injected issuers, backends, and session stores remain owned by
// their callers. It is safe to call Close more than once.
func (a *Auth) Close() error {
	a.closeOnce.Do(func() {
		a.closing.Store(true)
		var errs []error
		a.retiredMu.Lock()
		all := append([]strategy.Authenticator(nil), a.retired...)
		a.retiredMu.Unlock()
		all = append(all, a.registry.List()...)

		for _, s := range all {
			if err := a.closeStrategy(s); err != nil {
				errs = append(errs, err)
			}
		}
		if c, ok := a.secondFactor.(interface{ Close() error }); ok {
			errs = append(errs, c.Close())
		}
		a.closeErr = errors.Join(errs...)
	})

	return a.closeErr
}

func (a *Auth) retainStrategy(s strategy.Authenticator) {
	if _, ok := s.(interface{ Close() error }); !ok {
		return
	}

	a.retiredMu.Lock()
	for _, previous := range a.retired {
		if sameStrategyInstance(previous, s) {
			a.retiredMu.Unlock()
			return
		}
	}
	if a.closing.Load() {
		a.retiredMu.Unlock()
		_ = a.closeStrategy(s)
		return
	}
	a.retired = append(a.retired, s)
	a.retiredMu.Unlock()
}

func (a *Auth) closeStrategy(s strategy.Authenticator) error {
	c, ok := s.(interface{ Close() error })
	if !ok {
		return nil
	}

	a.retiredMu.Lock()
	for _, previous := range a.closed {
		if sameStrategyInstance(previous, s) {
			a.retiredMu.Unlock()
			return nil
		}
	}
	a.closed = append(a.closed, s)
	a.retiredMu.Unlock()

	return c.Close()
}

func sameStrategyInstance(a, b strategy.Authenticator) bool {
	if a == nil || b == nil || reflect.TypeOf(a) != reflect.TypeOf(b) {
		return false
	}
	t := reflect.TypeOf(a)
	return t.Comparable() && reflect.ValueOf(a).Interface() == reflect.ValueOf(b).Interface()
}

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

	// A second factor, if configured, stands between a verified first factor
	// and an actual session.
	if a.beginSecondFactor(w, r, id, name) {
		return
	}

	pair, err := a.issuer.Issue(r.Context(), id)
	if err != nil {
		slog.Error("auth: issue session", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "issue_failed", err.Error())

		return
	}

	a.session.IssueCookie(w, r, pair.SessionID)
	a.setSuccessCookie(w, r)

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
	a.setSuccessCookie(w, r)

	a.respondAfterRegister(w, r, name)
}

// respondAfterRegister writes the JSON response for a successful register
// with auto-login. Includes auto_login: true so the UI knows to redirect
// rather than showing a "please sign in" message.
func (a *Auth) respondAfterRegister(w http.ResponseWriter, r *http.Request, strategyName string) {
	redirectPath := session.SafeRedirectPath(r.URL.Query().Get("redirect_path"))

	if r.Method == http.MethodPost && wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{
			"strategy":      strategyName,
			"registered":    true,
			"auto_login":    true,
			"redirect_path": redirectPath,
		})

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write([]byte("<script>window.close();</script>")); err != nil {
		slog.Debug("auth: write close-popup", "error", err.Error())
	}
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
	a.removeSuccessCookie(w, r)

	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) handleStatus(w http.ResponseWriter, r *http.Request) {
	a.status.serve(w, r, a.cfg.SuccessCookie.Name)
}

func (a *Auth) handleUI(w http.ResponseWriter, r *http.Request) {
	// The login page reads redirect_path straight out of window.location and
	// navigates to it once authentication succeeds. Server-side validation of
	// the value we echo back is not enough, because the browser never asked
	// us about the copy in its own address bar — so strip an unsafe value
	// here, before the page can ever see it.
	if raw := r.URL.Query().Get("redirect_path"); raw != "" && session.SafeRedirectPath(raw) == "" {
		q := r.URL.Query()
		q.Del("redirect_path")

		clean := *r.URL
		clean.RawQuery = q.Encode()

		http.Redirect(w, r, clean.RequestURI(), http.StatusFound)

		return
	}

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
	redirectPath := session.SafeRedirectPath(r.URL.Query().Get("redirect_path"))

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

// successCookieOptions returns the Set-Cookie policy for the post-login
// indicator cookie. HttpOnly is deliberately off: the status iframe reads it
// from JavaScript, which is its entire purpose. It carries no secret — only
// the fact that a login just happened.
func (a *Auth) successCookieOptions() cookie.Options {
	return cookie.Options{
		Path:            a.cfg.SuccessCookie.Path,
		Domain:          a.cfg.SuccessCookie.Domain,
		MaxAge:          a.cfg.SuccessCookie.MaxAge,
		Secure:          a.cfg.SuccessCookie.Secure,
		SameSite:        a.cfg.SuccessCookie.SameSite,
		DisableHTTPOnly: true,
	}
}

func (a *Auth) setSuccessCookie(w http.ResponseWriter, r *http.Request) {
	a.successCookieOptions().Set(w, r, a.cfg.SuccessCookie.Name, "true")
}

func (a *Auth) removeSuccessCookie(w http.ResponseWriter, r *http.Request) {
	a.successCookieOptions().Clear(w, r, a.cfg.SuccessCookie.Name)
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
