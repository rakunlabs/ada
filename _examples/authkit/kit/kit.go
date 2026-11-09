// Package kit assembles the whole of middleware/auth into one value: login
// page, sessions, local users with roles and permissions, account and user
// management APIs, an OAuth 2.1 server for MCP and CLI clients, and personal
// access tokens.
//
// It is part of the Auth Kit reference application (_examples/authkit): copy
// it into your app (internal/auth) together with users/ and store/. Every
// value it builds is exposed on Kit, so you can reach past it where you need
// something it does not decide for you.
//
//	k, err := kit.New(ctx, cfg.Auth, kit.Stores{Users: st, OAuth: st})
//	k.Mount(mux)
//	api := mux.Group("/api/v1", k.API()...)
//	api.GET("/reports", h, k.RequirePermission("reports:read"))
package kit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/rakunlabs/ada/middleware/auth"
	"github.com/rakunlabs/ada/middleware/auth/authz"
	"github.com/rakunlabs/ada/middleware/auth/guard"
	"github.com/rakunlabs/ada/middleware/auth/issuer/backend"
	"github.com/rakunlabs/ada/middleware/auth/issuer/crypto"
	"github.com/rakunlabs/ada/middleware/auth/oauthserver"
	"github.com/rakunlabs/ada/middleware/auth/resource"
	"github.com/rakunlabs/ada/middleware/auth/session"
	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
	"github.com/rakunlabs/ada/middleware/auth/strategy/local"
	"github.com/rakunlabs/ada/_examples/authkit/users"
)

// Config is the auth section of an application config. Every field has a
// working default; ExternalURL is the one to set in production.
type Config struct {
	// ExternalURL is the public URL of the application including any proxy
	// prefix, e.g. "https://tools.example.com/myapp". It pins the OAuth
	// issuer and the MCP resource identifier. Empty derives both from the
	// request, which is fine for development only.
	ExternalURL string `cfg:"external_url"`

	// BasePath is the mux prefix of the application, e.g. "/" or "/myapp".
	BasePath string `cfg:"base_path"`

	// Login configures the login page, cookies and session lifetimes
	// (auth.Config). Base defaults to BasePath.
	Login auth.Config `cfg:"login"`

	// Users configures local accounts, roles and signup.
	Users users.Config `cfg:"users"`

	// LocalLabel is the label of the username/password form. Default
	// "Username".
	LocalLabel string `cfg:"local_label"`

	// DisableLocal removes the username/password login, e.g. for SSO-only
	// deployments. Users are still managed (and SSO identities can be
	// mapped to them).
	DisableLocal bool `cfg:"disable_local"`

	// Limiter locks accounts after repeated failed logins.
	Limiter guard.Config `cfg:"limiter"`

	// AccountPath is where the signed-in user's own API lives. Default
	// "{base}api/account". "-" disables it.
	AccountPath string `cfg:"account_path"`

	// AdminPath is where user management lives: the JSON API at AdminPath
	// and the built-in page at AdminPath + "/ui/". Default
	// "{base}api/admin/users". "-" disables both.
	AdminPath string `cfg:"admin_path"`

	// DisableAdminUI keeps the user-management API but not its page.
	DisableAdminUI bool `cfg:"disable_admin_ui"`

	// OAuth turns on the authorization server for MCP and CLI clients.
	OAuth OAuth `cfg:"oauth"`

	// Session persistence. With a Stores.Sessions store, CipherKey encrypts
	// sessions at rest (strongly recommended).
	CipherKey string `cfg:"cipher_key" log:"-"`
}

// OAuth configures the authorization server.
type OAuth struct {
	// Enabled turns it on.
	Enabled bool `cfg:"enabled"`

	// Server is passed to oauthserver.New. Issuer and BasePath default to
	// ExternalURL and BasePath; Hooks.Identity defaults to the users
	// service, so tokens follow the account.
	Server oauthserver.Config `cfg:"server"`

	// ResourcePath is the protected endpoint clients ask tokens for,
	// relative to BasePath. Default "/mcp".
	ResourcePath string `cfg:"resource_path"`

	// Subresources makes every path below ResourcePath its own resource,
	// for tokens limited to one sub-endpoint (/mcp/{conn}).
	Subresources bool `cfg:"subresources"`

	// Scopes advertised and accepted. Default ["mcp"], which is also the
	// default scope.
	Scopes []string `cfg:"scopes"`
}

// Stores are the storage backends. Nil fields fall back to memory, which
// loses everything on restart.
type Stores struct {
	Users users.Store
	OAuth oauthserver.Store
	// Sessions persists login sessions (sessionstore/file, sessionstore/redis).
	Sessions sessionstore.Store
}

// Kit is the assembled authentication stack.
type Kit struct {
	Auth  *auth.Auth
	Users *users.Service
	// OAuth is nil unless Config.OAuth.Enabled.
	OAuth *oauthserver.Server
	Guard *guard.Guard

	cfg   Config
	base  string
	extra []strategy.Authenticator
}

// Option customizes New.
type Option func(*Kit)

// WithStrategy registers another login strategy (OIDC, LDAP, passkey, API
// key, bearer) next to the local one.
func WithStrategy(s strategy.Authenticator) Option {
	return func(k *Kit) { k.extra = append(k.extra, s) }
}

// New builds and initializes the stack. It creates the bootstrap
// administrator when configured and no user exists.
func New(ctx context.Context, cfg Config, stores Stores, opts ...Option) (*Kit, error) {
	k := &Kit{cfg: cfg}
	for _, o := range opts {
		o(k)
	}

	k.base = "/" + strings.Trim(cfg.BasePath, "/")
	if k.base != "/" {
		k.base += "/"
	}

	ext := strings.TrimSuffix(cfg.ExternalURL, "/")

	if stores.Users == nil {
		stores.Users = users.NewMemoryStore()
	}

	if len(k.extra) > 0 {
		// Another login (SSO, passkey) exists, so an admin without a
		// password still counts as somebody who can sign in.
		cfg.Users.ExternalLogin = true
	}

	svc, err := users.New(cfg.Users, stores.Users)
	if err != nil {
		return nil, fmt.Errorf("kit: users; %w", err)
	}
	if err := svc.Init(ctx); err != nil {
		return nil, fmt.Errorf("kit: users; %w", err)
	}
	k.Users = svc

	lc := cfg.Login
	if lc.Base == "" {
		lc.Base = k.base
	}
	if lc.UI.SignupFirstFn == nil {
		lc.UI.SignupFirstFn = func() bool { return svc.NoUsers(context.Background()) }
	}

	if cfg.OAuth.Enabled {
		if len(cfg.OAuth.Scopes) == 0 {
			cfg.OAuth.Scopes = []string{"mcp"}
		}
		if cfg.OAuth.ResourcePath == "" {
			cfg.OAuth.ResourcePath = "/mcp"
		}

		rc := &resource.Config{
			ScopesSupported: cfg.OAuth.Scopes,
			ResourceName:    firstNonEmpty(cfg.OAuth.Server.ServiceName, lc.UI.Title),
			Subresources:    cfg.OAuth.Subresources,
		}

		resourcePath := strings.TrimSuffix(k.base, "/") + "/" + strings.Trim(cfg.OAuth.ResourcePath, "/")
		if ext != "" {
			rc.Resource = ext + "/" + strings.Trim(cfg.OAuth.ResourcePath, "/")
		} else {
			rc.ResourcePath = resourcePath
			rc.TrustedProxies = cfg.OAuth.Server.TrustedProxies
			rc.UnsafeTrustAllForwardedHeaders = cfg.OAuth.Server.UnsafeTrustAllForwardedHeaders
		}

		lc.ProtectedResource = rc
	}

	a := auth.New(lc)

	if !cfg.DisableLocal {
		k.Guard = guard.New(cfg.Limiter)

		a.Strategy(local.New("local", svc.Verifier(),
			local.WithLabel(firstNonEmpty(cfg.LocalLabel, "Username")),
			local.WithLimiter(k.Guard),
			local.WithRegistrar(svc.Registrar()),
			local.WithRegisterEnabled(func() bool { return svc.SignupOpen(context.Background()) }),
			local.WithAutoLogin(true),
		))
	}

	for _, s := range k.extra {
		a.Strategy(s)
	}

	if cfg.OAuth.Enabled {
		oc := cfg.OAuth.Server
		if oc.Issuer == "" && oc.IssuerFunc == nil && ext != "" {
			oc.Issuer = ext
		}
		if oc.BasePath == "" {
			oc.BasePath = k.base
		}
		if oc.ServiceName == "" {
			oc.ServiceName = lc.UI.Title
		}
		if len(oc.ScopesSupported) == 0 {
			oc.ScopesSupported = cfg.OAuth.Scopes
		}
		if len(oc.DefaultScopes) == 0 {
			oc.DefaultScopes = cfg.OAuth.Scopes
		}
		if oc.Hooks.Identity == nil {
			oc.Hooks.Identity = svc.IdentityHook()
		}
		if oc.Authenticate == nil {
			// The consent page must see the current user: a disabled or
			// deleted user is refused there, and Hooks.Authorize decides
			// with today's roles. Resolved per request because Auth.Require
			// only exists after Init.
			// oauthserver applies it in Mount, which runs after Init, so
			// the session exists by then.
			oc.Authenticate = func(next http.Handler) http.Handler {
				return k.Auth.Session().Require()(svc.Fresh(true)(next))
			}
		}

		if stores.OAuth == nil {
			stores.OAuth = oauthserver.NewMemoryStore()
		}

		srv, err := oauthserver.New(oc, stores.OAuth)
		if err != nil {
			return nil, fmt.Errorf("kit: oauth; %w", err)
		}

		a.WithOAuthServer(srv)
		k.OAuth = srv
	}

	if stores.Sessions != nil {
		var sopts []backend.SessionStoreOption
		if cfg.CipherKey != "" {
			c, err := crypto.New(cfg.CipherKey)
			if err != nil {
				return nil, fmt.Errorf("kit: cipher_key; %w", err)
			}

			sopts = append(sopts, backend.WithCipher(c))
		}

		a.WithSessionStore(stores.Sessions, sopts...)
	}

	if err := a.Init(ctx); err != nil {
		return nil, fmt.Errorf("kit: auth; %w", err)
	}
	k.Auth = a

	return k, nil
}

// Close releases the limiter and the strategies.
func (k *Kit) Close() error {
	var errs []error
	if k.Guard != nil {
		errs = append(errs, k.Guard.Close())
	}

	errs = append(errs, k.Auth.Close())

	return errors.Join(errs...)
}

// Mount registers the login page, the OAuth endpoints and discovery
// documents, the account API and user management on mux.
func (k *Kit) Mount(mux auth.Mux) {
	k.Auth.Mount(mux)

	account := k.path(k.cfg.AccountPath, "api/account")
	if account != "" {
		k.Users.MountSelf(mux, account, k.API()...)
	}

	if p := k.path(k.cfg.AdminPath, "api/admin/users"); p != "" {
		k.Users.MountAdmin(mux, p, k.API()...)

		if !k.cfg.DisableAdminUI {
			k.Users.MountAdminUI(mux, p+"/ui", users.UIOptions{API: "..", AccountAPI: relative(p+"/ui/", account)}, k.Browser()...)
		}
	}
}

func (k *Kit) path(configured, def string) string {
	switch configured {
	case "-":
		return ""
	case "":
		return k.base + def
	}

	return configured
}

// Require authenticates a request and refreshes the user: a session cookie,
// an OAuth or personal token, or any registered request strategy. Browsers
// without a session are redirected to the login page.
func (k *Kit) Require() func(http.Handler) http.Handler {
	auth, fresh := k.Auth.Require(), k.Users.Fresh(true)

	return func(next http.Handler) http.Handler { return auth(fresh(next)) }
}

// API is the middleware chain for JSON and MCP routes: unauthenticated
// callers get 401 with a WWW-Authenticate challenge instead of a redirect.
func (k *Kit) API() []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{session.DisableRedirect(), k.Require()}
}

// Browser is the middleware chain for pages a person navigates to.
func (k *Kit) Browser() []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{k.Require()}
}

// RequirePermission guards a route by a permission granted through roles.
func (k *Kit) RequirePermission(perm string) func(http.Handler) http.Handler {
	return k.Users.RequirePermission(perm)
}

// RequireRole guards a route by role (any of them).
func (k *Kit) RequireRole(roles ...string) func(http.Handler) http.Handler {
	return authz.RequireAnyRole(roles...)
}

// relative returns target as a path relative to the page at from (both
// absolute mux paths, from ending in "/"), so links survive a proxy that
// strips a path prefix. An empty target stays empty.
func relative(from, target string) string {
	if target == "" {
		return ""
	}

	a := strings.Split(strings.Trim(from, "/"), "/")
	b := strings.Split(strings.Trim(target, "/"), "/")

	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}

	parts := make([]string, 0, len(a)-i+len(b)-i)
	for range a[i:] {
		parts = append(parts, "..")
	}
	parts = append(parts, b[i:]...)

	if len(parts) == 0 {
		return "."
	}

	return strings.Join(parts, "/")
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}

	return ""
}
