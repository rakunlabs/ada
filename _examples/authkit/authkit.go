// Package authkit is the Auth Kit reference application: a small "reports"
// app with a login page, local users, roles and permissions, a user
// management page, personal access tokens and an OAuth-protected MCP-style
// endpoint.
//
// middleware/auth provides the login page, sessions, strategies and the
// OAuth server. Everything application-specific lives here and is meant to
// be copied into your app and adapted:
//
//	users/  accounts, roles, permissions, admin and account APIs, admin page
//	store/  SQL store for users and OAuth (PostgreSQL, SQLite, MySQL)
//	kit/    wires users + store + middleware/auth together
//
// The tests next to each package are part of the reference: keep them when
// you copy the code, they check the security rules (single-use codes,
// refresh rotation, last admin, no privilege escalation).
//
//	EXAMPLE=authkit go run .
//
// Then open http://localhost:8080/. Users and OAuth data are kept in
// authkit.db (SQLite) next to the binary; delete it to start over.
//
//	ADDR             listen address (default :8080)
//	EXTERNAL_URL     public URL (default http://localhost:8080)
//	ADMIN_PASSWORD   creates user "admin" on first start; without it the
//	                 first person to sign up becomes the administrator
//	AUTH_DB          SQLite file (default authkit.db)
package authkit

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/rakunlabs/ada"
	"github.com/rakunlabs/ada/middleware/auth"
	"github.com/rakunlabs/ada/middleware/auth/authz"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/_examples/authkit/kit"
	"github.com/rakunlabs/ada/middleware/auth/oauthserver"
	"github.com/rakunlabs/ada/_examples/authkit/store"
	"github.com/rakunlabs/ada/_examples/authkit/users"
	mlog "github.com/rakunlabs/ada/middleware/log"
	mrecover "github.com/rakunlabs/ada/middleware/recover"

	_ "modernc.org/sqlite"
)

//go:embed index.html
var indexHTML []byte

// Roles of the example. "admin" may do anything; "analyst" reads and writes
// reports; "viewer" only reads them.
var roles = []users.Role{
	{Name: "admin", Description: "Everything, including user management", Permissions: []string{"*"}},
	{Name: "analyst", Description: "Reads and writes reports", Permissions: []string{"reports:*"}},
	{Name: "viewer", Description: "Reads reports", Permissions: []string{"reports:read"}},
}

func Run(ctx context.Context) error {
	addr := envOr("ADDR", ":8080")
	external := envOr("EXTERNAL_URL", "http://localhost"+addr)

	db, err := sql.Open("sqlite", envOr("AUTH_DB", "authkit.db")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return fmt.Errorf("open db; %w", err)
	}
	defer func() { _ = db.Close() }()

	st, err := store.New(db, store.Config{Dialect: store.SQLite})
	if err != nil {
		return err
	}
	if err := st.CreateTables(ctx); err != nil {
		return err
	}

	cfg := kit.Config{
		ExternalURL: external,
		Login: auth.Config{UI: auth.UIConfig{
			Title:    "Reports",
			Subtitle: "Auth Kit example",
		}},
		Users: users.Config{
			Roles:        roles,
			DefaultRoles: []string{"viewer"},
		},
		OAuth: kit.OAuth{Enabled: true, Scopes: []string{"mcp"}},
	}

	if pw := os.Getenv("ADMIN_PASSWORD"); pw != "" {
		cfg.Users.Bootstrap = users.Bootstrap{Username: "admin", Password: pw}
	}

	authKit, err := kit.New(ctx, cfg, kit.Stores{Users: st, OAuth: st})
	if err != nil {
		return fmt.Errorf("auth kit; %w", err)
	}
	defer func() { _ = authKit.Close() }()

	go cleanup(ctx, st)

	app := &reportsApp{reports: newReports()}

	server, err := ada.NewWithFunc(ctx, func(_ context.Context, mux *ada.Mux) error {
		mux.Use(mrecover.Middleware(), mlog.Middleware())

		// Login page, OAuth endpoints and discovery, /api/account and
		// /api/admin/users (+ /ui/).
		authKit.Mount(mux)

		// The home page is public; it asks /api/account who is signed in.
		mux.GET("/", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(indexHTML)
		})

		api := mux.Group("/api/v1", authKit.API()...)
		api.GET("/reports", app.list, authKit.RequirePermission("reports:read"))
		api.POST("/reports", app.create, authKit.RequirePermission("reports:write"))
		api.DELETE("/reports/{id}", app.remove, authKit.RequirePermission("reports:delete"))

		tokens := &tokenAPI{oauth: authKit.OAuth, store: st}
		api.GET("/tokens", tokens.list)
		api.POST("/tokens", tokens.create)
		api.DELETE("/tokens/{id}", tokens.remove)

		// What an MCP client would call. Unauthenticated requests get 401 with
		// a resource_metadata pointer, so `claude mcp add` and the MCP
		// Inspector can discover the OAuth server and sign the user in.
		mcpGuard := append(authKit.API(), authz.RequireScope("mcp"))
		mux.HandleWithMethod("", "/mcp", app.mcp, mcpGuard...)

		return nil
	})
	if err != nil {
		return err
	}

	slog.Info("auth kit example running",
		"url", external+"/",
		"users", external+"/api/admin/users/ui/",
		"mcp", external+"/mcp",
		"bootstrap_admin", cfg.Users.Bootstrap.Username != "",
	)

	return server.StartWithContext(ctx, addr)
}

// cleanup removes expired OAuth codes and tokens. In a real deployment use
// hardloop (and alan.LeaderLoop with several replicas).
func cleanup(ctx context.Context, st *store.Store) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := st.DeleteExpired(ctx, time.Now()); err != nil {
				slog.Warn("auth cleanup", "error", err.Error())
			}
		}
	}
}

// ////////////////////////////////////////////////////////////////////////////
// tokens

type tokenAPI struct {
	oauth *oauthserver.Server
	store *store.Store
}

func (t *tokenAPI) list(c *ada.Context) error {
	list, err := t.store.TokensBySubject(c.Request.Context(), identity.FromContext(c.Request.Context()).Subject)
	if err != nil {
		return err
	}

	out := make([]map[string]any, 0, len(list))
	for _, tok := range list {
		out = append(out, map[string]any{
			"id": tok.ID, "name": tok.Name, "client_id": tok.ClientID, "scopes": tok.Scopes,
			"created_at": tok.CreatedAt, "expires_at": tok.AccessExpiresAt,
		})
	}

	return c.SendJSON(out)
}

func (t *tokenAPI) create(c *ada.Context) error {
	var in struct {
		Name string `json:"name"`
		Days int    `json:"days"`
	}
	if err := c.Bind(&in); err != nil {
		return ada.WrapHTTPError(http.StatusBadRequest, err)
	}
	if in.Name == "" {
		return ada.NewHTTPError(http.StatusBadRequest, "name is required")
	}

	raw, tok, err := t.oauth.IssueToken(c.Request.Context(), oauthserver.IssueRequest{
		Name:     in.Name,
		Identity: identity.FromContext(c.Request.Context()),
		Scopes:   []string{"mcp"},
		TTL:      time.Duration(in.Days) * 24 * time.Hour,
	})
	if err != nil {
		return err
	}

	return c.SetStatus(http.StatusCreated).SendJSON(map[string]any{"id": tok.ID, "token": raw})
}

func (t *tokenAPI) remove(c *ada.Context) error {
	ctx := c.Request.Context()
	me := identity.FromContext(ctx)

	list, err := t.store.TokensBySubject(ctx, me.Subject)
	if err != nil {
		return err
	}

	for _, tok := range list {
		if tok.ID == c.Request.PathValue("id") {
			if tok.ClientID != "" {
				_ = t.store.DeleteConsent(ctx, me.Subject, tok.ClientID)
			}

			if err := t.store.DeleteToken(ctx, tok.ID); err != nil {
				return err
			}

			return c.SendNoContent()
		}
	}

	return ada.NewHTTPError(http.StatusNotFound, "no such token")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return def
}
