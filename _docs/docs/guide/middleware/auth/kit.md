# Auth Kit

**Auth Kit** is the complete authentication stack for an ada application, delivered as a reference application you copy into your app: [`_examples/authkit`](https://github.com/rakunlabs/ada/tree/main/_examples/authkit).

It gives you:

- a **login page**, with first-run signup and optional self-signup
- **local users**: create, edit, disable and delete accounts, reset passwords, case-insensitive usernames, lockout after failed logins
- **roles and permissions**: roles defined in config, permissions such as `reports:read` or `reports:*`, and route guards
- a **user management page** and JSON API for administrators
- an **account API** for the signed-in user (profile, password change)
- an **OAuth 2.1 server** for MCP and CLI clients: well-known discovery, dynamic client registration, consent, PKCE, refresh, revocation
- **personal access tokens**
- **SSO** (OIDC, LDAP, passkey…) next to local login
- **immediate revocation**: disabling, deleting or demoting a user applies to their sessions and tokens on the next request

::: tip For people and AI agents
Say **"add ada Auth Kit"**. The step-by-step procedure is in the [`rakunlabs-go` skill](https://github.com/rakunlabs/rakunlabs/tree/main/skills/rakunlabs-go) (`references/auth-kit*.md`). This page explains what goes where.
:::

## Why copy instead of import

Users, roles and storage belong to your application: your table names, your migrations, your admin screens, your rules for who may do what. `middleware/auth` stays generic and provides the parts that are the same everywhere. The example provides the rest as plain code.

| Where | What | You |
|---|---|---|
| `middleware/auth` | Login page, sessions, strategies, `Require()`, MFA, lockout (`guard`) | import |
| `middleware/auth/oauthserver` | OAuth 2.1 server, MemoryStore ([details](./authorization-server)) | import |
| `middleware/auth/authz` | Role and scope guards, rule tables ([details](./access)) | import |
| `_examples/authkit/users` | Users, roles, permissions, signup, admin and account APIs, admin page | copy to `internal/auth/users` |
| `_examples/authkit/store` | SQL store for users and OAuth (PostgreSQL, SQLite, MySQL) | copy to `internal/store`, or rewrite on your data layer |
| `_examples/authkit/kit` | Wires the three together: `kit.New`, `Mount`, `API`, `Browser`, `RequirePermission` | copy to `internal/auth` |

Copy the tests with the code. They check the rules that fail silently when broken: single-use authorization codes, refresh rotation, replay detection, the last-admin rule, no privilege escalation, deleted users losing access.

## Run the example

```sh
cd _examples
EXAMPLE=authkit go run .
# open http://localhost:8080/  (first visitor becomes admin)
# ADMIN_PASSWORD=... creates "admin" instead
```

It shows reports guarded by permissions, the admin page at `/api/admin/users/ui/`, personal tokens, and an MCP endpoint at `/mcp`: `claude mcp add --transport http reports http://localhost:8080/mcp` walks through registration, login and consent.

## What it looks like in your app

```go
st, err := store.New(db, store.Config{Dialect: store.Postgres})
// tables come from your migrations (store.Schema shows them)

authKit, err := kit.New(ctx, cfg.Auth, kit.Stores{Users: st, OAuth: st})
defer authKit.Close()

authKit.Mount(mux) // login, OAuth, well-known, account and admin APIs, admin page

api := mux.Group("/api/v1", authKit.API()...)
api.GET("/reports", h, authKit.RequirePermission("reports:read"))

mcp := mux.Group("/mcp", append(authKit.API(), authz.RequireScope("mcp"))...)
```

## Security rules the code enforces

Keep these when you adapt it:

- The account and admin APIs accept **browser sessions only**. OAuth and personal tokens get 403, so an MCP client can never manage users. State-changing calls must be same-origin JSON.
- An actor may only give roles whose permissions they already hold, and can't change, reset or delete an account holding permissions they lack.
- The last enabled admin who can sign in can't be disabled, deleted, demoted or left without a password.
- Every request re-reads the user (`Users.Fresh`, the OAuth `IdentityHook`). A local identity whose user is gone is refused, not mistaken for SSO.
- A token works only on the resource it was issued for (`oauthserver`).

The last-admin and first-signup guarantees hold within one process. With several replicas, enforce them in the store too.

## See also

- [Authorization Server](./authorization-server): OAuth endpoints, hooks, the store contract, custom consent page
- [Identity & Access](./access): `authz` rules, MFA, lockout, password hashing
- [Strategies](./strategies): OIDC, LDAP, passkey, API key, bearer
- [Sessions](./sessions): lifetimes and session stores
- [Login UI](./login-ui): theming or replacing the login page
