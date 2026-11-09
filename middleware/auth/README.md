# ada/middleware/auth

Pluggable authentication for ada:

- a login UI and sessions
- strategies: local, OIDC, passkey, LDAP, API key, bearer, …
- role and scope guards (`authz`)
- MFA and lockout (`guard`)
- an OAuth 2.1 authorization server for MCP and CLI clients (`oauthserver`)
- RFC 9728 protected-resource metadata (`resource`)

## Auth Kit: users, roles, admin page, MCP

Local users, roles, permissions, user management and SQL storage are application code, not part of this module. A complete, tested reference lives in [`_examples/authkit`](../../_examples/authkit): copy its `users/`, `store/` and `kit/` packages into your app and adapt them.

Ask an agent with **"add ada Auth Kit"**. The procedure is in the `rakunlabs-go` skill (`github.com/rakunlabs/rakunlabs/skills/rakunlabs-go`, `references/auth-kit*.md`). Docs: https://rakunlabs.github.io/ada/guide/middleware/auth/kit

## Packages

| Package | Purpose |
|---|---|
| `auth` | `New`, `Strategy`, `WithOAuthServer`, `Init`, `Mount`, `Require` |
| `oauthserver` | RFC 8414, RFC 7591, authorize + consent, PKCE, refresh rotation, RFC 7009, personal tokens, MemoryStore |
| `strategy/*` | Login mechanisms |
| `authz` | `RequireRole`, `RequireScope`, rule tables |
| `resource` | RFC 9728 metadata and `WWW-Authenticate` challenges |
| `guard` | Lockout after failed logins |
| `session`, `issuer`, `sessionstore/*` | Sessions and their storage |

## Writing an `oauthserver.Store`

Breaking one of these rules doesn't fail loudly. The app keeps working and the hole stays open:

- Missing records return `oauthserver.ErrNotFound`.
- `TakeCode` reads and deletes in one step (single-use across replicas).
- `RotateToken` is a compare-and-swap on the old refresh hash. If nothing changed, return `ErrConflict`.
- `TokenByRefresh` also matches `PreviousRefreshHash` (replay detection).
- Every `Token` field is persisted.

`_examples/authkit/store` implements all of them for PostgreSQL, SQLite and MySQL, with tests.
