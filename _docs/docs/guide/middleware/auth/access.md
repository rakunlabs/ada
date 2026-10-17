# Identity & Access

Once a strategy has authenticated a request, these pieces decide what the caller is, what it may do, and how hard it is to guess a password.

## Identity

After `Require()`, the identity is available in the request context:

```go
id := identity.FromContext(r.Context())

id.Subject       // "alice"
id.Name          // "Alice Example"
id.Email         // "alice@example.com"
id.EmailVerified // true
id.Roles         // ["admin", "user"]
id.Scopes        // ["read", "write"]
id.Provider      // "local" or "google"
id.Claims        // map[string]any — raw OIDC claims
id.IssuedAt      // time.Time

// Typed claim access
tenantID := identity.Claim[string](id, "tenant_id")

// Role/scope checks. An empty role or scope is false, not "no requirement":
// id.HasRole(cfg.Role) with an unset config value must not wave everyone through.
id.HasRole("admin")             // true
id.HasScope("write")            // true
id.HasAnyRole("admin", "root")  // true
id.HasAllRoles("admin", "root") // false
```

## Authorization

`Require()` only answers "is this someone?". `middleware/auth/authz` answers
"may they do this?".

```go
import "github.com/rakunlabs/ada/middleware/auth/authz"

// Per-route.
mux.GET("/admin", handler, authMW.Require(), authz.RequireRole("admin"))
mux.GET("/reports", handler, authMW.Require(), authz.RequireAnyScope("reports:read", "admin"))

// Or a policy table, evaluated in order — first match wins.
rules := authz.Rules{
    Rules: []authz.Rule{
        {Name: "health", Paths: []string{"/health", "/metrics"}, Public: true},
        {Name: "admin", Paths: []string{"/api/admin/**"}, Roles: []string{"admin"}},
        {
            Name:     "api",
            Paths:    []string{"/api/**"},
            Excluded: []authz.Rule{{Paths: []string{"/api/public/**"}}},
            Scopes:   []string{"api"},
        },
    },
    // Applies when nothing matches. Defaults to Authenticated.
    Default: authz.Authenticated,
}

if err := rules.Validate(); err != nil {
    return err
}

mux.Use(authMW.Require(), rules.Middleware())
```

Path patterns support `*` (one segment), `**` (any depth) and `?` (one
character). `/api/**` also matches `/api` itself.

A denied request gets `403` when somebody is logged in and `401` when nobody
is; the response never names the requirement that was missing.

## Second factor (MFA)

`strategy/totp` is an RFC 6238 primitive. `WithSecondFactor` is where it plugs
into the login flow:

```go
sf := totp.NewSecondFactor(totp.Default(), lookupSecret,
    totp.WithRecoveryCodes(consumeRecoveryCode))

authMW := auth.New(cfg).
    Strategy(local.New("local", verify)).
    WithSecondFactor(sf)
```

The default issuer, `WithBackend`, and `WithSessionStore` automatically create
an isolated pending issuer whose lifetime is `MFA.TTL`. A custom session issuer
cannot be safely reused because Ada cannot infer its lifetime. When combining
`WithIssuer` and `WithSecondFactor`, provide a separate pending issuer:

```go
authMW := auth.New(cfg).
    WithIssuer(customSessionIssuer).
    WithPendingIssuer(customPendingIssuer).
    Strategy(local.New("local", verify)).
    WithSecondFactor(sf)
```

`customPendingIssuer` must implement `issuer.AtomicUpdater` and enforce a
lifetime no longer than `cfg.MFA.TTL`. In a replicated
deployment, back it with shared storage so attempts and expiry are enforced
across every instance. `Init` rejects MFA configuration that uses a custom
issuer without this pending issuer.

The first factor no longer issues a session. It parks the identity for
`MFA.TTL`, sets a short-lived `HttpOnly` cookie scoped to `/login/mfa`, and
answers `{"mfa_required": true}`. The client posts the code to
`POST {base}login/mfa`; only then is the real session minted. A parked login
is not usable as a session — `Require()` rejects it — and it is destroyed
after `MFA.MaxAttempts` wrong codes.

Return `totp.ErrNotEnrolled` from the lookup for users who have no secret, so
enrolment can be rolled out gradually.

## Rate limiting and lockout

Nothing counts failed attempts unless you say so:

```go
import "github.com/rakunlabs/ada/middleware/auth/guard"

g := guard.New(guard.Config{})   // 5 failures, escalating lockout from 15m
defer g.Close()

local.New("local", verify, local.WithLimiter(g))
magiclink.New("mail", send, resolve,
    magiclink.WithVerifyBaseURL("https://app.example.com"),
    magiclink.WithLimiter(g),
)
```

The local strategy keys on the username, not the client address: an attacker
grinding one account from a botnet is the case an IP key misses, and the one
that actually takes over accounts. The guard is in-process, so with several
replicas the effective limit multiplies by the replica count; supply your own
`guard.Limiter` for an exact global budget.

## Password hashing

```go
import "github.com/rakunlabs/ada/middleware/auth/password"

h := password.New() // PBKDF2-HMAC-SHA256, 600k iterations

encoded, err := h.Hash("correct horse battery staple")

// On login — use the dummy hash for unknown users so a missing account costs
// the same as a wrong password.
stored, ok := db.Lookup(username)
if !ok {
    stored = password.Dummy
}

if err := h.Verify(stored, given); err != nil {
    return nil, local.ErrInvalidCredentials
}

if h.NeedsRehash(stored) {
    // upgrade in the background
}
```

PBKDF2 is the weakest acceptable choice; it is the default only because this
module carries no third-party dependencies. Implement `password.Hasher` with
Argon2id if you can take the dependency.
