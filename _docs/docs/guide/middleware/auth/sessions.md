# Session & Issuer

The session is backed by an internal **issuer** that mints opaque access/refresh tokens:

- Browser cookie carries only an opaque session ID (never a JWT)
- Access tokens live for 15 minutes (configurable)
- Refresh tokens live for 7 days (configurable), rotated on each use
- Session state is stored in a pluggable backend (in-memory by default)

`AccessTTL` never extends past `RefreshTTL`; if configured longer, access-token
expiry is clamped to refresh expiry. A strategy-supplied `Identity.ExpiresAt`
is also clamped to the resulting access-token expiry, while an earlier identity
expiry is preserved.

## Persisting sessions

```go
import (
    "github.com/rakunlabs/ada/middleware/auth/issuer/backend"
    "github.com/rakunlabs/ada/middleware/auth/issuer/crypto"
    "github.com/rakunlabs/ada/middleware/auth/sessionstore"
    "github.com/rakunlabs/ada/middleware/auth/sessionstore/file"
)

store, err := file.New(file.Config{
    // Set this. Left empty, a random key is generated per process: every
    // session breaks on restart and no two replicas can read each other's.
    SessionKey: os.Getenv("SESSION_KEY"),
    Path:       "/var/sessions",
}, sessionstore.Options{Path: "/", MaxAge: 86400})
if err != nil {
    return err
}

store.StartGC() // sweep expired session files
defer store.Close()

cipher, err := crypto.New(os.Getenv("SESSION_ENCRYPTION_KEY"))
if err != nil {
    return err
}

authMW.WithSessionStore(store, backend.WithCipher(cipher))
```

`WithCipher` is strongly recommended: the stored pair holds both live tokens
and the full identity, including every raw upstream claim. Without it, a
database dump or a stolen disk is a stack of usable sessions.

For Redis:

```go
import redisstore "github.com/rakunlabs/ada/middleware/auth/sessionstore/redis"

store, err := redisstore.New(ctx, redisstore.Config{
    Address:    "localhost:6379",
    Password:   "secret",
    SessionKey: os.Getenv("SESSION_KEY"),
}, sessionstore.Options{Path: "/", MaxAge: 86400})

authMW.WithSessionStore(store, backend.WithCipher(cipher))
```

The store must implement `sessionstore.DirectStore` — reading and writing by
raw session ID, without an `*http.Request`. Both bundled stores do. A store
that does not is rejected at `Init` rather than silently losing every write.
