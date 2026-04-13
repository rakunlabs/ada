# Runtime Reload

Ada supports replacing, disabling, and adding middlewares at runtime without restarting the server or re-registering routes. Two primitives are provided:

- **Slot** — wraps a single middleware in an atomic pointer for replace/disable/enable.
- **Pipeline** — manages an ordered, keyed set of middlewares with add/remove/replace at runtime.

## Slot

A Slot wraps a single middleware and allows it to be swapped, disabled, or re-enabled while the server is running. All registration points that share the same Slot observe changes immediately.

```go
import "github.com/rakunlabs/ada"
```

### Basic Usage

```go
// Create a slot with an initial middleware
auth := ada.NewSlot(forwardauth.Middleware(
    forwardauth.WithAddress("http://auth:8080/verify"),
))

// Register it — works with Use, Group, or per-route
server.Use(auth.Middleware())
server.GET("/api/me", meHandler)

// Later, at runtime:
auth.Replace(forwardauth.Middleware(
    forwardauth.WithAddress("http://auth-v2:8080/verify"),
    forwardauth.WithTimeout(2 * time.Second),
))

auth.Disable()  // bypass — requests pass through
auth.Enable()   // restore the previously-set middleware
```

### Shared Across Locations

Registering the same Slot in multiple places is safe. A single `Replace` call updates all of them:

```go
auth := ada.NewSlot(forwardauth.Middleware(...))

server.Use(auth.Middleware())             // global
api := server.Group("/api", auth.Middleware())  // group

// One call updates both locations:
auth.Replace(forwardauth.Middleware(newOpts...))
```

::: warning
If the same Slot is registered in stacked locations (e.g. root `Use` **and** a child `Group`), the middleware runs once per registration point per request in that group. This matches how non-slotted middlewares behave in ada.
:::

### Cancelling In-Flight Requests

By default, `Replace` and `Disable` let in-flight requests finish with the old middleware. If you need to signal in-flight requests to abort (e.g. the old auth provider is compromised), use the timeout variants:

```go
// Cancel in-flight requests after 100ms grace period
auth.ReplaceWithTimeout(newAuthMiddleware, 100*time.Millisecond)

// Cancel immediately (grace = 0)
auth.DisableWithTimeout(0)
```

Handlers that respect `ctx.Done()` (database queries via `QueryContext`, HTTP calls via `NewRequestWithContext`, etc.) will abort after the grace period. Handlers that don't check context will finish normally — the cancel is best-effort.

```
t=0ms     ReplaceWithTimeout called
          |-- new snapshot stored atomically
          |-- NEW requests use the new middleware immediately
          |-- old in-flight requests still running
          |
t=0-100ms  grace period
          |-- request A: finishes at t=20ms   -> completed normally
          |-- request B: finishes at t=80ms   -> completed normally
          |-- request C: still running...
          |
t=100ms   old generation context cancelled
          |-- request C: ctx.Done() fires -> aborts if handler checks context
```

### API Reference

| Method | Description |
|---|---|
| `NewSlot(mw)` | Create a new enabled Slot. Pass `nil` for a no-op placeholder. |
| `Middleware()` | Returns a stable closure for registration with `Use`/`Group`/route. |
| `Replace(mw)` | Swap the middleware. Old in-flight requests finish normally. |
| `ReplaceWithTimeout(mw, grace)` | Swap and cancel old in-flight after grace. `0` = immediate. |
| `Disable()` | Make the slot a pass-through. Preserves the middleware for `Enable`. |
| `DisableWithTimeout(grace)` | Disable and cancel old in-flight after grace. |
| `Enable()` | Restore the previously-set middleware. No-op if already enabled. |
| `Enabled()` | Reports whether the slot is currently enabled. |

## Pipeline

A Pipeline manages an ordered set of middlewares keyed by string. Middlewares can be added, replaced, removed, and reordered at runtime.

```go
import "github.com/rakunlabs/ada"
```

### Basic Usage

```go
stack := ada.NewPipeline()
stack.Set("cors", cors.Middleware(...))
stack.Set("auth", forwardauth.Middleware(...))
server.Use(stack.Middleware())

// Later, at runtime:
stack.Set("ratelimit", ratelimit.Middleware(...))  // add new (appended at end)
stack.Remove("auth")                                // remove entirely
stack.Set("auth", forwardauth.Middleware(newOpts...))  // add back (at end)
```

### Ordering

New keys are appended at the end. Replacing an existing key preserves its position:

```go
stack.Set("cors", corsMw)     // order: [cors]
stack.Set("auth", authMw)     // order: [cors, auth]
stack.Set("log", logMw)       // order: [cors, auth, log]

stack.Set("auth", newAuthMw)  // order: [cors, auth, log]  (replaced in-place)
```

Use `SetAt` for explicit positioning:

```go
stack.SetAt(1, "ratelimit", rateMw)  // insert at index 1
```

::: info
`Remove` followed by `Set` with the same key appends to the end, losing the original position. Use `Apply` with `SetAt` to preserve position — see [Batch Mutations](#batch-mutations).
:::

### Inspecting the Stack

You can inspect the current state of a Pipeline at any time:

```go
// List all keys in order
keys := stack.Keys()    // ["cors", "auth", "ratelimit"]

// Check length
stack.Len()             // 3

// Check if a key exists
stack.Has("auth")       // true

// Find position of a key
stack.Index("auth")     // 1
stack.Index("unknown")  // -1

// Human-readable output (implements fmt.Stringer)
fmt.Println(stack)
// Output:
// Pipeline(3 middlewares):
//   [0] cors
//   [1] auth
//   [2] ratelimit
```

The `String()` method is useful for logging the current middleware stack, for example after a reload:

```go
stack.Apply(func(b *ada.PipelineBuilder) {
    b.Reset()
    b.Set("cors", newCorsMw)
    b.Set("auth", newAuthMw)
})
log.Printf("middleware stack reloaded: %s", stack)
```

### Batch Mutations

Multiple changes can be applied as a single atomic swap using `Apply`. In-flight requests never see an intermediate state:

```go
// Rebuild the entire stack atomically
stack.Apply(func(b *ada.PipelineBuilder) {
    b.Reset()
    b.Set("cors", newCorsMw)
    b.Set("auth", newAuthMw)
    b.Set("ratelimit", newRateMw)
})
```

Remove and re-insert at the correct position:

```go
stack.Apply(func(b *ada.PipelineBuilder) {
    b.Remove("auth")
    b.SetAt(1, "auth", forwardauth.Middleware(newOpts...))
})
// order is preserved: auth stays at index 1
```

Conditional mutations:

```go
stack.Apply(func(b *ada.PipelineBuilder) {
    if b.Has("auth") {
        b.Remove("auth")
    }
    b.Set("ratelimit", rateMw)
})
```

### Cancelling In-Flight Requests

Like Slot, Pipeline supports a grace-period cancel for in-flight requests:

```go
// Batch swap + cancel old in-flight after 100ms
stack.ApplyWithTimeout(func(b *ada.PipelineBuilder) {
    b.Reset()
    b.Set("cors", newCorsMw)
    b.Set("auth", newAuthMw)
}, 100*time.Millisecond)

// Immediate cancel
stack.ApplyWithTimeout(func(b *ada.PipelineBuilder) {
    b.Remove("auth")
}, 0)
```

### API Reference

#### Pipeline

| Method | Description |
|---|---|
| `NewPipeline()` | Create an empty Pipeline. |
| `Middleware()` | Returns a stable closure for registration. Pre-built chain, ~1 ns per request. |
| `Set(key, mw)` | Add or replace. New keys append; existing keys replace in-place. |
| `SetAt(index, key, mw)` | Add or replace at explicit position. Moves existing keys. |
| `Remove(key)` | Remove by key. Returns `true` if found. |
| `Has(key)` | Reports whether the key exists. |
| `Len()` | Number of middlewares. |
| `Keys()` | Returns a copy of the current key order. |
| `Index(key)` | Returns position of the key, or `-1` if not found. |
| `String()` | Human-readable stack listing (implements `fmt.Stringer`). |
| `Apply(fn)` | Batch mutations via `PipelineBuilder`, single atomic swap. |
| `ApplyWithTimeout(fn, grace)` | Batch + cancel old in-flight after grace. |
| `Reset()` | Remove all middlewares atomically. |

#### PipelineBuilder

Available inside `Apply` / `ApplyWithTimeout` callbacks:

| Method | Description |
|---|---|
| `Set(key, mw)` | Add or replace (same as Pipeline.Set). |
| `SetAt(index, key, mw)` | Add or replace at position. |
| `Remove(key)` | Remove by key. |
| `Reset()` | Clear all entries. |
| `Has(key)` | Check if key exists. |
| `Keys()` | Current key order. |
| `Len()` | Number of entries. |

## In-Flight Request Safety

Both Slot and Pipeline use atomic snapshots with copy-on-write semantics. When a mutation occurs:

1. A new immutable snapshot is created
2. The new snapshot is stored via `atomic.Pointer.Store`
3. New requests immediately use the new snapshot
4. In-flight requests continue with the old snapshot undisturbed
5. The old snapshot is garbage-collected when all references are released

No request ever sees a partial or mixed state. Each request observes exactly one consistent snapshot for its entire lifetime.

### Resource Cleanup

When a middleware is replaced, the old instance stays alive until all in-flight requests using it complete and the garbage collector reclaims it. For middlewares that hold external resources (e.g. `ForwardAuth` with an `http.Client`):

- **Keep-alive connections**: cleaned up by Go's transport idle timeout (typically 90s)
- **Active requests**: complete normally — no connection is killed mid-flight
- **Explicit cleanup**: if needed, hold a reference to the old middleware and close resources after the swap

## Performance

| Primitive | Per-request cost | On mutation |
|---|---|---|
| Static middleware (no Slot/Pipeline) | ~30 ns, 0 allocs (baked at registration) | N/A |
| Slot | ~35 ns, 0 allocs (pre-built chain, 2 atomic loads) | 1 atomic store + chain rebuild |
| Pipeline | ~40 ns, 0 allocs (pre-built chain, 2 atomic loads) | mutex + copy-on-write + chain rebuild |
| Slot with `WithTimeout` active | ~400 ns (context derivation + cleanup) | 1 atomic store + chain rebuild |
| Pipeline with `ApplyWithTimeout` active | ~400 ns (context derivation + cleanup) | mutex + copy-on-write + chain rebuild |

Slot and Pipeline have near-zero overhead compared to static middlewares (~5-8 ns difference). The cancel context for `WithTimeout` variants is **opt-in** — it is only created when you call `ReplaceWithTimeout`, `DisableWithTimeout`, or `ApplyWithTimeout`. Regular `Replace`, `Disable`, `Set`, `Remove`, and `Apply` do not create cancel contexts and have zero allocation overhead.

Static middlewares keep their zero-overhead baked path. Only routes that use a Slot or Pipeline pay the additional atomic-load cost.

## Choosing Between Slot and Pipeline

| Use case | Recommended |
|---|---|
| Toggle one middleware (e.g. auth on/off) | **Slot** |
| Replace one middleware's config | **Slot** |
| Manage multiple middlewares by name | **Pipeline** |
| Add new middlewares after server start | **Pipeline** |
| Remove middlewares entirely | **Pipeline** |
| Rebuild entire middleware stack atomically | **Pipeline** with `Apply` + `Reset` |

## Helper

### NoOp

`ada.NoOp()` returns a middleware that does nothing and passes through to the next handler. Useful as a placeholder:

```go
// Start with a disabled slot
auth := ada.NewSlot(ada.NoOp())
server.Use(auth.Middleware())

// Enable later
auth.Replace(forwardauth.Middleware(...))
```
