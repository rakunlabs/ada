package ada

import (
	"fmt"
	"net/http"
	"path"
)

// MethodQuery is the QUERY HTTP method, a safe and idempotent method that
// carries the query semantics in the request body. Defined in RFC 10008
// "The HTTP QUERY Method"; not yet available as a constant in net/http.
const MethodQuery = "QUERY"

// Mux is ada's router.
//
// Routes may be added with the routing methods and dropped with Remove at any
// time, including while the server is serving: the routing table is published
// as an immutable snapshot and a request keeps the snapshot it started with.
//
// Everything else on the Mux — Use, Group, NotFound, MethodNotAllowed,
// ErrorHandler — is setup-time only and must be configured before the first
// request. Use a Slot or a Pipeline for middlewares that need to change on a
// running server.
type Mux struct {
	// routes is shared by pointer with every Group derived from this Mux, so
	// a group's registrations land in the same tree. It is safe to mutate
	// while the server is serving; see routeTable.
	routes *routeTable

	errHandler       func(c *Context, err error)
	notFound         http.HandlerFunc
	methodNotAllowed http.HandlerFunc
	middlewares      []func(next http.Handler) http.Handler
	prefix           string

	// Pre-chained 404/405 handlers. Rebuilt whenever middlewares or the
	// custom handlers change (registration time), so the request path
	// never rebuilds the middleware chain — previously every 404/405
	// allocated len(middlewares) closures via Chain.
	notFoundChain         http.Handler
	methodNotAllowedChain http.Handler
	autoOptionsChain      http.Handler
}

func NewMux() *Mux {
	m := &Mux{
		routes: newRouteTable(),
	}
	m.rebuildErrorChains()

	return m
}

// rebuildErrorChains re-composes the middleware chain around the 404, 405 and
// auto-OPTIONS handlers. Called at every mutation point (NewMux, Use, Group,
// NotFound, MethodNotAllowed) so ServeHTTP only reads the cached chains.
//
// Routing these three through the middleware chain is what makes headers set
// by middleware (CORS being the obvious one) present on the responses that
// most need them.
func (m *Mux) rebuildErrorChains() {
	notFound := m.notFound
	if notFound == nil {
		notFound = http.NotFound
	}
	m.notFoundChain = Chain(m.middlewares...)(notFound)

	methodNotAllowed := m.methodNotAllowed
	if methodNotAllowed == nil {
		methodNotAllowed = func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
	m.methodNotAllowedChain = Chain(m.middlewares...)(methodNotAllowed)

	// The Allow header varies per node, so it is written by the caller
	// before the chain runs; this terminal handler only emits the status.
	m.autoOptionsChain = Chain(m.middlewares...)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
}

// scopeErrors marks the subtree under this Mux's prefix as belonging to this
// Mux for error dispatch, so 404/405/auto-OPTIONS responses below a Group run
// that Group's middleware chain and its NotFound/MethodNotAllowed handlers.
//
// The marker is metadata on the wildcard node, not a route: it never answers a
// request, so it cannot shadow a real handler.
func (m *Mux) scopeErrors() {
	prefix := m.prefix

	m.routes.mutate(func(root *node) {
		scope, _, _ := root.insertPath(prefix + "/*")
		scope.errorScope = m
	})
}

// errorMux resolves which Mux handles an error response: the deepest scope the
// request walked through, falling back to the Mux that is serving.
func (m *Mux) errorMux(scope *Mux) *Mux {
	if scope != nil {
		return scope
	}

	return m
}

// RouteHandler lists the handler shapes the routing methods accept.
//
// Both plain net/http handlers and ada's Context-style handlers are allowed.
// Context-style handlers are bound to the Mux they are registered on, so that
// Mux's ErrorHandler receives their returned errors:
//
//	mux.GET("/a", func(w http.ResponseWriter, r *http.Request) { ... })
//	mux.GET("/b", func(c *ada.Context) error { ... })
type RouteHandler interface {
	func(http.ResponseWriter, *http.Request) |
		http.HandlerFunc |
		func(*Context) error |
		HandlerFunc
}

// resolveHandler converts any RouteHandler shape into an http.HandlerFunc.
//   - Context-style handlers are wrapped against this Mux, so ErrorHandler applies.
//   - Runs at registration time only; the request path is unaffected.
func (m *Mux) resolveHandler(handler any) http.HandlerFunc {
	switch h := handler.(type) {
	case func(http.ResponseWriter, *http.Request):
		return h
	case http.HandlerFunc:
		return h
	case func(*Context) error:
		return m.Wrap(h)
	case HandlerFunc:
		return m.Wrap(h)
	default:
		panic(fmt.Sprintf("ada: unsupported handler type %T", handler))
	}
}

// HandleWithMethod registers an http.HandlerFunc for the given method.
//   - This is the non-generic primitive: it is the method to embed in an
//     interface when abstracting over *Mux, because Go interfaces cannot
//     declare (nor be satisfied by) generic methods.
func (m *Mux) HandleWithMethod(method, path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	handlerFunc := Chain(append(m.middlewares, middlewares...)...)(handler)

	m.routes.insert(method, m.routePath(path), handlerFunc.ServeHTTP)
}

func (m *Mux) GET[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodGet, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) POST[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodPost, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) PUT[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodPut, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) PATCH[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodPatch, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) DELETE[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodDelete, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) HEAD[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodHead, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) OPTIONS[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodOptions, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) TRACE[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodTrace, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) CONNECT[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(http.MethodConnect, path, m.resolveHandler(any(handler)), middlewares...)
}

// QUERY registers a handler for the QUERY HTTP method, a safe and idempotent
// method with a request body carrying the query (RFC 10008).
func (m *Mux) QUERY[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod(MethodQuery, path, m.resolveHandler(any(handler)), middlewares...)
}

func (m *Mux) HandleFunc[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleWithMethod("", path, m.resolveHandler(any(handler)), middlewares...)
}

// HandleFuncWildcard is registering all paths under the given path.
func (m *Mux) HandleFuncWildcard[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleFunc(normalizeWildcardPath(path), handler, middlewares...)
}

func (m *Mux) Handle(path string, handler http.Handler, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleFunc(path, handler.ServeHTTP, middlewares...)
}

// HandleWildcard is registering all paths under the given path.
func (m *Mux) HandleWildcard(path string, handler http.Handler, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleFuncWildcard(path, handler.ServeHTTP, middlewares...)
}

// Use appends middlewares to this Mux's chain.
//
// Unlike route registration, Use is a setup-time operation: it rewrites the
// middleware slice that route registration reads and the pre-built 404/405
// chains that ServeHTTP reads, neither of which is synchronised. Call it before
// the server starts.
//
// To change middlewares on a running server, register a Slot or a Pipeline once
// during setup and mutate that instead — those are built for it.
func (m *Mux) Use(middlewares ...func(next http.Handler) http.Handler) {
	if len(middlewares) == 0 {
		return
	}

	m.middlewares = append(m.middlewares, middlewares...)
	m.rebuildErrorChains()

	// Claim this prefix for error dispatch so the middlewares just added
	// also run on unmatched paths below it.
	m.scopeErrors()
}

func (m Mux) Group(pathGroup string, middlewares ...func(next http.Handler) http.Handler) *Mux {
	m.prefix = path.Join("/", m.prefix, pathGroup)
	if m.prefix == "/" {
		m.prefix = ""
	}

	// Defensive copy: Mux is taken by value, so m.middlewares' slice
	// header was duplicated, but it still points at the parent's backing
	// array. Without copying here, sibling groups created from the same
	// parent (`a := s.Group(); b := s.Group()`) would share that backing
	// array — and a later `b.Use(...)` could append-in-place into a slot
	// that `a` already considers part of its chain (or vice versa),
	// silently corrupting the middleware order on whichever group ran
	// `Use` first. Allocating a fresh slice with len == cap pins this
	// child group to its own storage and makes append always grow.
	parent := m.middlewares
	m.middlewares = make([]func(next http.Handler) http.Handler, len(parent), len(parent)+len(middlewares))
	copy(m.middlewares, parent)
	m.middlewares = append(m.middlewares, middlewares...)
	m.rebuildErrorChains()
	// Claim the group prefix so 404/405/OPTIONS below it run this group's
	// chain rather than the parent's.
	(&m).scopeErrors()

	return &m
}

// Prefix returns the current prefix of the Mux.
//   - Useful when giving basepath for sub-routers.
func (m *Mux) Prefix() string {
	return m.prefix
}

// NotFound sets the handler for 404 Not Found responses.
//   - If not set, it defaults to http.NotFound.
func (m *Mux) NotFound(handler http.HandlerFunc) {
	m.notFound = handler
	m.rebuildErrorChains()
	// Claim the prefix so a group's handler actually takes effect without
	// requiring an unrelated Use call first.
	m.scopeErrors()
}

func (m *Mux) notFoundHandler(w http.ResponseWriter, r *http.Request, scope *Mux) {
	// Pre-chained at registration time; no per-request chain rebuild.
	m.errorMux(scope).notFoundChain.ServeHTTP(w, r)
}

// MethodNotAllowed sets the handler for 405 Method Not Allowed responses.
//   - If not set, it defaults to a standard 405 text response.
//   - The Allow header is always set before the handler is called.
func (m *Mux) MethodNotAllowed(handler http.HandlerFunc) {
	m.methodNotAllowed = handler
	m.rebuildErrorChains()
	m.scopeErrors()
}

func (m *Mux) methodNotAllowedHandler(w http.ResponseWriter, r *http.Request, allowed string, scope *Mux) {
	w.Header().Set("Allow", allowed)

	// Pre-chained at registration time; no per-request chain rebuild.
	m.errorMux(scope).methodNotAllowedChain.ServeHTTP(w, r)
}

// ErrorHandler sets the handler for 500 Internal Server Error responses.
//   - If not set, it defaults to a generic error handler.
//   - Only usable for ada.HandlerFunc handlers.
func (m *Mux) ErrorHandler(handler func(c *Context, err error)) {
	m.errHandler = handler
}

// Chain is a utility function to chain multiple middleware functions together.
func Chain(middlewares ...func(next http.Handler) http.Handler) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}

		return next
	}
}
