package ada

import (
	"fmt"
	"net/http"
	"path"
	"strings"
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
//
// Path handling: Mux matches on the decoded r.URL.Path as received. Unlike
// net/http.ServeMux it does NOT apply path.Clean and does NOT redirect to a
// canonical form. Two consequences are security-relevant:
//
//   - Values returned by r.PathValue are attacker-controlled and may contain
//     ".." and "." segments, whether sent literally or percent-encoded
//     ("/static/..%2f..%2fetc/passwd" decodes to "/static/../../etc/passwd"
//     before matching). A greedy capture MUST be cleaned and confined before
//     being used as a filesystem path — prefer os.OpenRoot or an fs.FS over
//     filepath.Join on raw input.
//   - "%2F" decodes to a real separator, so a {name} param can never capture a
//     slash: GET /users/a%2Fb is matched as /users/a/b.
type Mux struct {
	// routes is shared by pointer with every Group derived from this Mux, so
	// a group's registrations land in the same tree. It is safe to mutate
	// while the server is serving; see routeTable.
	routes *routeTable

	// parent is the Mux this one was derived from with Group; nil on a root
	// Mux. children are the Groups derived from this one.
	//
	// The links exist so a Group keeps tracking its parent instead of
	// freezing a copy of it at creation time: a later NotFound,
	// MethodNotAllowed or Use on the parent has to reach every descendant
	// that has not overridden that same behaviour. They are written only by
	// Group, which — like every other configuration method here — is
	// setup-time only, so they need no synchronisation.
	parent   *Mux
	children []*Mux

	errHandler func(c *Context, err error)

	// notFound and methodNotAllowed hold only what was set on THIS Mux. nil
	// means "not overridden here", which is what lets resolveNotFound and
	// resolveMethodNotAllowed inherit the nearest ancestor's choice.
	notFound         http.HandlerFunc
	methodNotAllowed http.HandlerFunc

	// ownMiddlewares are the middlewares added on this Mux itself: the
	// Group's own arguments plus everything a later Use appended. It is the
	// authoritative record, because the effective chain below is derived and
	// recomputed whenever an ancestor changes.
	ownMiddlewares []func(next http.Handler) http.Handler
	// middlewares is the effective chain — every ancestor's, outermost
	// first, then ownMiddlewares. Route registration reads it. Each refresh
	// allocates it fresh with len == cap, so sibling Groups can never share
	// a backing array and append into each other's slots.
	middlewares []func(next http.Handler) http.Handler

	prefix string

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

// refresh recomputes this Mux's effective middleware chain from its parent,
// rebuilds its cached error chains, and cascades to every Group derived from
// it.
//
// The cascade is what makes a Group track its parent. Group used to copy the
// parent Mux by value and then claim its prefix for error dispatch, so the
// snapshot it took at creation time was frozen: a NotFound, MethodNotAllowed
// or Use applied to the parent afterwards rebuilt only the parent's chains,
// while the prefix node still pointed at the child — and every 404/405 below
// the group kept answering with the defaults the child had captured.
//
// Setup-time only, like every caller that reaches it.
func (m *Mux) refresh() {
	var inherited []func(next http.Handler) http.Handler
	if m.parent != nil {
		inherited = m.parent.middlewares
	}

	if len(inherited) == 0 && len(m.ownMiddlewares) == 0 {
		m.middlewares = nil
	} else {
		// len == cap, so a later append cannot write into storage a
		// sibling Group also considers its own.
		chain := make([]func(next http.Handler) http.Handler, 0, len(inherited)+len(m.ownMiddlewares))
		chain = append(chain, inherited...)
		chain = append(chain, m.ownMiddlewares...)
		m.middlewares = chain
	}

	m.rebuildErrorChains()

	for _, child := range m.children {
		child.refresh()
	}
}

// resolveNotFound returns the 404 handler in effect here: this Mux's own, else
// the nearest ancestor that set one, else the net/http default. Walking the
// chain instead of copying the parent's handler at Group creation is what lets
// a group inherit a NotFound the parent installs later.
func (m *Mux) resolveNotFound() http.HandlerFunc {
	for scope := m; scope != nil; scope = scope.parent {
		if scope.notFound != nil {
			return scope.notFound
		}
	}

	return http.NotFound
}

// resolveMethodNotAllowed is resolveNotFound's 405 counterpart.
func (m *Mux) resolveMethodNotAllowed() http.HandlerFunc {
	for scope := m; scope != nil; scope = scope.parent {
		if scope.methodNotAllowed != nil {
			return scope.methodNotAllowed
		}
	}

	return func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// rebuildErrorChains re-composes the middleware chain around the 404, 405 and
// auto-OPTIONS handlers. Called at every mutation point (NewMux, Use, Group,
// NotFound, MethodNotAllowed) so ServeHTTP only reads the cached chains.
//
// Routing these three through the middleware chain is what makes headers set
// by middleware (CORS being the obvious one) present on the responses that
// most need them.
func (m *Mux) rebuildErrorChains() {
	m.notFoundChain = Chain(m.middlewares...)(m.resolveNotFound())
	m.methodNotAllowedChain = Chain(m.middlewares...)(m.resolveMethodNotAllowed())

	// The Allow header varies per node, so it is written by the caller
	// before the chain runs; this terminal handler only emits the status.
	m.autoOptionsChain = Chain(m.middlewares...)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
}

// scopeErrors marks this Mux's prefix as belonging to it for error dispatch, so
// 404/405/auto-OPTIONS responses at and below a Group run that Group's
// middleware chain and its NotFound/MethodNotAllowed handlers.
//
// The marker is metadata on the actual prefix node, not a synthetic wildcard
// route. This lets the prefix itself inherit the scope and supports groups whose
// prefixes already contain wildcard syntax. If multiple Groups share a prefix,
// the most recent scope configuration applies uniformly below that prefix.
func (m *Mux) scopeErrors() {
	prefix := m.prefix

	m.routes.mutate(func(root *node) {
		scope, _, _ := root.insertPath(prefix)
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

// checkMethod rejects a method that could never match a request.
//
// Route selection compares against r.Method, which net/http delivers verbatim
// and which RFC 9110 defines as case-sensitive — so "get" registers a route
// that is unreachable for the rest of the process's life, and reports nothing.
// It is a typo with no legitimate reading, so it fails at boot like the
// ambiguous patterns trie_insert rejects, rather than being silently upcased
// into a route the caller did not write.
//
// The empty method is the documented catch-all used by Handle and HandleFunc
// and is always accepted.
func checkMethod(method string) {
	if method == "" {
		return
	}

	for i := range len(method) {
		if isUpperMethodChar(method[i]) {
			continue
		}

		panic(fmt.Sprintf(
			"ada: invalid HTTP method %q: methods are case-sensitive and must be uppercase RFC 9110 tokens (use \"\" for a catch-all)",
			method,
		))
	}
}

// isUpperMethodChar reports whether c may appear in a canonical method: an RFC
// 9110 token character that is not a lowercase letter.
func isUpperMethodChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c >= 'a' && c <= 'z':
		return false
	}

	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// HandleWithMethod registers an http.HandlerFunc for the given method.
//   - This is the non-generic primitive: it is the method to embed in an
//     interface when abstracting over *Mux, because Go interfaces cannot
//     declare (nor be satisfied by) generic methods.
//   - Panics if method is neither "" nor a valid uppercase HTTP method token;
//     see checkMethod.
func (m *Mux) HandleWithMethod(method, path string, handler http.HandlerFunc, middlewares ...func(next http.Handler) http.Handler) {
	checkMethod(method)

	combined := make([]MiddlewareFunc, 0, len(m.middlewares)+len(middlewares))
	combined = append(combined, m.middlewares...)
	combined = append(combined, middlewares...)
	handlerFunc := Chain(combined...)(handler)

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
//
// The greedy capture is the decoded remainder of r.URL.Path as received: Mux
// applies no path.Clean and no canonicalizing redirect, so r.PathValue("*") is
// attacker-controlled and may contain ".." and "." segments, sent literally or
// percent-encoded ("/static/..%2f..%2fetc/passwd" decodes to
// "/static/../../etc/passwd" before matching). Clean and confine it before
// using it as a filesystem path — prefer os.OpenRoot or an fs.FS over
// filepath.Join on raw input. See the Mux type documentation.
func (m *Mux) HandleFuncWildcard[H RouteHandler](path string, handler H, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleFunc(normalizeWildcardPath(path), handler, middlewares...)
}

func (m *Mux) Handle(path string, handler http.Handler, middlewares ...func(next http.Handler) http.Handler) {
	m.HandleFunc(path, handler.ServeHTTP, middlewares...)
}

// HandleWildcard is registering all paths under the given path.
//
// The greedy capture is the decoded remainder of r.URL.Path as received: Mux
// applies no path.Clean and no canonicalizing redirect, so r.PathValue("*") is
// attacker-controlled and may contain ".." and "." segments, sent literally or
// percent-encoded ("/static/..%2f..%2fetc/passwd" decodes to
// "/static/../../etc/passwd" before matching). Clean and confine it before
// using it as a filesystem path — prefer os.OpenRoot or an fs.FS over
// filepath.Join on raw input. See the Mux type documentation.
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

	// Recorded as this Mux's own, then re-derived: refresh rebuilds the
	// effective chain here and in every descendant Group, so root
	// middleware added after a Group was created still runs on the 404s
	// and 405s below that group's prefix.
	m.ownMiddlewares = append(m.ownMiddlewares, middlewares...)
	m.refresh()

	// Claim this prefix for error dispatch so the middlewares just added
	// also run on unmatched paths below it.
	m.scopeErrors()
}

// Group returns a Mux that shares this one's routing table but registers under
// an additional path prefix, with additional middlewares.
//
// A group inherits, rather than snapshots, its parent's configuration: a
// NotFound, MethodNotAllowed or Use applied to the parent after the group was
// created still takes effect below the group's prefix. A group that sets its
// own keeps winning for that specific behaviour, and only for it — overriding
// NotFound does not detach the group from a later parent Use.
//
// Where two Groups share the same prefix, the most recently created (or most
// recently reconfigured) one owns the error scope for everything below it, as
// the prefix node can only point at one Mux.
func (m *Mux) Group(pathGroup string, middlewares ...func(next http.Handler) http.Handler) *Mux {
	prefix := path.Join("/", m.prefix, pathGroup)
	if prefix == "/" {
		prefix = ""
	}

	group := &Mux{
		routes: m.routes,
		parent: m,
		// ErrorHandler is not part of the error-chain cascade: it is read
		// through the wrapper a Context handler was registered with, so it
		// is captured here exactly as it was before.
		errHandler: m.errHandler,
		prefix:     prefix,
		// Copied out of the variadic slice so the caller cannot mutate the
		// group's chain afterwards, and so this group owns storage no
		// sibling shares.
		ownMiddlewares: append([]func(next http.Handler) http.Handler(nil), middlewares...),
	}

	m.children = append(m.children, group)
	group.refresh()

	// Claim the group prefix so 404/405/OPTIONS below it run this group's
	// chain rather than the parent's.
	group.scopeErrors()

	return group
}

// Prefix returns the current prefix of the Mux.
//   - Useful when giving basepath for sub-routers.
func (m *Mux) Prefix() string {
	return m.prefix
}

// NotFound sets the handler for 404 Not Found responses.
//   - If not set, it defaults to http.NotFound.
//   - Groups derived from this Mux that have not set their own inherit it,
//     whether they were created before or after this call.
func (m *Mux) NotFound(handler http.HandlerFunc) {
	m.notFound = handler
	m.refresh()
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
//   - Groups derived from this Mux that have not set their own inherit it,
//     whether they were created before or after this call.
func (m *Mux) MethodNotAllowed(handler http.HandlerFunc) {
	m.methodNotAllowed = handler
	m.refresh()
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
