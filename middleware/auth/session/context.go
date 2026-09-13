package session

import (
	"context"
	"net/http"
)

type ctxKey int

const (
	ctxKeyDisableRedirect ctxKey = iota
	ctxKeyCookieName
)

// SetDisableRedirect makes the session middleware return a 401 instead of a
// 307 redirect for unauthenticated requests on this context.
func SetDisableRedirect(ctx context.Context, v bool) context.Context {
	return context.WithValue(ctx, ctxKeyDisableRedirect, v)
}

// GetDisableRedirect reports whether RedirectToLogin should return a 401 for
// requests carrying this context.
func GetDisableRedirect(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKeyDisableRedirect).(bool)

	return v
}

// DisableRedirect returns a middleware that marks every request under it as
// non-interactive, so an unauthenticated caller gets 401 with a
// WWW-Authenticate challenge instead of a 303 to the login page.
//
// Put it in front of anything a program talks to rather than a person — a
// JSON API, an MCP endpoint, a webhook receiver. A redirect to an HTML login
// form is a dead end for those callers: they follow it, get 200 and a page
// they cannot parse, and report a bizarre failure far from its cause. The
// 401 carries the RFC 9728 resource_metadata pointer, which is what lets an
// MCP client discover the authorization server and authenticate on its own.
//
//	api := mux.Group("/mcp")
//	api.Use(session.DisableRedirect(), authMW.Require())
func DisableRedirect() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(SetDisableRedirect(r.Context(), true)))
		})
	}
}

// SetCookieName overrides the session cookie name for this request. Useful
// when downstream code needs to act on a different bucket.
func SetCookieName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, ctxKeyCookieName, name)
}

// GetCookieName returns the cookie-name override for this context, or "".
func GetCookieName(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyCookieName).(string)

	return v
}
