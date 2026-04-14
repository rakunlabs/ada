package session

import "context"

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
