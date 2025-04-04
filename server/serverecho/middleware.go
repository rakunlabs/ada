package serverecho

import (
	"context"

	"github.com/labstack/echo/v4"

	"github.com/rakunlabs/rest/server"
)

const (
	// UserKey is the key for the user in the context and value is string.
	UserKey = "X-User"
	// BrowserKey is the key for the browser in the context and value is bool.
	BrowserKey = "X-Browser"
)

// MiddlewareUserInfo adds the user and browser to echo's store.
//
//	user, _ := c.Get(UserKey).(string)
//	isBrowser, _ := c.Get(BrowserKey).(bool)
func MiddlewareUserInfo(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := c.Request().Header.Get(UserKey)
		c.Set(UserKey, user)

		browser := server.IsBrowser(c.Request().Header.Get("User-Agent"))
		c.Set(BrowserKey, browser)

		return next(c)
	}
}

// MiddlewareUserInfoWithCtx adds the user and browser to echo's store with request context.
func MiddlewareUserInfoWithCtx(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := c.Request().Header.Get(UserKey)
		c.Set(UserKey, user)

		browser := server.IsBrowser(c.Request().Header.Get("User-Agent"))
		c.Set(BrowserKey, browser)

		// add to request context
		ctx := c.Request().Context()

		ctx = context.WithValue(ctx, UserKey, user)
		ctx = context.WithValue(ctx, BrowserKey, browser)

		c.SetRequest(c.Request().WithContext(ctx))

		return next(c)
	}
}
