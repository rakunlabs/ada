package benchmark

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
)

var echoNoopHandler = func(c *echo.Context) error { return nil }

func echoNoopMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		return next(c)
	}
}

func setupEchoStatic() *echo.Echo {
	e := echo.New()
	for _, r := range StaticRoutes {
		e.Add(r.Method, r.Path, echoNoopHandler)
	}

	return e
}

func setupEchoParam() *echo.Echo {
	e := echo.New()
	for _, r := range ParamRoutes {
		e.Add(r.Method, r.Pattern, echoNoopHandler)
	}

	return e
}

// ── Static routes ───────────────────────────────────────────────────────────

func BenchmarkEcho_StaticAll(b *testing.B) {
	e := setupEchoStatic()
	reqs := make([]*http.Request, len(StaticRoutes))
	recs := make([]*httptest.ResponseRecorder, len(StaticRoutes))
	for i, r := range StaticRoutes {
		reqs[i] = httptest.NewRequest(r.Method, r.Path, nil)
		recs[i] = httptest.NewRecorder()
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		for i, req := range reqs {
			e.ServeHTTP(recs[i], req)
		}
	}
}

func BenchmarkEcho_StaticSingle(b *testing.B) {
	e := setupEchoStatic()
	req := httptest.NewRequest("GET", "/api/v1/users/list/all", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		e.ServeHTTP(rec, req)
	}
}

// ── Parameterized routes ────────────────────────────────────────────────────

func BenchmarkEcho_Param1(b *testing.B) {
	e := setupEchoParam()
	req := httptest.NewRequest("GET", "/users/12345", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		e.ServeHTTP(rec, req)
	}
}

func BenchmarkEcho_Param3(b *testing.B) {
	e := setupEchoParam()
	req := httptest.NewRequest("GET", "/api/v2/users/42/posts/789", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		e.ServeHTTP(rec, req)
	}
}

// ── Middleware ───────────────────────────────────────────────────────────────

func BenchmarkEcho_Middleware5(b *testing.B) {
	e := echo.New()
	for range 5 {
		e.Use(echoNoopMiddleware)
	}

	e.GET("/test", echoNoopHandler)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		e.ServeHTTP(rec, req)
	}
}
