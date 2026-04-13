package benchmark

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.ReleaseMode)
}

var ginNoopHandler = func(c *gin.Context) {}

func ginNoopMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

func setupGinStatic() *gin.Engine {
	r := gin.New()
	for _, route := range StaticRoutes {
		r.Handle(route.Method, route.Path, ginNoopHandler)
	}

	return r
}

func setupGinParam() *gin.Engine {
	r := gin.New()
	for _, route := range ParamRoutes {
		r.Handle(route.Method, route.Pattern, ginNoopHandler)
	}

	return r
}

// ── Static routes ───────────────────────────────────────────────────────────

func BenchmarkGin_StaticAll(b *testing.B) {
	r := setupGinStatic()
	reqs := make([]*http.Request, len(StaticRoutes))
	recs := make([]*httptest.ResponseRecorder, len(StaticRoutes))
	for i, route := range StaticRoutes {
		reqs[i] = httptest.NewRequest(route.Method, route.Path, nil)
		recs[i] = httptest.NewRecorder()
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		for i, req := range reqs {
			r.ServeHTTP(recs[i], req)
		}
	}
}

func BenchmarkGin_StaticSingle(b *testing.B) {
	r := setupGinStatic()
	req := httptest.NewRequest("GET", "/api/v1/users/list/all", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		r.ServeHTTP(rec, req)
	}
}

// ── Parameterized routes ────────────────────────────────────────────────────

func BenchmarkGin_Param1(b *testing.B) {
	r := setupGinParam()
	req := httptest.NewRequest("GET", "/users/12345", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		r.ServeHTTP(rec, req)
	}
}

func BenchmarkGin_Param3(b *testing.B) {
	r := setupGinParam()
	req := httptest.NewRequest("GET", "/api/v2/users/42/posts/789", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		r.ServeHTTP(rec, req)
	}
}

// ── Middleware ───────────────────────────────────────────────────────────────

func BenchmarkGin_Middleware5(b *testing.B) {
	r := gin.New()
	for range 5 {
		r.Use(ginNoopMiddleware())
	}

	r.GET("/test", ginNoopHandler)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		r.ServeHTTP(rec, req)
	}
}
