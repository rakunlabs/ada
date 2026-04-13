package ada

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// noopHandler is a minimal handler for benchmarks.
var noopHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

// noopMiddleware is a minimal middleware for benchmarks.
func noopMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// ── Router lookup benchmarks ────────────────────────────────────────────────

func BenchmarkRouter_StaticRoot(b *testing.B) {
	mux := NewMux()
	mux.GET("/", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkRouter_StaticShort(b *testing.B) {
	mux := NewMux()
	mux.GET("/users", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkRouter_StaticDeep(b *testing.B) {
	mux := NewMux()
	mux.GET("/api/v1/users/list/all", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/list/all", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkRouter_Param1(b *testing.B) {
	mux := NewMux()
	mux.GET("/users/{id}", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/users/12345", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkRouter_Param3(b *testing.B) {
	mux := NewMux()
	mux.GET("/api/{version}/users/{userId}/posts/{postId}", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v2/users/42/posts/789", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkRouter_Wildcard(b *testing.B) {
	mux := NewMux()
	mux.GET("/files/*", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/files/css/style.min.css", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkRouter_MixedRoutes50(b *testing.B) {
	mux := NewMux()
	registerMixedRoutes(mux, 50)

	req := httptest.NewRequest(http.MethodGet, "/api/route-25/detail", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkRouter_MixedRoutes200(b *testing.B) {
	mux := NewMux()
	registerMixedRoutes(mux, 200)

	req := httptest.NewRequest(http.MethodGet, "/api/route-100/detail", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkRouter_NotFound(b *testing.B) {
	mux := NewMux()
	mux.GET("/users", noopHandler)
	mux.GET("/posts", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/nonexistent/path", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkRouter_MethodNotAllowed(b *testing.B) {
	mux := NewMux()
	mux.GET("/users", noopHandler)
	mux.POST("/users", noopHandler)

	req := httptest.NewRequest(http.MethodDelete, "/users", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

// ── Middleware overhead benchmarks ──────────────────────────────────────────

func BenchmarkMiddleware_0(b *testing.B) {
	mux := NewMux()
	mux.GET("/test", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkMiddleware_1(b *testing.B) {
	mux := NewMux()
	mux.Use(noopMiddleware)
	mux.GET("/test", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkMiddleware_5(b *testing.B) {
	mux := NewMux()
	for range 5 {
		mux.Use(noopMiddleware)
	}
	mux.GET("/test", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkMiddleware_10(b *testing.B) {
	mux := NewMux()
	for range 10 {
		mux.Use(noopMiddleware)
	}
	mux.GET("/test", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

// ── Slot / Pipeline overhead benchmarks ─────────────────────────────────────

func BenchmarkSlot(b *testing.B) {
	mux := NewMux()
	slot := NewSlot(noopMiddleware)
	mux.Use(slot.Middleware())
	mux.GET("/test", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkPipeline_3(b *testing.B) {
	mux := NewMux()
	p := NewPipeline()
	p.Set("a", noopMiddleware)
	p.Set("b", noopMiddleware)
	p.Set("c", noopMiddleware)
	mux.Use(p.Middleware())
	mux.GET("/test", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkPipeline_5(b *testing.B) {
	mux := NewMux()
	p := NewPipeline()
	for i := range 5 {
		p.Set(fmt.Sprintf("mw-%d", i), noopMiddleware)
	}
	mux.Use(p.Middleware())
	mux.GET("/test", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// registerMixedRoutes registers n routes with a mix of static, param, and wildcard patterns.
func registerMixedRoutes(mux *Mux, n int) {
	for i := range n {
		path := fmt.Sprintf("/api/route-%d/detail", i)
		mux.GET(path, noopHandler)

		paramPath := fmt.Sprintf("/api/route-%d/{id}", i)
		mux.GET(paramPath, noopHandler)
	}
}
