package benchmark

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rakunlabs/ada"
)

var adaNoopHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

func adaNoopMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func setupAdaStatic() *ada.Mux {
	mux := ada.NewMux()
	for _, r := range StaticRoutes {
		mux.HandleWithMethod(r.Method, r.Path, adaNoopHandler)
	}

	return mux
}

func setupAdaParam() *ada.Mux {
	mux := ada.NewMux()
	for _, r := range AdaParamRoutes {
		mux.HandleWithMethod(r.Method, r.Pattern, adaNoopHandler)
	}

	return mux
}

// ── Static routes ───────────────────────────────────────────────────────────

func BenchmarkAda_StaticAll(b *testing.B) {
	mux := setupAdaStatic()
	reqs := make([]*http.Request, len(StaticRoutes))
	for i, r := range StaticRoutes {
		reqs[i] = httptest.NewRequest(r.Method, r.Path, nil)
	}

	rec := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		for _, req := range reqs {
			mux.ServeHTTP(rec, req)
		}
	}
}

func BenchmarkAda_StaticSingle(b *testing.B) {
	mux := setupAdaStatic()
	req := httptest.NewRequest("GET", "/api/v1/users/list/all", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

// ── Parameterized routes ────────────────────────────────────────────────────

func BenchmarkAda_Param1(b *testing.B) {
	mux := setupAdaParam()
	req := httptest.NewRequest("GET", "/users/12345", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

func BenchmarkAda_Param3(b *testing.B) {
	mux := setupAdaParam()
	req := httptest.NewRequest("GET", "/api/v2/users/42/posts/789", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}

// ── Middleware ───────────────────────────────────────────────────────────────

func BenchmarkAda_Middleware5(b *testing.B) {
	mux := ada.NewMux()
	for range 5 {
		mux.Use(adaNoopMiddleware)
	}

	mux.GET("/test", adaNoopHandler)
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		mux.ServeHTTP(rec, req)
	}
}
