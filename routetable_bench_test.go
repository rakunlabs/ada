package ada

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkRouter_RuntimePublish(b *testing.B) {
	for _, routes := range []int{50, 200, 1000} {
		b.Run(fmt.Sprintf("routes=%d", routes), func(b *testing.B) {
			mux := NewMux()
			for i := range routes {
				mux.HandleWithMethod(http.MethodGet, fmt.Sprintf("/route/%d", i), noopHandler)
			}

			// Publish the startup table; replacements below exercise eager
			// runtime publication rather than first-request initialization.
			mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/route/0", nil))

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				mux.HandleWithMethod(http.MethodGet, "/route/0", noopHandler)
			}
		})
	}
}
