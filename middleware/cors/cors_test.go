package cors

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"sync"
	"testing"
)

func TestOrdinaryOptionsPassesDownstream(t *testing.T) {
	tests := []struct {
		name   string
		origin string
	}{
		{name: "without origin"},
		{name: "with origin", origin: "https://client.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusAccepted)
			})
			handler := (&Cors{AllowOrigins: []string{"https://client.example"}}).Middleware()(next)

			req := httptest.NewRequest(http.MethodOptions, "/resource", nil)
			if tt.origin != "" {
				req.Header.Set(headerOrigin, tt.origin)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if !called {
				t.Fatal("ordinary OPTIONS request did not reach downstream handler")
			}
			if rec.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusAccepted)
			}
		})
	}
}

func TestPreflightValidatesMethodAndHeaders(t *testing.T) {
	config := Cors{
		AllowOrigins: []string{"https://client.example"},
		AllowMethods: []string{http.MethodGet, http.MethodPost},
		AllowHeaders: []string{"X-Token", "X-Trace"},
	}
	tests := []struct {
		name             string
		method           string
		headers          string
		wantAllowed      bool
		wantAllowHeaders string
	}{
		{name: "allowed", method: http.MethodPost, headers: "x-token, X-TRACE", wantAllowed: true, wantAllowHeaders: "X-Token,X-Trace"},
		{name: "allowed without requested headers", method: http.MethodGet, wantAllowed: true, wantAllowHeaders: "X-Token,X-Trace"},
		{name: "disallowed method", method: http.MethodDelete},
		{name: "method matching is case sensitive", method: "get"},
		{name: "one disallowed header", method: http.MethodGet, headers: "X-Token, X-Admin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := config.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			}))
			req := preflightRequest(tt.method, tt.headers)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if called {
				t.Fatal("preflight request reached downstream handler")
			}
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
			}
			if got := rec.Header().Get(headerAccessControlAllowOrigin); (got != "") != tt.wantAllowed {
				t.Fatalf("Access-Control-Allow-Origin = %q, allowed = %v", got, tt.wantAllowed)
			}
			if got := rec.Header().Get(headerAccessControlAllowHeaders); got != tt.wantAllowHeaders {
				t.Fatalf("Access-Control-Allow-Headers = %q, want %q", got, tt.wantAllowHeaders)
			}
			vary := rec.Header().Values(headerVary)
			for _, value := range []string{headerOrigin, headerAccessControlRequestMethod, headerAccessControlRequestHeaders} {
				if !slices.Contains(vary, value) {
					t.Errorf("Vary = %q, missing %q", vary, value)
				}
			}
		})
	}
}

func TestPreflightValidatesEveryRequestedHeaderLine(t *testing.T) {
	handler := (&Cors{
		AllowOrigins: []string{"https://client.example"},
		AllowMethods: []string{http.MethodGet},
		AllowHeaders: []string{"X-Token"},
	}).Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("preflight request reached downstream handler")
	}))
	req := preflightRequest(http.MethodGet, "X-Token")
	req.Header.Add(headerAccessControlRequestHeaders, "X-Admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get(headerAccessControlAllowOrigin); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want empty for rejected preflight", got)
	}
	assertNoPreflightAllowHeaders(t, rec.Header())
}

func TestEmptyAllowHeadersRejectsRequestedHeaders(t *testing.T) {
	handler := (&Cors{}).Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("preflight request reached downstream handler")
	}))

	t.Run("allows request without requested headers", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, preflightRequest(http.MethodGet, ""))

		if got := rec.Header().Get(headerAccessControlAllowOrigin); got != "*" {
			t.Fatalf("Access-Control-Allow-Origin = %q, want *", got)
		}
		if got := rec.Header().Get(headerAccessControlAllowHeaders); got != "" {
			t.Fatalf("Access-Control-Allow-Headers = %q, want empty", got)
		}
	})

	t.Run("rejects and does not reflect requested headers", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, preflightRequest(http.MethodGet, "X-Unconfigured"))

		if got := rec.Header().Get(headerAccessControlAllowHeaders); got != "" {
			t.Fatalf("Access-Control-Allow-Headers reflected unconfigured header %q", got)
		}
		assertNoPreflightAllowHeaders(t, rec.Header())
	})
}

func TestPreflightAllowsIntentionalWildcards(t *testing.T) {
	handler := (&Cors{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"*"},
		AllowHeaders: []string{"*"},
	}).Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("preflight request reached downstream handler")
	}))
	req := preflightRequest("PROPFIND", "X-Anything, X-Another")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get(headerAccessControlAllowOrigin); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want *", got)
	}
	if got := rec.Header().Get(headerAccessControlAllowMethods); got != "*" {
		t.Fatalf("Access-Control-Allow-Methods = %q, want *", got)
	}
	if got := rec.Header().Get(headerAccessControlAllowHeaders); got != "*" {
		t.Fatalf("Access-Control-Allow-Headers = %q, want *", got)
	}
}

func TestCredentialedWildcardPoliciesReturnRequestedValues(t *testing.T) {
	tests := []struct {
		name         string
		origins      []string
		unsafeOrigin bool
	}{
		{name: "specific origin", origins: []string{"https://client.example"}},
		{name: "explicit unsafe wildcard origin", origins: []string{"*"}, unsafeOrigin: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := (&Cors{
				AllowOrigins:                             tt.origins,
				AllowMethods:                             []string{"*"},
				AllowHeaders:                             []string{"*"},
				AllowCredentials:                         true,
				UnsafeWildcardOriginWithAllowCredentials: tt.unsafeOrigin,
			}).Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("preflight request reached downstream handler")
			}))
			req := preflightRequest("PROPFIND", "X-Anything, X-Another")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if got := rec.Header().Get(headerAccessControlAllowOrigin); got != "https://client.example" {
				t.Fatalf("Access-Control-Allow-Origin = %q, want concrete origin", got)
			}
			if got := rec.Header().Get(headerAccessControlAllowCredentials); got != "true" {
				t.Fatalf("Access-Control-Allow-Credentials = %q, want true", got)
			}
			if got := rec.Header().Get(headerAccessControlAllowMethods); got != "PROPFIND" {
				t.Fatalf("Access-Control-Allow-Methods = %q, want PROPFIND", got)
			}
			if got := rec.Header().Get(headerAccessControlAllowHeaders); got != "X-Anything, X-Another" {
				t.Fatalf("Access-Control-Allow-Headers = %q, want requested headers", got)
			}
		})
	}
}

func TestDeniedPreflightDoesNotExposeAllowHeaders(t *testing.T) {
	tests := []struct {
		name    string
		cors    Cors
		method  string
		headers string
	}{
		{
			name: "disallowed method and header",
			cors: Cors{
				AllowOrigins:     []string{"https://client.example"},
				AllowMethods:     []string{http.MethodGet},
				AllowHeaders:     []string{"X-Token"},
				AllowCredentials: true,
				MaxAge:           60,
			},
			method:  http.MethodPost,
			headers: "X-Admin",
		},
		{
			name: "wildcard policy with malformed requested method",
			cors: Cors{
				AllowOrigins:     []string{"https://client.example"},
				AllowMethods:     []string{"*"},
				AllowHeaders:     []string{"*"},
				AllowCredentials: true,
			},
			method:  "GET,POST",
			headers: "X-Token",
		},
		{
			name: "wildcard policy with malformed requested header",
			cors: Cors{
				AllowOrigins:     []string{"https://client.example"},
				AllowMethods:     []string{"*"},
				AllowHeaders:     []string{"*"},
				AllowCredentials: true,
			},
			method:  http.MethodGet,
			headers: "X Token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := tt.cors.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("preflight request reached downstream handler")
			}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, preflightRequest(tt.method, tt.headers))

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
			}
			assertNoPreflightAllowHeaders(t, rec.Header())
		})
	}
}

func TestMiddlewareSnapshotsCallerConfig(t *testing.T) {
	cfg := &Cors{
		AllowOrigins:     []string{"https://*.example.com"},
		AllowMethods:     []string{http.MethodPost},
		AllowHeaders:     []string{"X-Token"},
		AllowCredentials: true,
		ExposeHeaders:    []string{"X-Result"},
		MaxAge:           60,
	}
	handler := cfg.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))

	// Change every caller-owned field after construction. The handler must keep
	// using the validated snapshot, not these relaxed values.
	cfg.AllowOrigins[0] = "*"
	cfg.AllowMethods[0] = http.MethodDelete
	cfg.AllowHeaders[0] = "X-Admin"
	cfg.ExposeHeaders[0] = "X-Secret"
	cfg.AllowCredentials = false
	cfg.UnsafeWildcardOriginWithAllowCredentials = true
	cfg.MaxAge = 0

	assertSnapshot := func(preflight bool) {
		var req *http.Request
		if preflight {
			req = preflightRequest(http.MethodPost, "X-Token")
			req.Header.Set(headerOrigin, "https://client.example.com")
		} else {
			req = httptest.NewRequest(http.MethodGet, "/resource", nil)
			req.Header.Set(headerOrigin, "https://client.example.com")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if got := rec.Header().Get(headerAccessControlAllowOrigin); got != "https://client.example.com" {
			t.Errorf("Access-Control-Allow-Origin = %q, want snapshotted origin", got)
		}
		if got := rec.Header().Get(headerAccessControlAllowCredentials); got != "true" {
			t.Errorf("Access-Control-Allow-Credentials = %q, want true", got)
		}
		if preflight {
			if got := rec.Header().Get(headerAccessControlAllowMethods); got != http.MethodPost {
				t.Errorf("Access-Control-Allow-Methods = %q, want POST", got)
			}
			if got := rec.Header().Get(headerAccessControlAllowHeaders); got != "X-Token" {
				t.Errorf("Access-Control-Allow-Headers = %q, want X-Token", got)
			}
			if got := rec.Header().Get(headerAccessControlMaxAge); got != "60" {
				t.Errorf("Access-Control-Max-Age = %q, want 60", got)
			}
		} else {
			if rec.Code != http.StatusAccepted {
				t.Errorf("simple request status = %d, want %d", rec.Code, http.StatusAccepted)
			}
			if got := rec.Header().Get(headerAccessControlExposeHeaders); got != "X-Result" {
				t.Errorf("Access-Control-Expose-Headers = %q, want X-Result", got)
			}
		}
	}
	assertSnapshot(true)
	assertSnapshot(false)

	const (
		workers    = 8
		iterations = 100
	)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers + 1)
	go func() {
		defer wg.Done()
		<-start
		for i := range workers * iterations {
			cfg.AllowOrigins[0] = []string{"*", "https://evil.example"}[i%2]
			cfg.AllowMethods[0] = []string{http.MethodDelete, http.MethodPatch}[i%2]
			cfg.AllowHeaders[0] = []string{"X-Admin", "X-Secret"}[i%2]
			cfg.ExposeHeaders[0] = []string{"X-Admin", "X-Secret"}[i%2]
			cfg.AllowCredentials = i%2 == 0
			cfg.MaxAge = i
			if i%16 == 0 {
				runtime.Gosched()
			}
		}
	}()
	for worker := range workers {
		go func(worker int) {
			defer wg.Done()
			<-start
			for i := range iterations {
				assertSnapshot((worker+i)%2 == 0)
			}
		}(worker)
	}
	close(start)
	wg.Wait()
}

func TestMiddlewarePanicsForInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cors Cors
	}{
		{name: "empty origin pattern", cors: Cors{AllowOrigins: []string{""}}},
		{name: "origin pattern whitespace", cors: Cors{AllowOrigins: []string{" https://example.com"}}},
		{name: "malformed UTF-8 origin pattern", cors: Cors{AllowOrigins: []string{string([]byte{0xff})}}},
		{name: "invalid method token", cors: Cors{AllowMethods: []string{"GET,POST"}}},
		{name: "invalid header token", cors: Cors{AllowHeaders: []string{"X Token"}}},
		{name: "credentialed default wildcard origin", cors: Cors{AllowCredentials: true}},
		{name: "credentialed explicit wildcard origin", cors: Cors{AllowOrigins: []string{"*"}, AllowCredentials: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("Middleware did not panic for invalid configuration")
				}
			}()
			tt.cors.Middleware()
		})
	}
}

func assertNoPreflightAllowHeaders(t *testing.T, header http.Header) {
	t.Helper()
	for _, name := range []string{
		headerAccessControlAllowOrigin,
		headerAccessControlAllowCredentials,
		headerAccessControlAllowMethods,
		headerAccessControlAllowHeaders,
		headerAccessControlMaxAge,
	} {
		if got := header.Get(name); got != "" {
			t.Errorf("denied preflight exposed %s: %q", name, got)
		}
	}
}

func preflightRequest(method, headers string) *http.Request {
	req := httptest.NewRequest(http.MethodOptions, "/resource", nil)
	req.Header.Set(headerOrigin, "https://client.example")
	req.Header.Set(headerAccessControlRequestMethod, method)
	if headers != "" {
		req.Header.Set(headerAccessControlRequestHeaders, headers)
	}

	return req
}
