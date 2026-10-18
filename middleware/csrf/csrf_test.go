package csrf

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_, _ = io.WriteString(w, TokenFromRequest(r))
})

func newHandler(cfg Config) http.Handler {
	return Middleware(WithConfig(cfg))(okHandler)
}

func TestOriginCheck(t *testing.T) {
	h := newHandler(Config{
		TrustedOrigins: []string{"https://trusted.example.com"},
		BypassPatterns: []string{"POST /webhook/"},
	})

	tests := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
		want    int
	}{
		{"safe method cross-site", http.MethodGet, "/", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusOK},
		{"same-origin post", http.MethodPost, "/", map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusOK},
		{"user initiated post", http.MethodPost, "/", map[string]string{"Sec-Fetch-Site": "none"}, http.StatusOK},
		{"cross-site post", http.MethodPost, "/", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"same-site post", http.MethodPost, "/", map[string]string{"Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
		{"origin matches host", http.MethodPost, "/", map[string]string{"Origin": "http://example.com"}, http.StatusOK},
		{"origin mismatch", http.MethodPost, "/", map[string]string{"Origin": "https://evil.com"}, http.StatusForbidden},
		{"trusted origin", http.MethodPost, "/", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://trusted.example.com"}, http.StatusOK},
		{"non-browser", http.MethodPost, "/", nil, http.StatusOK},
		{"bypass", http.MethodPost, "/webhook/github", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusOK},
		{"bypass method mismatch", http.MethodPut, "/webhook/github", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"bypass needs direct match", http.MethodPost, "/webhook", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "http://example.com"+tt.path, nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestDisableOriginCheck(t *testing.T) {
	h := newHandler(Config{DisableOriginCheck: true})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestDefaultDenyResponse(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	newHandler(Config{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if !strings.Contains(rec.Body.String(), ErrCrossOrigin.Error()) {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestDenyHandlerReceivesCause(t *testing.T) {
	var cause error
	h := newHandler(Config{
		Token: Token{Enabled: true},
		DenyHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cause = Cause(r)
			w.WriteHeader(http.StatusTeapot)
		}),
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d", rec.Code)
	}
	if !errors.Is(cause, ErrTokenMissing) {
		t.Fatalf("cause = %v", cause)
	}
}

func issueCookie(t *testing.T, h http.Handler, name string) (*http.Cookie, string) {
	t.Helper()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c, rec.Body.String()
		}
	}

	t.Fatal("csrf cookie not set")
	return nil, ""
}

func TestToken(t *testing.T) {
	for _, secret := range []string{"", "s3cret"} {
		t.Run("secret="+secret, func(t *testing.T) {
			h := newHandler(Config{Token: Token{Enabled: true, Secret: secret}})

			cookie, exposed := issueCookie(t, h, DefaultCookieName)
			if !cookie.Secure || cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
				t.Fatalf("unexpected cookie attributes %+v", cookie)
			}
			if exposed != cookie.Value {
				t.Fatalf("TokenFromRequest = %q, want cookie value", exposed)
			}

			post := func(token string, form bool) int {
				var req *http.Request
				if form {
					req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{DefaultFormField: {token}}.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				} else {
					req = httptest.NewRequest(http.MethodPost, "/", nil)
					if token != "" {
						req.Header.Set(DefaultHeaderName, token)
					}
				}
				req.AddCookie(cookie)

				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				return rec.Code
			}

			if got := post(cookie.Value, false); got != http.StatusOK {
				t.Fatalf("header token status = %d", got)
			}
			if got := post(cookie.Value, true); got != http.StatusOK {
				t.Fatalf("form token status = %d", got)
			}
			if got := post("", false); got != http.StatusForbidden {
				t.Fatalf("missing token status = %d", got)
			}
			if got := post("wrong", false); got != http.StatusForbidden {
				t.Fatalf("wrong token status = %d", got)
			}
		})
	}
}

func TestTokenExistingCookieIsKept(t *testing.T) {
	h := newHandler(Config{Token: Token{Enabled: true, Secret: "s3cret"}})
	cookie, _ := issueCookie(t, h, DefaultCookieName)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("valid cookie must not be reissued")
	}
	if rec.Body.String() != cookie.Value {
		t.Fatalf("TokenFromRequest = %q", rec.Body.String())
	}
}

func TestTokenForgedCookie(t *testing.T) {
	h := newHandler(Config{Token: Token{Enabled: true, Secret: "s3cret"}})
	unsigned, _ := issueCookie(t, newHandler(Config{Token: Token{Enabled: true}}), DefaultCookieName)

	for _, forged := range []string{
		strings.Repeat("A", 43) + ".invalid",
		unsigned.Value,
		"short.sig",
	} {
		t.Run(forged, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: forged})
			req.Header.Set(DefaultHeaderName, forged)

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d", rec.Code)
			}
		})
	}
}

func TestTokenUnsignedRejectsSignedFormat(t *testing.T) {
	signed, _ := issueCookie(t, newHandler(Config{Token: Token{Enabled: true, Secret: "s3cret"}}), DefaultCookieName)
	h := newHandler(Config{Token: Token{Enabled: true}})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(signed)
	req.Header.Set(DefaultHeaderName, signed.Value)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestTokenCookieOptions(t *testing.T) {
	h := newHandler(Config{Token: Token{
		Enabled:        true,
		CookieName:     "xsrf",
		CookiePath:     "/app",
		CookieDomain:   "example.com",
		CookieMaxAge:   time.Hour,
		CookieInsecure: true,
		CookieSameSite: "Strict",
	}})

	cookie, _ := issueCookie(t, h, "xsrf")
	if cookie.Secure || cookie.Path != "/app" || cookie.Domain != "example.com" || cookie.MaxAge != 3600 || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected cookie attributes %+v", cookie)
	}
}

func TestTokenCustomHeader(t *testing.T) {
	h := newHandler(Config{Token: Token{Enabled: true, HeaderName: "X-XSRF-Token"}})
	cookie, _ := issueCookie(t, h, DefaultCookieName)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(cookie)
	req.Header.Set("X-XSRF-Token", cookie.Value)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestBypassSkipsTokenCheck(t *testing.T) {
	h := newHandler(Config{
		BypassPatterns: []string{"POST /webhook/{provider}"},
		Token:          Token{Enabled: true},
	})

	req := httptest.NewRequest(http.MethodPost, "/webhook/github", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestConfigIsSnapshotted(t *testing.T) {
	cfg := Config{BypassPatterns: []string{"POST /webhook/"}}
	h := newHandler(cfg)
	cfg.BypassPatterns[0] = "POST /other/"

	req := httptest.NewRequest(http.MethodPost, "/webhook/x", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestInvalidConfigPanics(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantPanic string
	}{
		{"trusted origin", Config{TrustedOrigins: []string{"not a url"}}, "trusted origin"},
		{"bypass pattern", Config{BypassPatterns: []string{"BAD PATTERN WITH SPACES"}}, "bypass pattern"},
		{"conflicting bypass", Config{BypassPatterns: []string{"/a/", "/a/"}}, "bypass pattern"},
		{"same site", Config{Token: Token{Enabled: true, CookieSameSite: "weird"}}, "CookieSameSite"},
		{"same site none insecure", Config{Token: Token{Enabled: true, CookieSameSite: "none", CookieInsecure: true}}, "requires a secure cookie"},
		{"negative max age", Config{Token: Token{Enabled: true, CookieMaxAge: -time.Second}}, "CookieMaxAge"},
		{"host prefix domain", Config{Token: Token{Enabled: true, CookieName: "__Host-csrf", CookieDomain: "example.com"}}, "__Host-"},
		{"secure prefix insecure", Config{Token: Token{Enabled: true, CookieName: "__Secure-csrf", CookieInsecure: true}}, "__Secure-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				got := recover()
				if got == nil || !strings.Contains(fmt.Sprint(got), tt.wantPanic) {
					t.Fatalf("panic = %v, want text %q", got, tt.wantPanic)
				}
			}()
			Middleware(WithConfig(tt.config))
		})
	}
}
