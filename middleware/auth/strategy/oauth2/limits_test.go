package oauth2

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth/internal/bodylimit"
)

func TestPasswordBodyOver64KiBReturns413(t *testing.T) {
	s := New("idp", Config{PasswordFlow: true, TokenURL: "https://idp.invalid/token"}, Options{})
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", maxRequestBodyBytes+1)))
	r.Header.Set("Content-Type", "application/json")
	_, _, _ = s.Login(rec, r)

	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), `"error":"body_too_large"`) || !strings.Contains(rec.Body.String(), "65536") {
		t.Fatalf("response = %d %s", rec.Code, rec.Body)
	}
}

func TestUpstreamResponseLimitsDetectNPlusOne(t *testing.T) {
	large := strings.Repeat("x", maxUpstreamResponseBytes+1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration", "/token", "/userinfo", "/jwks":
			_, _ = w.Write([]byte(large))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	if _, err := Discover(context.Background(), server.Client(), server.URL); !errors.Is(err, bodylimit.ErrUpstreamResponseTooLarge) {
		t.Fatalf("discovery error = %v", err)
	}

	s := &Strategy{cfg: Config{TokenURL: server.URL + "/token", UserInfoURL: server.URL + "/userinfo"}, client: server.Client()}
	if _, err := s.tokenRequest(context.Background(), nil); !errors.Is(err, bodylimit.ErrUpstreamResponseTooLarge) {
		t.Fatalf("token error = %v", err)
	}
	if _, err := s.fetchUserInfo(context.Background(), "token"); !errors.Is(err, bodylimit.ErrUpstreamResponseTooLarge) {
		t.Fatalf("userinfo error = %v", err)
	}

	ks := newKeySet(server.URL+"/jwks", server.Client())
	if err := ks.refresh(context.Background()); !errors.Is(err, bodylimit.ErrUpstreamResponseTooLarge) {
		t.Fatalf("jwks error = %v", err)
	}
}

func TestOversizedUpstreamResponseIsNotClient413(t *testing.T) {
	large := strings.Repeat("x", maxUpstreamResponseBytes+1)
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"key"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + ".AA"

	for _, test := range []struct {
		name       string
		wantStatus int
		configure  func(*Config, string)
		handler    http.HandlerFunc
	}{
		{
			name:       "token",
			wantStatus: http.StatusUnauthorized,
			handler:    func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(large)) },
		},
		{
			name:       "userinfo",
			wantStatus: http.StatusBadGateway,
			configure:  func(c *Config, url string) { c.UserInfoURL = url + "/userinfo" },
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					_, _ = w.Write([]byte(`{"access_token":"token"}`))
					return
				}
				_, _ = w.Write([]byte(large))
			},
		},
		{
			name:       "jwks",
			wantStatus: http.StatusBadGateway,
			configure:  func(c *Config, url string) { c.JWKSURL = url + "/jwks" },
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					_, _ = w.Write([]byte(`{"access_token":"token","id_token":"` + unsigned + `"}`))
					return
				}
				_, _ = w.Write([]byte(large))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			t.Cleanup(server.Close)
			cfg := Config{PasswordFlow: true, TokenURL: server.URL + "/token"}
			if test.configure != nil {
				test.configure(&cfg, server.URL)
			}
			s := New("idp", cfg, Options{})
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username":"alice","password":"pw"}`))
			r.Header.Set("Content-Type", "application/json")
			_, _, _ = s.Login(rec, r)

			if rec.Code != test.wantStatus || rec.Code == http.StatusRequestEntityTooLarge {
				t.Fatalf("response = %d %s, want %d", rec.Code, rec.Body, test.wantStatus)
			}
		})
	}
}
