package bearer

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/resource"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

// issuerStub is a minimal authorization server: RFC 8414 metadata, a JWKS,
// and a token signer.
type issuerStub struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string

	metadataHits atomic.Int64
	jwksHits     atomic.Int64
}

func newIssuerStub(t *testing.T) *issuerStub {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	s := &issuerStub{key: key, kid: "test-kid"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		s.metadataHits.Add(1)
		writeJSON(w, map[string]any{
			"issuer":   s.issuer(),
			"jwks_uri": s.issuer() + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		s.jwksHits.Add(1)
		writeJSON(w, map[string]any{"keys": []any{s.jwk()}})
	})

	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)

	return s
}

func (s *issuerStub) issuer() string { return s.server.URL }

func (s *issuerStub) jwk() map[string]any {
	return map[string]any{
		"kty": "RSA",
		"kid": s.kid,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(s.key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.key.E)).Bytes()),
	}
}

func (s *issuerStub) sign(t *testing.T, header, claims map[string]any) string {
	t.Helper()

	if header == nil {
		header = map[string]any{}
	}
	header["alg"] = "RS256"
	if _, ok := header["kid"]; !ok {
		header["kid"] = s.kid
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	signing := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func request(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}

	return r
}

func newStrategy(t *testing.T, stub *issuerStub, mutate func(*Config)) *Strategy {
	t.Helper()

	cfg := Config{
		Issuer:   stub.issuer(),
		Audience: []string{"https://api.example.com/mcp"},
	}
	if mutate != nil {
		mutate(&cfg)
	}

	s, err := New(cfg, Options{HTTPClient: stub.server.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return s
}

func baseClaims(stub *issuerStub) map[string]any {
	now := time.Now()

	return map[string]any{
		"iss":   stub.issuer(),
		"aud":   "https://api.example.com/mcp",
		"sub":   "user-1",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"scope": "mcp:read mcp:write",
	}
}

func TestNewValidation(t *testing.T) {
	tests := map[string]Config{
		"no issuer":                 {Audience: []string{"a"}},
		"whitespace issuer":         {Issuer: " https://idp ", Audience: []string{"a"}},
		"no audience":               {Issuer: "https://idp.example.com"},
		"empty audience entry":      {Issuer: "https://idp.example.com", Audience: []string{""}},
		"blank audience entry":      {Issuer: "https://idp.example.com", Audience: []string{"  "}},
		"audience only whitespaced": {Issuer: "https://idp.example.com", Audience: []string{"\t"}},
	}

	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Fatalf("New(%+v) = nil error, want rejection", cfg)
			}
		})
	}

	t.Run("audience optional when disabled", func(t *testing.T) {
		if _, err := New(Config{Issuer: "https://idp.example.com", DisableAudienceCheck: true}); err != nil {
			t.Fatalf("New: %v", err)
		}
	})
}

func TestAuthenticateRequestHappyPath(t *testing.T) {
	stub := newIssuerStub(t)
	s := newStrategy(t, stub, nil)

	claims := baseClaims(stub)
	claims["name"] = "Ada"
	claims["email"] = "ada@example.com"
	claims["email_verified"] = true
	claims["realm_access"] = map[string]any{"roles": []any{"admin", "user"}}

	id, err := s.AuthenticateRequest(context.Background(), request(stub.sign(t, nil, claims)))
	if err != nil {
		t.Fatalf("AuthenticateRequest: %v", err)
	}

	if id.Subject != "user-1" {
		t.Fatalf("subject = %q", id.Subject)
	}
	if id.Name != "Ada" {
		t.Fatalf("name = %q", id.Name)
	}
	if id.Email != "ada@example.com" || !id.EmailVerified {
		t.Fatalf("email = %q verified = %v", id.Email, id.EmailVerified)
	}
	if got := strings.Join(id.Scopes, ","); got != "mcp:read,mcp:write" {
		t.Fatalf("scopes = %v", id.Scopes)
	}
	if got := strings.Join(id.Roles, ","); got != "admin,user" {
		t.Fatalf("roles = %v", id.Roles)
	}
	if id.Provider != "bearer" {
		t.Fatalf("provider = %q", id.Provider)
	}
	if id.ExpiresAt.IsZero() {
		t.Fatal("expires_at not set from exp")
	}

	if stub.metadataHits.Load() != 1 {
		t.Fatalf("discovery fetched %d times, want 1", stub.metadataHits.Load())
	}

	// A second call must reuse the discovered key set.
	if _, err := s.AuthenticateRequest(context.Background(), request(stub.sign(t, nil, claims))); err != nil {
		t.Fatalf("second AuthenticateRequest: %v", err)
	}
	if stub.metadataHits.Load() != 1 {
		t.Fatalf("discovery refetched: %d", stub.metadataHits.Load())
	}
}

func TestAuthenticateRequestNoCredentials(t *testing.T) {
	stub := newIssuerStub(t)
	s := newStrategy(t, stub, nil)

	t.Run("no header", func(t *testing.T) {
		_, err := s.AuthenticateRequest(context.Background(), request(""))
		if !errors.Is(err, strategy.ErrNoCredentials) {
			t.Fatalf("err = %v, want ErrNoCredentials", err)
		}
	})

	t.Run("other scheme", func(t *testing.T) {
		r := request("")
		r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

		_, err := s.AuthenticateRequest(context.Background(), r)
		if !errors.Is(err, strategy.ErrNoCredentials) {
			t.Fatalf("err = %v, want ErrNoCredentials", err)
		}
	})

	// "Bearer" with nothing after it is a broken client, not an anonymous
	// request. Falling through to the cookie would hide it behind a redirect.
	t.Run("empty token", func(t *testing.T) {
		r := request("")
		r.Header.Set("Authorization", "Bearer ")

		_, err := s.AuthenticateRequest(context.Background(), r)
		if !errors.Is(err, strategy.ErrInvalidCredentials) {
			t.Fatalf("err = %v, want ErrInvalidCredentials", err)
		}
	})

	t.Run("duplicate authorization headers", func(t *testing.T) {
		r := request("")
		r.Header.Add("Authorization", "Bearer one")
		r.Header.Add("Authorization", "Bearer two")

		_, err := s.AuthenticateRequest(context.Background(), r)
		if !errors.Is(err, strategy.ErrInvalidCredentials) {
			t.Fatalf("err = %v, want ErrInvalidCredentials", err)
		}
	})
}

func TestAuthenticateRequestRejections(t *testing.T) {
	stub := newIssuerStub(t)
	other := newIssuerStub(t)

	tests := []struct {
		name   string
		mutate func(*Config)
		claims func(map[string]any)
		header map[string]any
		signer *issuerStub
		want   error
	}{
		{
			name:   "wrong issuer",
			claims: func(c map[string]any) { c["iss"] = "https://evil.example" },
			want:   ErrBadIssuer,
		},
		{
			name:   "no issuer",
			claims: func(c map[string]any) { delete(c, "iss") },
			want:   ErrBadIssuer,
		},
		{
			name:   "wrong audience",
			claims: func(c map[string]any) { c["aud"] = "https://other.example/api" },
			want:   ErrBadAudience,
		},
		{
			name:   "no audience",
			claims: func(c map[string]any) { delete(c, "aud") },
			want:   ErrBadAudience,
		},
		{
			name:   "expired",
			claims: func(c map[string]any) { c["exp"] = time.Now().Add(-2 * time.Hour).Unix() },
			want:   ErrExpired,
		},
		{
			name:   "no expiry",
			claims: func(c map[string]any) { delete(c, "exp") },
			want:   ErrNoExpiry,
		},
		{
			name:   "not yet valid",
			claims: func(c map[string]any) { c["nbf"] = time.Now().Add(2 * time.Hour).Unix() },
			want:   ErrNotYetValid,
		},
		{
			name:   "no subject",
			claims: func(c map[string]any) { delete(c, "sub") },
			want:   ErrNoSubject,
		},
		{
			name:   "signed by another issuer's key",
			signer: other,
			want:   ErrMalformedToken,
		},
		{
			name:   "unknown kid",
			header: map[string]any{"kid": "rotated-away"},
			want:   ErrMalformedToken,
		},
		{
			name:   "typ pinned but absent",
			mutate: func(c *Config) { c.RequireAccessTokenType = true },
			want:   ErrWrongType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStrategy(t, stub, tt.mutate)

			claims := baseClaims(stub)
			if tt.claims != nil {
				tt.claims(claims)
			}

			signer := stub
			if tt.signer != nil {
				signer = tt.signer
			}

			_, err := s.AuthenticateRequest(context.Background(), request(signer.sign(t, tt.header, claims)))
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			// Every rejection must present as a credential failure so
			// Require answers 401 rather than 500.
			if !errors.Is(err, strategy.ErrInvalidCredentials) {
				t.Fatalf("err = %v, want it to wrap ErrInvalidCredentials", err)
			}
		})
	}
}

// alg: none is the oldest JWT bug there is. It must not come back through a
// new entry point.
func TestAuthenticateRequestRejectsUnsignedToken(t *testing.T) {
	stub := newIssuerStub(t)
	s := newStrategy(t, stub, nil)

	header, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	claims, _ := json.Marshal(baseClaims(stub))
	token := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(claims) + "."

	_, err := s.AuthenticateRequest(context.Background(), request(token))
	if !errors.Is(err, strategy.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestRequireAccessTokenTypeAccepted(t *testing.T) {
	stub := newIssuerStub(t)
	s := newStrategy(t, stub, func(c *Config) { c.RequireAccessTokenType = true })

	token := stub.sign(t, map[string]any{"typ": "at+jwt"}, baseClaims(stub))
	if _, err := s.AuthenticateRequest(context.Background(), request(token)); err != nil {
		t.Fatalf("AuthenticateRequest: %v", err)
	}
}

func TestAudienceArrayAndDisable(t *testing.T) {
	stub := newIssuerStub(t)

	t.Run("array containing the resource", func(t *testing.T) {
		s := newStrategy(t, stub, nil)
		claims := baseClaims(stub)
		claims["aud"] = []any{"https://other.example", "https://api.example.com/mcp"}

		if _, err := s.AuthenticateRequest(context.Background(), request(stub.sign(t, nil, claims))); err != nil {
			t.Fatalf("AuthenticateRequest: %v", err)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		s := newStrategy(t, stub, func(c *Config) {
			c.Audience = nil
			c.DisableAudienceCheck = true
		})
		claims := baseClaims(stub)
		delete(claims, "aud")

		if _, err := s.AuthenticateRequest(context.Background(), request(stub.sign(t, nil, claims))); err != nil {
			t.Fatalf("AuthenticateRequest: %v", err)
		}
	})
}

func TestClockSkew(t *testing.T) {
	stub := newIssuerStub(t)

	claims := baseClaims(stub)
	claims["exp"] = time.Now().Add(-30 * time.Second).Unix()
	token := stub.sign(t, nil, claims)

	t.Run("within default skew", func(t *testing.T) {
		s := newStrategy(t, stub, nil)
		if _, err := s.AuthenticateRequest(context.Background(), request(token)); err != nil {
			t.Fatalf("AuthenticateRequest: %v", err)
		}
	})

	t.Run("skew disabled", func(t *testing.T) {
		s := newStrategy(t, stub, func(c *Config) { c.ClockSkew = -1 })
		if _, err := s.AuthenticateRequest(context.Background(), request(token)); !errors.Is(err, ErrExpired) {
			t.Fatalf("err = %v, want ErrExpired", err)
		}
	})
}

func TestScopeClaimVariants(t *testing.T) {
	stub := newIssuerStub(t)
	s := newStrategy(t, stub, nil)

	t.Run("scp array", func(t *testing.T) {
		claims := baseClaims(stub)
		delete(claims, "scope")
		claims["scp"] = []any{"mcp:read"}

		id, err := s.AuthenticateRequest(context.Background(), request(stub.sign(t, nil, claims)))
		if err != nil {
			t.Fatalf("AuthenticateRequest: %v", err)
		}
		if len(id.Scopes) != 1 || id.Scopes[0] != "mcp:read" {
			t.Fatalf("scopes = %v", id.Scopes)
		}
	})
}

func TestCustomClaimMap(t *testing.T) {
	stub := newIssuerStub(t)
	s := newStrategy(t, stub, func(c *Config) {
		c.Claims = ClaimMap{
			Subject: "user_id",
			Name:    []string{"display_name"},
			Roles:   []string{"resource_access.mcp.roles"},
		}
	})

	claims := baseClaims(stub)
	delete(claims, "sub")
	claims["user_id"] = "u-42"
	claims["display_name"] = "Grace"
	claims["resource_access"] = map[string]any{
		"mcp": map[string]any{"roles": []any{"operator"}},
	}

	id, err := s.AuthenticateRequest(context.Background(), request(stub.sign(t, nil, claims)))
	if err != nil {
		t.Fatalf("AuthenticateRequest: %v", err)
	}
	if id.Subject != "u-42" || id.Name != "Grace" {
		t.Fatalf("identity = %+v", id)
	}
	if len(id.Roles) != 1 || id.Roles[0] != "operator" {
		t.Fatalf("roles = %v", id.Roles)
	}
}

// An outage at the issuer is our failure, not the caller's bad credential.
// Reporting it as 401 sends clients into a pointless re-authentication loop.
func TestIssuerOutageIsNotACredentialFailure(t *testing.T) {
	stub := newIssuerStub(t)
	token := stub.sign(t, nil, baseClaims(stub))

	s := newStrategy(t, stub, nil)
	stub.server.Close()

	_, err := s.AuthenticateRequest(context.Background(), request(token))
	if err == nil {
		t.Fatal("want error")
	}
	if errors.Is(err, strategy.ErrInvalidCredentials) || errors.Is(err, strategy.ErrNoCredentials) {
		t.Fatalf("err = %v, want a transport failure", err)
	}
}

// RFC 8414 §3.3. Without it, anyone who can influence the discovery URL can
// point the verifier at a JWKS they control.
func TestDiscoveryRejectsIssuerMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":   "https://evil.example",
			"jwks_uri": "https://evil.example/jwks",
		})
	}))
	t.Cleanup(server.Close)

	_, err := discover(context.Background(), server.Client(), server.URL)
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("err = %v, want ErrIssuerMismatch", err)
	}
}

func TestDiscoveryURLOrder(t *testing.T) {
	got, err := discoveryURLs("https://idp.example.com/realms/main")
	if err != nil {
		t.Fatalf("discoveryURLs: %v", err)
	}

	want := []string{
		"https://idp.example.com/.well-known/oauth-authorization-server/realms/main",
		"https://idp.example.com/.well-known/openid-configuration/realms/main",
		"https://idp.example.com/realms/main/.well-known/openid-configuration",
	}

	if len(got) != len(want) {
		t.Fatalf("discoveryURLs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("discoveryURLs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDiscoveryFallsBackToOIDCLayout(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/tenant/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"issuer": base + "/tenant", "jwks_uri": base + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "k", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	base = server.URL

	doc, err := discover(context.Background(), server.Client(), base+"/tenant")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if doc.JWKSURI != base+"/jwks" {
		t.Fatalf("jwks_uri = %q", doc.JWKSURI)
	}
}

func TestChallengeCarriesResourceMetadata(t *testing.T) {
	stub := newIssuerStub(t)
	s := newStrategy(t, stub, nil)

	if got := s.ChallengeRequest(request("")); got != "Bearer" {
		t.Fatalf("ChallengeRequest without a resource = %q, want %q", got, "Bearer")
	}

	rs, err := resource.New(resource.Config{
		Resource:             "https://api.example.com/mcp",
		AuthorizationServers: []string{stub.issuer()},
	})
	if err != nil {
		t.Fatalf("resource.New: %v", err)
	}

	s.SetProtectedResource(rs)

	want := `Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"`
	if got := s.ChallengeRequest(request("")); got != want {
		t.Fatalf("ChallengeRequest = %q, want %q", got, want)
	}

	// The binder must not clobber an explicit value.
	other, err := resource.New(resource.Config{
		Resource:             "https://other.example",
		AuthorizationServers: []string{stub.issuer()},
	})
	if err != nil {
		t.Fatalf("resource.New: %v", err)
	}

	s.SetProtectedResource(other)
	if got := s.ChallengeRequest(request("")); got != want {
		t.Fatalf("SetProtectedResource overwrote an existing value: %q", got)
	}
}

func TestCustomVerifierStillGetsClaimChecks(t *testing.T) {
	stub := newIssuerStub(t)

	claims := map[string]any{
		"iss": stub.issuer(),
		"aud": "https://other.example",
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	s, err := New(Config{
		Issuer:   stub.issuer(),
		Audience: []string{"https://api.example.com/mcp"},
	}, Options{
		Verifier: VerifierFunc(func(context.Context, string) (map[string]any, error) {
			return claims, nil
		}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := s.AuthenticateRequest(context.Background(), request("opaque")); !errors.Is(err, ErrBadAudience) {
		t.Fatalf("err = %v, want ErrBadAudience", err)
	}
}

func TestLoginWritesChallengeOnBadToken(t *testing.T) {
	stub := newIssuerStub(t)
	s := newStrategy(t, stub, nil)

	rs, err := resource.New(resource.Config{
		Resource:             "https://api.example.com/mcp",
		AuthorizationServers: []string{stub.issuer()},
	})
	if err != nil {
		t.Fatalf("resource.New: %v", err)
	}
	s.SetProtectedResource(rs)

	claims := baseClaims(stub)
	claims["exp"] = time.Now().Add(-time.Hour).Unix()

	w := httptest.NewRecorder()
	id, outcome, err := s.Login(w, request(stub.sign(t, nil, claims)))

	if err != nil || id != nil || outcome != strategy.OutcomeFailed {
		t.Fatalf("Login = (%v, %v, %v)", id, outcome, err)
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}

	challenge := w.Header().Get("WWW-Authenticate")
	for _, want := range []string{`error="invalid_token"`, `resource_metadata=`} {
		if !strings.Contains(challenge, want) {
			t.Fatalf("WWW-Authenticate = %q, missing %q", challenge, want)
		}
	}
}
