package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/resource"
	"github.com/rakunlabs/ada/middleware/auth/session"
	"github.com/rakunlabs/ada/middleware/auth/strategy/bearer"
)

const testResource = "https://api.example.com/mcp"

// fakeIssuer is a minimal authorization server: RFC 8414 metadata, a JWKS and
// a signer.
type fakeIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	f := &fakeIssuer{key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   f.url(),
			"jwks_uri": f.url() + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA",
			"kid": "k1",
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes()),
		}}})
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)

	return f
}

func (f *fakeIssuer) url() string { return f.server.URL }

func (f *fakeIssuer) token(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()

	now := time.Now()
	claims := map[string]any{
		"iss":   f.url(),
		"aud":   testResource,
		"sub":   "ada",
		"name":  "Ada Lovelace",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"scope": "mcp:read",
	}
	if mutate != nil {
		mutate(claims)
	}

	header, err := json.Marshal(map[string]any{"alg": "RS256", "kid": "k1", "typ": "at+jwt"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	signing := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)

	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// mcpSetup wires the full resource-server stack the way a deployment would:
// RFC 9728 metadata from Config, a bearer strategy that picks the metadata
// server up through strategy.ResourceBinder, and a protected route behind
// session.DisableRedirect so a non-browser client is challenged instead of
// redirected.
func mcpSetup(t *testing.T) (*fakeIssuer, *fakeMux) {
	t.Helper()

	idp := newFakeIssuer(t)

	bearerStrategy, err := bearer.New(bearer.Config{
		Issuer:                 idp.url(),
		Audience:               []string{testResource},
		RequireAccessTokenType: true,
	}, bearer.Options{HTTPClient: idp.server.Client()})
	if err != nil {
		t.Fatalf("bearer.New: %v", err)
	}

	a := auth.New(auth.Config{
		UI: auth.UIConfig{ExternalFolder: true},
		ProtectedResource: &resource.Config{
			Resource:             testResource,
			AuthorizationServers: []string{idp.url()},
			ScopesSupported:      []string{"mcp:read", "mcp:write"},
			ResourceName:         "Example MCP",
		},
	})
	a.Strategy(bearerStrategy)

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identity.FromContext(r.Context())
		if id == nil {
			t.Error("protected handler reached with no identity")
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		_ = json.NewEncoder(w).Encode(id)
	})

	mux.HandleWithMethod(http.MethodPost, "/mcp", func(w http.ResponseWriter, r *http.Request) {
		session.DisableRedirect()(a.Require()(protected)).ServeHTTP(w, r)
	})

	// The same handler without the DisableRedirect marker, to show the
	// browser-facing behavior is unchanged.
	mux.HandleWithMethod(http.MethodGet, "/app", func(w http.ResponseWriter, r *http.Request) {
		a.Require()(protected).ServeHTTP(w, r)
	})

	return idp, mux
}

// Step 1 of the MCP discovery chain: an unauthenticated call must say where
// to get a token, not just that one is missing.
func TestMCPUnauthenticatedRequestCarriesResourceMetadata(t *testing.T) {
	_, mux := mcpSetup(t)

	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
	}

	challenge := rec.Header().Get("WWW-Authenticate")
	want := `Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"`
	if challenge != want {
		t.Fatalf("WWW-Authenticate = %q, want %q", challenge, want)
	}
}

// Step 2: the metadata document the challenge points at must be reachable
// without a credential — a discovery document behind the credential it tells
// you how to obtain is a closed loop.
func TestMCPMetadataIsPublicAndComplete(t *testing.T) {
	idp, mux := mcpSetup(t)

	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	var doc resource.Metadata
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if doc.Resource != testResource {
		t.Fatalf("resource = %q, want %q", doc.Resource, testResource)
	}
	if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != idp.url() {
		t.Fatalf("authorization_servers = %v, want [%s]", doc.AuthorizationServers, idp.url())
	}
	if len(doc.ScopesSupported) != 2 {
		t.Fatalf("scopes_supported = %v", doc.ScopesSupported)
	}
}

// Step 3: the token the client comes back with is accepted, and the identity
// it carries reaches the handler.
func TestMCPValidTokenAuthenticates(t *testing.T) {
	idp, mux := mcpSetup(t)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+idp.token(t, nil))

	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	var id identity.Identity
	if err := json.Unmarshal(rec.Body.Bytes(), &id); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if id.Subject != "ada" || id.Name != "Ada Lovelace" {
		t.Fatalf("identity = %+v", id)
	}
	if len(id.Scopes) != 1 || id.Scopes[0] != "mcp:read" {
		t.Fatalf("scopes = %v", id.Scopes)
	}
	if id.Provider != "bearer" {
		t.Fatalf("provider = %q", id.Provider)
	}
}

func TestMCPRejectedTokens(t *testing.T) {
	tests := map[string]func(map[string]any){
		"expired":        func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() },
		"other audience": func(c map[string]any) { c["aud"] = "https://elsewhere.example/api" },
		"other issuer":   func(c map[string]any) { c["iss"] = "https://elsewhere.example" },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			idp, mux := mcpSetup(t)

			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			req.Header.Set("Authorization", "Bearer "+idp.token(t, mutate))

			rec := httptest.NewRecorder()
			mux.mu.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "resource_metadata=") {
				t.Fatalf("WWW-Authenticate = %q", rec.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

// A bad token must not be quietly downgraded to anonymous and then redirected
// to a login page: that hides the real failure behind an HTML response the
// client cannot act on.
func TestMCPInvalidTokenIsNotRedirected(t *testing.T) {
	_, mux := mcpSetup(t)

	req := httptest.NewRequest(http.MethodGet, "/app", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")

	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// Browsers keep the login redirect. Adding a resource server must not turn
// the interactive path into a 401 nobody renders.
func TestMCPBrowserPathStillRedirects(t *testing.T) {
	_, mux := mcpSetup(t)

	rec := httptest.NewRecorder()
	mux.mu.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app", nil))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
}

func TestMCPMetadataRejectsUnknownResource(t *testing.T) {
	_, mux := mcpSetup(t)

	for _, path := range []string{
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-protected-resource/other",
	} {
		rec := httptest.NewRecorder()
		mux.mu.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", path, rec.Code)
		}
	}
}
