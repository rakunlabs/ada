package resource

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mustNew(t *testing.T, cfg Config) *Server {
	t.Helper()

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return s
}

func TestNewRejectsIncompleteConfig(t *testing.T) {
	tests := map[string]Config{
		"no authorization server or jwks": {Resource: "https://api.example.com"},
		"resource and resource_path": {
			Resource:             "https://api.example.com/mcp",
			ResourcePath:         "/mcp",
			AuthorizationServers: []string{"https://idp.example.com"},
		},
		"relative resource": {
			Resource:             "/mcp",
			AuthorizationServers: []string{"https://idp.example.com"},
		},
		"resource with fragment": {
			Resource:             "https://api.example.com/mcp#x",
			AuthorizationServers: []string{"https://idp.example.com"},
		},
		"resource with query": {
			Resource:             "https://api.example.com/mcp?x=1",
			AuthorizationServers: []string{"https://idp.example.com"},
		},
		"resource_path without leading slash": {
			ResourcePath:         "mcp",
			AuthorizationServers: []string{"https://idp.example.com"},
		},
		"relative authorization server": {
			AuthorizationServers: []string{"/idp"},
		},
		"scope with space": {
			AuthorizationServers: []string{"https://idp.example.com"},
			ScopesSupported:      []string{"mcp:read mcp:write"},
		},
		"bad trusted proxy": {
			AuthorizationServers: []string{"https://idp.example.com"},
			TrustedProxies:       []string{"not-a-cidr"},
		},
	}

	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Fatalf("New(%+v) = nil error, want rejection", cfg)
			}
		})
	}
}

// RFC 9728 §3.1: the resource's path is inserted after the well-known path,
// not before it. Getting this backwards is the single most common way a
// discovery chain dies at the first hop.
func TestMetadataURLPathInsertion(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "resource with path",
			cfg: Config{
				Resource:             "https://api.example.com/mcp",
				AuthorizationServers: []string{"https://idp.example.com"},
			},
			want: "https://api.example.com/.well-known/oauth-protected-resource/mcp",
		},
		{
			name: "resource at origin",
			cfg: Config{
				Resource:             "https://api.example.com",
				AuthorizationServers: []string{"https://idp.example.com"},
			},
			want: "https://api.example.com/.well-known/oauth-protected-resource",
		},
		{
			name: "nested path",
			cfg: Config{
				Resource:             "https://api.example.com/v1/mcp",
				AuthorizationServers: []string{"https://idp.example.com"},
			},
			want: "https://api.example.com/.well-known/oauth-protected-resource/v1/mcp",
		},
		{
			name: "trailing slash is not a path segment",
			cfg: Config{
				Resource:             "https://api.example.com/mcp/",
				AuthorizationServers: []string{"https://idp.example.com"},
			},
			want: "https://api.example.com/.well-known/oauth-protected-resource/mcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mustNew(t, tt.cfg)
			r := httptest.NewRequest(http.MethodGet, "/mcp", nil)

			if got := s.MetadataURL(r); got != tt.want {
				t.Fatalf("MetadataURL = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResourceIDDerivedFromOrigin(t *testing.T) {
	s := mustNew(t, Config{
		ResourcePath:         "/mcp",
		AuthorizationServers: []string{"https://idp.example.com"},
	})

	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	r.Host = "api.internal:8080"

	if got, want := s.ResourceID(r), "http://api.internal:8080/mcp"; got != want {
		t.Fatalf("ResourceID = %q, want %q", got, want)
	}
	if got, want := s.MetadataURL(r), "http://api.internal:8080/.well-known/oauth-protected-resource/mcp"; got != want {
		t.Fatalf("MetadataURL = %q, want %q", got, want)
	}
}

// An untrusted peer must not be able to relocate the resource identifier by
// sending X-Forwarded-Host: a client would then be told to request a token
// for an origin the attacker controls.
func TestForwardedHeadersIgnoredFromUntrustedPeer(t *testing.T) {
	s := mustNew(t, Config{
		ResourcePath:         "/mcp",
		AuthorizationServers: []string{"https://idp.example.com"},
	})

	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	r.Host = "api.internal"
	r.RemoteAddr = "203.0.113.9:1234"
	r.Header.Set("X-Forwarded-Host", "evil.example")
	r.Header.Set("X-Forwarded-Proto", "https")

	if got, want := s.ResourceID(r), "http://api.internal/mcp"; got != want {
		t.Fatalf("ResourceID = %q, want %q", got, want)
	}
}

func TestForwardedHeadersHonoredFromTrustedPeer(t *testing.T) {
	s := mustNew(t, Config{
		ResourcePath:         "/mcp",
		AuthorizationServers: []string{"https://idp.example.com"},
		TrustedProxies:       []string{"10.0.0.0/8"},
	})

	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	r.Host = "api.internal"
	r.RemoteAddr = "10.1.2.3:4444"
	r.Header.Set("X-Forwarded-Host", "api.example.com")
	r.Header.Set("X-Forwarded-Proto", "https")

	if got, want := s.ResourceID(r), "https://api.example.com/mcp"; got != want {
		t.Fatalf("ResourceID = %q, want %q", got, want)
	}
}

func TestHandlerServesDocumentAtInsertedPath(t *testing.T) {
	s := mustNew(t, Config{
		Resource:             "https://api.example.com/mcp",
		AuthorizationServers: []string{"https://idp.example.com/realms/main/"},
		ScopesSupported:      []string{"mcp:read", "mcp:write"},
		ResourceName:         "Example MCP",
	})

	w := httptest.NewRecorder()
	s.Handler()(w, httptest.NewRequest(http.MethodGet, WellKnownPath+"/mcp", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q", got)
	}

	var doc Metadata
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if doc.Resource != "https://api.example.com/mcp" {
		t.Fatalf("resource = %q", doc.Resource)
	}
	// The trailing slash is normalized away: an issuer identifier is compared
	// byte for byte by clients and by the bearer strategy.
	if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != "https://idp.example.com/realms/main" {
		t.Fatalf("authorization_servers = %v", doc.AuthorizationServers)
	}
	if len(doc.BearerMethodsSupported) != 1 || doc.BearerMethodsSupported[0] != "header" {
		t.Fatalf("bearer_methods_supported = %v", doc.BearerMethodsSupported)
	}
	if doc.ResourceName != "Example MCP" {
		t.Fatalf("resource_name = %q", doc.ResourceName)
	}
}

// Serving the same document for every suffix would assert this server guards
// resources it has never heard of.
func TestHandlerRejectsMismatchedSuffix(t *testing.T) {
	s := mustNew(t, Config{
		Resource:             "https://api.example.com/mcp",
		AuthorizationServers: []string{"https://idp.example.com"},
	})

	for _, path := range []string{WellKnownPath, WellKnownPath + "/other", WellKnownPath + "/mcp/deeper"} {
		w := httptest.NewRecorder()
		s.Handler()(w, httptest.NewRequest(http.MethodGet, path, nil))

		if w.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", path, w.Code)
		}
	}
}

func TestHandlerServesOriginResourceAtBarePath(t *testing.T) {
	s := mustNew(t, Config{
		Resource:             "https://api.example.com",
		AuthorizationServers: []string{"https://idp.example.com"},
	})

	w := httptest.NewRecorder()
	s.Handler()(w, httptest.NewRequest(http.MethodGet, WellKnownPath, nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestChallenge(t *testing.T) {
	s := mustNew(t, Config{
		Resource:             "https://api.example.com/mcp",
		AuthorizationServers: []string{"https://idp.example.com"},
	})
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)

	t.Run("bare", func(t *testing.T) {
		got := s.Challenge(r, ChallengeParams{})
		want := `Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"`

		if got != want {
			t.Fatalf("Challenge = %q, want %q", got, want)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		got := s.Challenge(r, ChallengeParams{
			Error:       ErrorInvalidToken,
			Description: "the access token expired",
		})

		for _, want := range []string{
			`error="invalid_token"`,
			`error_description="the access token expired"`,
			`resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"`,
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("Challenge = %q, missing %q", got, want)
			}
		}
	})

	t.Run("insufficient scope", func(t *testing.T) {
		got := s.Challenge(r, ChallengeParams{
			Error: ErrorInsufficientScope,
			Scope: []string{"mcp:read", "mcp:write"},
		})

		if !strings.Contains(got, `scope="mcp:read mcp:write"`) {
			t.Fatalf("Challenge = %q", got)
		}
	})
}

// A quote or a control character reaching the header verbatim turns the
// challenge into something the client discards, or worse.
func TestChallengeQuotesAndStripsHostileValues(t *testing.T) {
	s := mustNew(t, Config{
		Resource:             "https://api.example.com",
		AuthorizationServers: []string{"https://idp.example.com"},
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	got := s.Challenge(r, ChallengeParams{
		Error:       ErrorInvalidToken,
		Description: "he said \"no\"\r\nX-Injected: yes\\",
	})

	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("challenge carries a header break: %q", got)
	}
	if !strings.Contains(got, `error_description="he said \"no\"X-Injected: yes\\"`) {
		t.Fatalf("Challenge = %q", got)
	}
}

func TestPaths(t *testing.T) {
	s := mustNew(t, Config{
		Resource:             "https://api.example.com/mcp",
		AuthorizationServers: []string{"https://idp.example.com"},
	})

	want := []string{WellKnownPath, WellKnownPath + "/*"}
	got := s.Paths()

	if len(got) != len(want) {
		t.Fatalf("Paths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Paths = %v, want %v", got, want)
		}
	}
}
