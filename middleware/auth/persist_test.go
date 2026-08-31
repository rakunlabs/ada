package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rakunlabs/ada/middleware/auth"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/issuer/backend"
	"github.com/rakunlabs/ada/middleware/auth/issuer/crypto"
	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
	"github.com/rakunlabs/ada/middleware/auth/sessionstore/file"
	"github.com/rakunlabs/ada/middleware/auth/strategy/local"
)

func fileStore(t *testing.T) *file.Store {
	t.Helper()

	s, err := file.New(file.Config{
		SessionKey: "0123456789abcdef0123456789abcdef",
		Path:       t.TempDir(),
		GCInterval: -1,
	}, sessionstore.Options{Path: "/", MaxAge: 3600})
	if err != nil {
		t.Fatalf("file store: %v", err)
	}

	t.Cleanup(func() { _ = s.Close() })

	return s
}

func verifier(_ context.Context, u, p string) (*identity.Identity, error) {
	if u == "alice" && p == "pw" {
		return &identity.Identity{Subject: "alice"}, nil
	}

	return nil, errInvalid
}

var errInvalid = errors.New("invalid_credentials")

// The regression: WithSessionStore drove a codec-based store through a
// synthesized request carrying the raw session ID. The codec rejected it, so
// every load missed, every save landed under a fresh random key, and the user
// was bounced back to the login page after a successful login.
func TestWithSessionStorePersistsAcrossRequests(t *testing.T) {
	a, mux := persistAuth(t, fileStore(t))

	sessionCookie := loginFor(t, mux)

	if sessionCookie == nil {
		t.Fatal("login did not set a session cookie")
	}

	// A protected request must now resolve, not redirect.
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.AddCookie(sessionCookie)

	var seen *identity.Identity

	a.Require()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = identity.FromContext(r.Context())
	})).ServeHTTP(rec, r)

	if rec.Code == http.StatusSeeOther {
		t.Fatal("a persisted session redirected back to login")
	}

	if seen == nil || seen.Subject != "alice" {
		t.Fatalf("identity = %+v", seen)
	}
}

func TestWithSessionStoreRejectsNonDirectStore(t *testing.T) {
	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}}).
		WithSessionStore(notDirectStore{})

	err := a.Init(context.Background())
	if err == nil {
		t.Fatal("a store that cannot address records by ID must be rejected at Init")
	}

	if !errors.Is(err, sessionstore.ErrNotDirect) {
		t.Fatalf("err = %v, want ErrNotDirect", err)
	}
}

type notDirectStore struct{}

func (notDirectStore) Get(*http.Request, string) (*sessionstore.Session, error) { return nil, nil }
func (notDirectStore) Save(*http.Request, http.ResponseWriter, *sessionstore.Session) error {
	return nil
}

func TestPairIsEncryptedAtRest(t *testing.T) {
	store := fileStore(t)

	c, err := crypto.New("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}

	a, mux := persistAuth(t, store, backend.WithCipher(c))

	cookie := loginFor(t, mux)
	if cookie == nil {
		t.Fatal("no session cookie")
	}

	// Still usable...
	pair, err := a.Issuer().Resolve(context.Background(), cookie.Value)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if pair.Identity.Subject != "alice" {
		t.Fatalf("identity = %+v", pair.Identity)
	}

	// ...and unreadable on disk.
	values, err := store.LoadByID(context.Background(), cookie.Value)
	if err != nil {
		t.Fatalf("load raw: %v", err)
	}

	raw, _ := values["pair"].(string)
	if raw == "" {
		t.Fatal("no stored blob")
	}

	if strings.Contains(raw, "alice") || strings.Contains(raw, pair.Refresh.Value) {
		t.Fatalf("pair stored in clear text: %s", raw)
	}
}

func persistAuth(t *testing.T, store sessionstore.Store, opts ...backend.SessionStoreOption) (*auth.Auth, *fakeMux) {
	t.Helper()

	a := auth.New(auth.Config{UI: auth.UIConfig{ExternalFolder: true}}).
		Strategy(localStrategy()).
		WithSessionStore(store, opts...)

	if err := a.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}

	mux := newFakeMux()
	a.Mount(mux)

	return a, mux
}

func loginFor(t *testing.T, mux *fakeMux) *http.Cookie {
	t.Helper()

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/login/pass/local",
		strings.NewReader(`{"username":"alice","password":"pw"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")

	mux.mu.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body)
	}

	return cookieNamed(rec, "auth_session")
}

func localStrategy() *local.Strategy {
	return local.New("local", verifier)
}
