package file_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
	"github.com/rakunlabs/ada/middleware/auth/sessionstore/file"
)

func newStore(t *testing.T) (*file.Store, string) {
	t.Helper()

	dir := t.TempDir()

	s, err := file.New(file.Config{
		SessionKey: "0123456789abcdef0123456789abcdef",
		Path:       dir,
		GCInterval: -1,
	}, sessionstore.Options{Path: "/", MaxAge: 3600})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	t.Cleanup(func() { _ = s.Close() })

	return s, dir
}

func TestDirectRoundTrip(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	want := map[string]any{"pair": "blob", "n": float64(3)}

	if err := s.SaveByID(ctx, "sid-1", want, time.Hour); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := s.LoadByID(ctx, "sid-1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if got["pair"] != "blob" || got["n"] != float64(3) {
		t.Fatalf("got %+v", got)
	}
}

func TestLoadMissingIsErrNoSession(t *testing.T) {
	s, _ := newStore(t)

	if _, err := s.LoadByID(context.Background(), "nope"); !errors.Is(err, sessionstore.ErrNoSession) {
		t.Fatalf("err = %v, want ErrNoSession", err)
	}
}

func TestDeleteByID(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	_ = s.SaveByID(ctx, "sid", map[string]any{"a": "b"}, time.Hour)

	if err := s.DeleteByID(ctx, "sid"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := s.LoadByID(ctx, "sid"); !errors.Is(err, sessionstore.ErrNoSession) {
		t.Fatalf("err = %v", err)
	}

	// Deleting twice is not an error.
	if err := s.DeleteByID(ctx, "sid"); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

// Records used to live forever: there was no TTL and no sweeper, so a file
// store accumulated one file per login for the life of the deployment.
func TestTTLExpiry(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()

	if err := s.SaveByID(ctx, "short", map[string]any{"a": "b"}, time.Millisecond); err != nil {
		t.Fatalf("save: %v", err)
	}

	time.Sleep(1100 * time.Millisecond)

	if _, err := s.LoadByID(ctx, "short"); !errors.Is(err, sessionstore.ErrNoSession) {
		t.Fatalf("err = %v, want ErrNoSession", err)
	}

	// Reading an expired record also removes it.
	matches, _ := filepath.Glob(filepath.Join(dir, "session_*.json"))
	if len(matches) != 0 {
		t.Errorf("expired file was not removed: %v", matches)
	}
}

func TestZeroTTLNeverExpires(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	_ = s.SaveByID(ctx, "forever", map[string]any{"a": "b"}, 0)

	time.Sleep(20 * time.Millisecond)

	if _, err := s.LoadByID(ctx, "forever"); err != nil {
		t.Fatalf("load: %v", err)
	}
}

// The issuer hands us its own session IDs. A crafted one must not be able to
// address a file outside the store directory.
func TestPathTraversalIsRefused(t *testing.T) {
	s, dir := newStore(t)
	ctx := context.Background()

	for _, id := range []string{"../escape", "a/b", `a\b`, "with.dot", "", string(make([]byte, 300))} {
		if err := s.SaveByID(ctx, id, map[string]any{"a": "b"}, time.Hour); err == nil {
			t.Errorf("SaveByID(%q) should have been refused", id)
		}

		if _, err := s.LoadByID(ctx, id); !errors.Is(err, sessionstore.ErrNoSession) {
			t.Errorf("LoadByID(%q) = %v", id, err)
		}
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("unexpected files written: %v", entries)
	}
}

// The request/response path must still work; the issuer adapter is a separate
// entry point, not a replacement.
func TestHTTPRoundTrip(t *testing.T) {
	s, _ := newStore(t)

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	sess, err := s.Get(r, "auth_session")
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if !sess.IsNew {
		t.Fatal("expected a new session")
	}

	sess.Values["k"] = "v"

	rec := httptest.NewRecorder()
	if err := s.Save(r, rec, sess); err != nil {
		t.Fatalf("save: %v", err)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected a cookie, got %d", len(cookies))
	}

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookies[0])

	got, err := s.Get(r2, "auth_session")
	if err != nil {
		t.Fatalf("get 2: %v", err)
	}

	if got.IsNew || got.Values["k"] != "v" {
		t.Fatalf("session did not round-trip: %+v", got)
	}
}

func TestTamperedCookieIsIgnored(t *testing.T) {
	s, _ := newStore(t)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, _ := s.Get(r, "auth_session")
	sess.Values["k"] = "v"

	rec := httptest.NewRecorder()
	_ = s.Save(r, rec, sess)

	c := rec.Result().Cookies()[0]
	c.Value = c.Value[:len(c.Value)-2] + "xx" // break the MAC

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(c)

	got, _ := s.Get(r2, "auth_session")
	if !got.IsNew {
		t.Fatal("a cookie with a broken signature must not resolve")
	}
}

func TestNewFailsOnUnwritableDir(t *testing.T) {
	// A directory that cannot be created used to be swallowed: os.MkdirAll's
	// error was discarded and every later write failed one at a time.
	f := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if _, err := file.New(file.Config{Path: filepath.Join(f, "sub")}, sessionstore.Options{}); err == nil {
		t.Error("expected an error when the session directory cannot be created")
	}
}

func TestGeneratedSessionIDCarriesNoTimestamp(t *testing.T) {
	a, err := sessionstore.GenerateSessionID()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	b, _ := sessionstore.GenerateSessionID()

	if a == b {
		t.Fatal("session IDs must be unique")
	}

	// The old format was "<unixnano>_<random>", which leaked session age. The
	// ID is now nothing but 32 random bytes in base64url — note that "_" is
	// part of that alphabet, so the check is on the decoded length.
	raw, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil {
		t.Fatalf("session ID is not base64url: %q", a)
	}

	if len(raw) != 32 {
		t.Fatalf("session ID carries %d bytes, want 32 of pure entropy", len(raw))
	}
}
