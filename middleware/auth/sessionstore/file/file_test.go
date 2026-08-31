package file_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

func TestAtomicTransactionAcrossStoreInstances(t *testing.T) {
	first, dir := newStore(t)
	second, err := file.New(file.Config{
		SessionKey: "0123456789abcdef0123456789abcdef",
		Path:       dir,
		GCInterval: -1,
	}, sessionstore.Options{Path: "/", MaxAge: 3600})
	if err != nil {
		t.Fatalf("second store: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	firstAtomic, ok := any(first).(sessionstore.AtomicDirectStore)
	if !ok {
		t.Skip("atomic file transactions are not available on this platform")
	}
	secondAtomic := any(second).(sessionstore.AtomicDirectStore)
	if err := first.SaveByID(context.Background(), "atomic", map[string]any{"count": 0}, time.Hour); err != nil {
		t.Fatalf("save: %v", err)
	}

	const updates = 50
	var wg sync.WaitGroup
	errs := make(chan error, updates)
	for i := range updates {
		store := firstAtomic
		if i%2 != 0 {
			store = secondAtomic
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.TransactByID(context.Background(), "atomic", time.Hour,
				func(current map[string]any) (map[string]any, bool, error) {
					count := 0
					switch value := current["count"].(type) {
					case int:
						count = value
					case float64:
						count = int(value)
					}
					current["count"] = count + 1

					return current, true, nil
				})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("transaction: %v", err)
		}
	}

	values, err := first.LoadByID(context.Background(), "atomic")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := int(values["count"].(float64)); got != updates {
		t.Fatalf("count = %d, want %d", got, updates)
	}
}

func TestTransactionLockFilesAreBounded(t *testing.T) {
	s, dir := newStore(t)
	atomic, ok := any(s).(sessionstore.AtomicDirectStore)
	if !ok {
		t.Skip("atomic file transactions are not available on this platform")
	}

	const sessions = 128
	for i := range sessions {
		id := "bounded-" + strconv.Itoa(i)
		if err := s.SaveByID(context.Background(), id, map[string]any{"value": i}, time.Hour); err != nil {
			t.Fatalf("save %q: %v", id, err)
		}
		if _, err := atomic.TransactByID(context.Background(), id, time.Hour,
			func(map[string]any) (map[string]any, bool, error) {
				return nil, false, nil
			}); err != nil {
			t.Fatalf("transaction %q: %v", id, err)
		}
	}

	locks, err := filepath.Glob(filepath.Join(dir, ".transaction-*.lock"))
	if err != nil {
		t.Fatalf("glob transaction locks: %v", err)
	}
	if len(locks) > 64 {
		t.Fatalf("transaction lock files = %d, want at most 64", len(locks))
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

func TestDeleteByIDPropagatesRemoveError(t *testing.T) {
	s, dir := newStore(t)
	target := filepath.Join(dir, "session_blocked-delete.json")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("create blocking directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "child"), []byte("x"), 0o600); err != nil {
		t.Fatalf("create blocking child: %v", err)
	}

	if err := s.DeleteByID(context.Background(), "blocked-delete"); err == nil {
		t.Fatal("DeleteByID() unexpectedly ignored remove error")
	}
}

func TestMissingDirectorySaveFailsAndDeleteSucceeds(t *testing.T) {
	s, dir := newStore(t)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	if err := s.SaveByID(context.Background(), "missing", map[string]any{"value": "lost"}, time.Hour); err == nil {
		t.Fatal("SaveByID() unexpectedly succeeded without a store directory")
	}
	if err := s.DeleteByID(context.Background(), "missing"); err != nil {
		t.Fatalf("DeleteByID() error = %v, want missing path to be successful", err)
	}
}

func TestSaveDeletionPropagatesRemoveError(t *testing.T) {
	s, dir := newStore(t)
	target := filepath.Join(dir, "session_blocked-save-delete.json")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("create blocking directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "child"), []byte("x"), 0o600); err != nil {
		t.Fatalf("create blocking child: %v", err)
	}

	session, err := s.Get(httptest.NewRequest(http.MethodGet, "/", nil), "auth")
	if err != nil {
		t.Fatal(err)
	}
	session.ID = "blocked-save-delete"
	session.Options.MaxAge = -1
	recorder := httptest.NewRecorder()
	err = s.Save(httptest.NewRequest(http.MethodGet, "/", nil), recorder, session)
	if err == nil {
		t.Fatal("Save() unexpectedly ignored remove error")
	}
	if cookie := recorder.Header().Get("Set-Cookie"); !strings.Contains(cookie, "auth=") || !strings.Contains(cookie, "Max-Age=0") {
		t.Fatalf("Set-Cookie = %q, want deletion tombstone", cookie)
	}
}

func TestTransactionPropagatesDeleteError(t *testing.T) {
	s, dir := newStore(t)
	atomic, ok := any(s).(sessionstore.AtomicDirectStore)
	if !ok {
		t.Skip("atomic file transactions are not available on this platform")
	}
	ctx := context.Background()
	if err := s.SaveByID(ctx, "blocked-transaction-delete", map[string]any{"value": "original"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "session_blocked-transaction-delete.json")

	var setupErr error
	_, err := atomic.TransactByID(ctx, "blocked-transaction-delete", time.Hour,
		func(map[string]any) (map[string]any, bool, error) {
			if setupErr = os.Remove(target); setupErr != nil {
				return nil, false, setupErr
			}
			if setupErr = os.Mkdir(target, 0o700); setupErr != nil {
				return nil, false, setupErr
			}
			if setupErr = os.WriteFile(filepath.Join(target, "child"), []byte("x"), 0o600); setupErr != nil {
				return nil, false, setupErr
			}

			return nil, true, nil
		})
	if setupErr != nil {
		t.Fatalf("set up delete failure: %v", setupErr)
	}
	if err == nil {
		t.Fatal("TransactByID() unexpectedly ignored delete error")
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

		if err := s.DeleteByID(ctx, id); err == nil {
			t.Errorf("DeleteByID(%q) should have been refused", id)
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

func TestGetClonesOptionsPerSession(t *testing.T) {
	s, _ := newStore(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	first, err := s.Get(r, "first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Get(r, "second")
	if err != nil {
		t.Fatal(err)
	}
	if first.Options == second.Options {
		t.Fatal("sessions share an options pointer")
	}

	first.Options.MaxAge = -1
	third, err := s.Get(r, "third")
	if err != nil {
		t.Fatal(err)
	}
	if second.Options.MaxAge != 3600 || third.Options.MaxAge != 3600 {
		t.Fatalf("mutating one session changed defaults: second=%d third=%d", second.Options.MaxAge, third.Options.MaxAge)
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

func TestGetPropagatesCorruptSessionFile(t *testing.T) {
	s, dir := newStore(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, _ := s.Get(r, "auth_session")

	rec := httptest.NewRecorder()
	if err := s.Save(r, rec, sess); err != nil {
		t.Fatalf("save: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "session_*.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("session files = %v, err = %v", matches, err)
	}
	if err := os.WriteFile(matches[0], []byte("{"), 0o600); err != nil {
		t.Fatalf("corrupt session: %v", err)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(rec.Result().Cookies()[0])
	if got, err := s.Get(r2, "auth_session"); err == nil || got != nil {
		t.Fatalf("Get() = (%v, %v), want nil session and corruption error", got, err)
	}
}

func TestGetMissingSessionReturnsFreshSession(t *testing.T) {
	s, dir := newStore(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, _ := s.Get(r, "auth_session")

	rec := httptest.NewRecorder()
	if err := s.Save(r, rec, sess); err != nil {
		t.Fatalf("save: %v", err)
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "session_*.json"))
	if err := os.Remove(matches[0]); err != nil {
		t.Fatalf("remove session: %v", err)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(rec.Result().Cookies()[0])
	got, err := s.Get(r2, "auth_session")
	if err != nil || !got.IsNew {
		t.Fatalf("Get() = (%v, %v), want fresh session", got, err)
	}
}

func TestAtomicSaveCleansTemporaryFileOnRenameFailure(t *testing.T) {
	s, dir := newStore(t)
	target := filepath.Join(dir, "session_blocked.json")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("create blocking target: %v", err)
	}

	if err := s.SaveByID(context.Background(), "blocked", map[string]any{"a": "b"}, time.Hour); err == nil {
		t.Fatal("expected rename failure")
	}

	temps, err := filepath.Glob(filepath.Join(dir, ".session-*.tmp"))
	if err != nil {
		t.Fatalf("glob temporary files: %v", err)
	}
	if len(temps) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", temps)
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
