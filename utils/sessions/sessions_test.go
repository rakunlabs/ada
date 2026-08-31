package sessions_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rakunlabs/ada/utils/securecookie"
	"github.com/rakunlabs/ada/utils/sessions"
)

func newStore() *sessions.CookieStore {
	return sessions.NewCookieStore(
		securecookie.GenerateRandomKey(64),
		securecookie.GenerateRandomKey(32),
	)
}

// readBack issues a Save, then builds a new request carrying the resulting
// cookies so a subsequent Get reads what was written.
func readBack(t *testing.T, w *httptest.ResponseRecorder) *http.Request {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}

	return r
}

func TestCookieStore_RoundTrip(t *testing.T) {
	store := newStore()

	// First request: create and save a session.
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	w1 := httptest.NewRecorder()

	sess, err := store.Get(r1, "auth")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !sess.IsNew {
		t.Fatal("expected new session")
	}

	sess.Values["user"] = "ada"
	sess.Values["count"] = 3
	if err := sess.Save(r1, w1); err != nil {
		t.Fatalf("save: %v", err)
	}

	if len(w1.Result().Cookies()) == 0 {
		t.Fatal("expected a Set-Cookie")
	}

	// Second request: load it back.
	r2 := readBack(t, w1)

	loaded, err := store.Get(r2, "auth")
	if err != nil {
		t.Fatalf("get back: %v", err)
	}
	if loaded.IsNew {
		t.Fatal("expected loaded session to not be new")
	}
	if loaded.Values["user"] != "ada" {
		t.Fatalf("user = %v", loaded.Values["user"])
	}
	if loaded.Values["count"] != 3 {
		t.Fatalf("count = %v", loaded.Values["count"])
	}
}

func TestCookieStore_Delete(t *testing.T) {
	store := newStore()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	sess, _ := store.Get(r, "auth")
	sess.Values["user"] = "ada"
	sess.Options.MaxAge = -1

	if err := sess.Save(r, w); err != nil {
		t.Fatalf("save: %v", err)
	}

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].MaxAge >= 0 {
		t.Fatalf("expected negative MaxAge, got %d", cookies[0].MaxAge)
	}
	if cookies[0].Value != "" {
		t.Fatalf("expected empty value, got %q", cookies[0].Value)
	}
}

func TestCookieStore_TamperedCookie(t *testing.T) {
	store := newStore()

	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	w1 := httptest.NewRecorder()
	sess, _ := store.Get(r1, "auth")
	sess.Values["user"] = "ada"
	if err := sess.Save(r1, w1); err != nil {
		t.Fatalf("save: %v", err)
	}

	orig := w1.Result().Cookies()[0]
	tampered := &http.Cookie{Name: orig.Name, Value: orig.Value + "x"}

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(tampered)

	loaded, err := store.New(r2, "auth")
	if err == nil {
		t.Fatal("expected decode error on tampered cookie")
	}
	if !loaded.IsNew {
		t.Fatal("tampered cookie should yield a new session")
	}
}

func TestCookieStore_Options(t *testing.T) {
	store := newStore()
	store.Options.Domain = "example.com"
	store.Options.Secure = true
	store.MaxAge(120)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	sess, _ := store.Get(r, "auth")
	sess.Values["k"] = "v"
	if err := sess.Save(r, w); err != nil {
		t.Fatalf("save: %v", err)
	}

	c := w.Result().Cookies()[0]
	if c.Domain != "example.com" {
		t.Fatalf("domain = %q", c.Domain)
	}
	if !c.Secure {
		t.Fatal("expected secure cookie")
	}
	if c.MaxAge != 120 {
		t.Fatalf("max-age = %d", c.MaxAge)
	}
	if !c.HttpOnly {
		t.Fatal("expected HttpOnly default")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("samesite = %v", c.SameSite)
	}
}

func TestCookieStore_MaxLength(t *testing.T) {
	store := newStore()

	value := strings.Repeat("a", 6000)

	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	w1 := httptest.NewRecorder()
	sess, _ := store.Get(r1, "auth")
	sess.Values["v"] = value

	if err := sess.Save(r1, w1); !errors.Is(err, securecookie.ErrValueTooLong) {
		t.Fatalf("default limit: want ErrValueTooLong, got %v", err)
	}

	store.MaxLength(32 * 1024)

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	w2 := httptest.NewRecorder()
	sess2, _ := store.Get(r2, "auth")
	sess2.Values["v"] = value

	if err := sess2.Save(r2, w2); err != nil {
		t.Fatalf("save after MaxLength: %v", err)
	}

	encoded := w2.Result().Cookies()[0].Value
	if len(encoded) <= securecookie.DefaultMaxLength {
		t.Fatalf("cookie is %d bytes, expected to exceed the default limit", len(encoded))
	}

	// Decoding honours the raised limit too, otherwise the cookie would be
	// writable but unreadable.
	loaded, err := store.Get(readBack(t, w2), "auth")
	if err != nil {
		t.Fatalf("load after MaxLength: %v", err)
	}
	if loaded.IsNew || loaded.Values["v"] != value {
		t.Fatalf("round-trip failed: isNew=%v", loaded.IsNew)
	}

	// Every codec is updated, so key rotation keeps working.
	rotated := sessions.NewCookieStore(
		securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32),
		securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32),
	)
	rotated.MaxLength(32 * 1024)

	for i, c := range rotated.Codecs {
		if _, err := c.Encode("auth", map[string]any{"v": value}); err != nil {
			t.Fatalf("codec %d: %v", i, err)
		}
	}
}

func TestRegistry_CachesSession(t *testing.T) {
	store := newStore()

	var first, second *sessions.Session
	h := sessions.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first, _ = store.Get(r, "auth")
		second, _ = store.Get(r, "auth")
	}))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if first == nil || second == nil {
		t.Fatal("sessions not populated")
	}
	if first != second {
		t.Fatal("expected the same cached session instance")
	}
}

func TestRegistry_SeparatesStoresWithSameSessionName(t *testing.T) {
	firstStore := newStore()
	secondStore := newStore()

	var first, second *sessions.Session
	h := sessions.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		first, _ = firstStore.Get(r, "auth")
		second, _ = secondStore.Get(r, "auth")
	}))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if first == second {
		t.Fatal("different stores must not share a cached session")
	}
	if first.Store() != firstStore || second.Store() != secondStore {
		t.Fatal("cached sessions were returned from the wrong store")
	}
}

func TestRegistry_PreservesCachedDecodeError(t *testing.T) {
	store := newStore()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "auth", Value: "invalid"})

	var firstSession, secondSession *sessions.Session
	var firstErr, secondErr error
	h := sessions.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		firstSession, firstErr = store.Get(r, "auth")
		secondSession, secondErr = store.Get(r, "auth")
	}))

	h.ServeHTTP(httptest.NewRecorder(), r)

	if firstErr == nil || secondErr == nil {
		t.Fatalf("decode errors = (%v, %v), want both non-nil", firstErr, secondErr)
	}
	if firstErr != secondErr {
		t.Fatal("cached Get did not preserve the original decode error")
	}
	if firstSession != secondSession {
		t.Fatal("cached Get returned a different session after a decode error")
	}
}

func TestSave_FlushesRegistry(t *testing.T) {
	store := newStore()

	w := httptest.NewRecorder()
	h := sessions.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, _ := store.Get(r, "a")
		a.Values["x"] = 1
		b, _ := store.Get(r, "b")
		b.Values["y"] = 2

		if err := sessions.Save(r, w); err != nil {
			t.Errorf("save: %v", err)
		}
	}))

	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	cookies := w.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
}

func TestSave_NoRegistryIsNoop(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	if err := sessions.Save(r, w); err != nil {
		t.Fatalf("expected no-op, got %v", err)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("expected no cookies written")
	}
}

func TestFlashes(t *testing.T) {
	store := newStore()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	sess, _ := store.Get(r, "auth")
	sess.AddFlash("hello")
	sess.AddFlash("world")

	if got := sess.Flashes(); len(got) != 2 || got[0] != "hello" || got[1] != "world" {
		t.Fatalf("flashes = %#v", got)
	}

	// Reading clears them.
	if got := sess.Flashes(); got != nil {
		t.Fatalf("expected nil after read, got %#v", got)
	}
}

func TestFlashes_CustomKey(t *testing.T) {
	store := newStore()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	sess, _ := store.Get(r, "auth")
	sess.AddFlash("err", "_error")
	sess.AddFlash("ok") // default bucket

	if got := sess.Flashes("_error"); len(got) != 1 || got[0] != "err" {
		t.Fatalf("error flashes = %#v", got)
	}
	if got := sess.Flashes(); len(got) != 1 || got[0] != "ok" {
		t.Fatalf("default flashes = %#v", got)
	}
}
