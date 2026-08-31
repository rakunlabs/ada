package redis

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
)

func newTestStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()

	server := miniredis.RunT(t)
	return newTestStoreForAddress(t, server.Addr()), server
}

func newTestStoreForAddress(t *testing.T, address string) *Store {
	t.Helper()

	client := goredis.NewClient(&goredis.Options{
		Addr:         address,
		MaxRetries:   -1,
		DialTimeout:  time.Second,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	})
	t.Cleanup(func() { _ = client.Close() })

	return &Store{
		client:    client,
		keyPrefix: "session_",
		codec:     sessionstore.NewCookieCodec([]byte("0123456789abcdef0123456789abcdef")),
		options:   sessionstore.Options{Path: "/", MaxAge: 3600},
		ttl:       time.Hour,
	}
}

func requestWithSessionCookie(store *Store, name, id string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: name, Value: store.codec.Encode(name, id)})

	return r
}

func TestGetMissingSessionReturnsFreshSession(t *testing.T) {
	store, _ := newTestStore(t)
	r := requestWithSessionCookie(store, "auth", "missing")

	got, err := store.Get(r, "auth")
	if err != nil || !got.IsNew {
		t.Fatalf("Get() = (%v, %v), want fresh session", got, err)
	}
}

func TestGetInvalidCookieReturnsFreshSession(t *testing.T) {
	store, _ := newTestStore(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "auth", Value: "invalid"})

	got, err := store.Get(r, "auth")
	if err != nil || !got.IsNew {
		t.Fatalf("Get() = (%v, %v), want fresh session", got, err)
	}
}

func TestGetPropagatesCorruptSessionData(t *testing.T) {
	store, server := newTestStore(t)
	if err := server.Set(store.redisKey("corrupt"), "{"); err != nil {
		t.Fatalf("set corrupt data: %v", err)
	}

	got, err := store.Get(requestWithSessionCookie(store, "auth", "corrupt"), "auth")
	if err == nil || got != nil {
		t.Fatalf("Get() = (%v, %v), want nil session and corruption error", got, err)
	}
}

func TestGetPropagatesBackendFailure(t *testing.T) {
	store, _ := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := requestWithSessionCookie(store, "auth", "session").WithContext(ctx)

	got, err := store.Get(r, "auth")
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("Get() = (%v, %v), want nil session and context.Canceled", got, err)
	}
}

func TestNewTLSConfig(t *testing.T) {
	if got, err := newTLSConfig(nil); err != nil || got != nil {
		t.Fatalf("newTLSConfig(nil) = (%v, %v), want (nil, nil)", got, err)
	}
	if got, err := newTLSConfig(&TLSConfig{InsecureSkipVerify: true}); err != nil || got != nil {
		t.Fatalf("newTLSConfig(disabled) = (%v, %v), want (nil, nil)", got, err)
	}

	got, err := newTLSConfig(&TLSConfig{Enabled: true})
	if err != nil {
		t.Fatalf("newTLSConfig(enabled): %v", err)
	}
	if got == nil {
		t.Fatal("newTLSConfig(enabled) returned nil config")
	}
	if got.InsecureSkipVerify {
		t.Error("newTLSConfig(enabled) unexpectedly skips verification")
	}
	if got.MinVersion < tls.VersionTLS12 {
		t.Errorf("newTLSConfig(enabled) MinVersion = %d, want TLS 1.2 or newer", got.MinVersion)
	}

	got, err = newTLSConfig(&TLSConfig{Enabled: true, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("newTLSConfig(insecure): %v", err)
	}
	if !got.InsecureSkipVerify {
		t.Error("newTLSConfig(insecure) did not preserve InsecureSkipVerify")
	}
}

func TestNewTLSConfigRejectsIncompleteKeyPair(t *testing.T) {
	for _, cfg := range []*TLSConfig{
		{Enabled: true, CertFile: "client.crt"},
		{Enabled: true, KeyFile: "client.key"},
	} {
		if _, err := newTLSConfig(cfg); err == nil {
			t.Errorf("newTLSConfig(%+v) unexpectedly succeeded", cfg)
		}
	}
}

func TestNewRejectsIncompleteKeyPairBeforeConnecting(t *testing.T) {
	_, err := New(context.Background(), Config{
		Address: "does-not-exist.invalid:6379",
		TLS:     &TLSConfig{Enabled: true, CertFile: "client.crt"},
	}, sessionstore.Options{})
	if err == nil || !strings.Contains(err.Error(), "both TLS cert and key files") {
		t.Fatalf("New() error = %v, want incomplete key-pair error", err)
	}
}

func TestGetClonesOptionsPerSession(t *testing.T) {
	store, _ := newTestStore(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	first, err := store.Get(r, "first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Get(r, "second")
	if err != nil {
		t.Fatal(err)
	}
	if first.Options == second.Options || first.Options == &store.options || second.Options == &store.options {
		t.Fatal("sessions share an options pointer")
	}

	first.Options.MaxAge = -1
	if second.Options.MaxAge != 3600 || store.options.MaxAge != 3600 {
		t.Fatalf("mutating one session changed defaults: second=%d store=%d", second.Options.MaxAge, store.options.MaxAge)
	}
}

func TestSaveDeletionPropagatesRedisError(t *testing.T) {
	store, server := newTestStore(t)
	server.SetError("ERR deletion failed")
	session := store.newSession("auth")
	session.ID = "session-id"
	session.Options.MaxAge = -1

	recorder := httptest.NewRecorder()
	err := store.Save(
		httptest.NewRequest(http.MethodGet, "/", nil),
		recorder,
		session,
	)
	if err == nil || !strings.Contains(err.Error(), "deletion failed") {
		t.Fatalf("Save() error = %v, want Redis deletion error", err)
	}
	setCookie := recorder.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, "auth=") || !strings.Contains(setCookie, "Max-Age=0") {
		t.Fatalf("Set-Cookie = %q, want deletion tombstone", setCookie)
	}
}

func TestSaveUsesSessionMaxAgeForTTL(t *testing.T) {
	store, server := newTestStore(t)
	session := store.newSession("auth")
	session.ID = "custom-ttl"
	session.Options.MaxAge = 90
	session.Values["user"] = "alice"

	if err := store.Save(
		httptest.NewRequest(http.MethodGet, "/", nil),
		httptest.NewRecorder(),
		session,
	); err != nil {
		t.Fatal(err)
	}
	if ttl := server.TTL(store.redisKey(session.ID)); ttl != 90*time.Second {
		t.Fatalf("TTL = %v, want 90s", ttl)
	}
}

func TestSaveByIDZeroTTLClearsExpiry(t *testing.T) {
	store, server := newTestStore(t)
	ctx := context.Background()
	if err := store.SaveByID(ctx, "non-expiring", map[string]any{"value": "first"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveByID(ctx, "non-expiring", map[string]any{"value": "second"}, 0); err != nil {
		t.Fatal(err)
	}
	if ttl := server.TTL(store.redisKey("non-expiring")); ttl != 0 {
		t.Fatalf("TTL = %v, want no expiry", ttl)
	}
}

func TestTransactByIDPreservesExactTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		t.Run(ttl.String(), func(t *testing.T) {
			store, server := newTestStore(t)
			ctx := context.Background()
			if err := store.SaveByID(ctx, "preserve", map[string]any{"value": "original"}, 2*time.Hour); err != nil {
				t.Fatal(err)
			}
			server.FastForward(30 * time.Minute)
			wantTTL := server.TTL(store.redisKey("preserve"))

			_, err := store.TransactByID(ctx, "preserve", ttl, func(current map[string]any) (map[string]any, bool, error) {
				current["value"] = "updated"

				return current, true, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := server.TTL(store.redisKey("preserve")); got != wantTTL {
				t.Fatalf("TTL = %v, want exact preserved TTL %v", got, wantTTL)
			}
		})
	}
}

func TestTransactByIDConflictCallsCallbackOnce(t *testing.T) {
	store, server := newTestStore(t)
	ctx := context.Background()
	if err := store.SaveByID(ctx, "atomic", map[string]any{"count": 0}, time.Hour); err != nil {
		t.Fatal(err)
	}

	calls := 0
	result, err := store.TransactByID(ctx, "atomic", 2*time.Minute, func(current map[string]any) (map[string]any, bool, error) {
		calls++
		if err := server.Set(store.redisKey("atomic"), `{"count":10}`); err != nil {
			t.Fatal(err)
		}
		current["count"] = current["count"].(float64) + 1
		return current, true, nil
	})
	if !errors.Is(err, sessionstore.ErrTransactionConflict) || result != nil {
		t.Fatalf("TransactByID() = (%v, %v), want transaction conflict", result, err)
	}
	if calls != 1 {
		t.Fatalf("transaction callback calls = %d, want 1 after conflict", calls)
	}
	values, err := store.LoadByID(ctx, "atomic")
	if err != nil {
		t.Fatal(err)
	}
	if values["count"] != float64(10) {
		t.Fatalf("stored values = %+v, want concurrent count 10", values)
	}
}

func TestTransactByIDAcrossClients(t *testing.T) {
	first, server := newTestStore(t)
	second := newTestStoreForAddress(t, server.Addr())
	ctx := context.Background()
	if err := first.SaveByID(ctx, "atomic", map[string]any{"count": 0}, time.Hour); err != nil {
		t.Fatal(err)
	}

	const updates = 40
	errs := make(chan error, updates)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := range updates {
		store := first
		if i%2 != 0 {
			store = second
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				_, err := store.TransactByID(ctx, "atomic", time.Hour, func(current map[string]any) (map[string]any, bool, error) {
					current["count"] = current["count"].(float64) + 1
					return current, true, nil
				})
				if errors.Is(err, sessionstore.ErrTransactionConflict) {
					continue
				}
				errs <- err
				return
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	values, err := first.LoadByID(ctx, "atomic")
	if err != nil {
		t.Fatal(err)
	}
	if values["count"] != float64(updates) {
		t.Fatalf("stored values = %+v, want count %d", values, updates)
	}
}

func TestTransactByIDDelete(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()
	if err := store.SaveByID(ctx, "delete", map[string]any{"value": "original"}, time.Hour); err != nil {
		t.Fatal(err)
	}

	result, err := store.TransactByID(ctx, "delete", time.Hour, func(map[string]any) (map[string]any, bool, error) {
		return nil, true, nil
	})
	if err != nil || result != nil {
		t.Fatalf("TransactByID() = (%v, %v), want successful delete", result, err)
	}
	if _, err := store.LoadByID(ctx, "delete"); !errors.Is(err, sessionstore.ErrNoSession) {
		t.Fatalf("LoadByID() error = %v, want ErrNoSession", err)
	}
}

func TestTransactByIDCommitWithCallbackError(t *testing.T) {
	callbackErr := errors.New("callback failed")
	for _, test := range []struct {
		name        string
		replacement map[string]any
	}{
		{name: "update", replacement: map[string]any{"value": "changed"}},
		{name: "delete", replacement: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, server := newTestStore(t)
			ctx := context.Background()
			if err := store.SaveByID(ctx, "session", map[string]any{"value": "original"}, time.Hour); err != nil {
				t.Fatal(err)
			}

			result, err := store.TransactByID(ctx, "session", 2*time.Minute, func(map[string]any) (map[string]any, bool, error) {
				return test.replacement, true, callbackErr
			})
			if !errors.Is(err, callbackErr) {
				t.Fatalf("TransactByID() error = %v, want callback error", err)
			}
			if test.replacement == nil {
				if result != nil {
					t.Fatalf("TransactByID() result = %v, want nil after delete", result)
				}
				if _, err := store.LoadByID(ctx, "session"); !errors.Is(err, sessionstore.ErrNoSession) {
					t.Fatalf("LoadByID() error = %v, want ErrNoSession", err)
				}
				return
			}

			if result["value"] != "changed" {
				t.Fatalf("TransactByID() result = %+v, want committed update", result)
			}
			values, err := store.LoadByID(ctx, "session")
			if err != nil {
				t.Fatal(err)
			}
			if values["value"] != "changed" {
				t.Fatalf("stored values = %+v, want committed update", values)
			}
			if ttl := server.TTL(store.redisKey("session")); ttl != 2*time.Minute {
				t.Fatalf("transaction TTL = %v, want 2m", ttl)
			}
		})
	}
}

func TestTransactByIDMissingRecord(t *testing.T) {
	store, _ := newTestStore(t)
	called := false
	_, err := store.TransactByID(context.Background(), "missing", time.Hour, func(map[string]any) (map[string]any, bool, error) {
		called = true
		return nil, true, nil
	})
	if !errors.Is(err, sessionstore.ErrNoSession) || called {
		t.Fatalf("TransactByID() = (called=%v, err=%v), want ErrNoSession without callback", called, err)
	}
}

func TestTransactByIDContextCancellationAbortsCommit(t *testing.T) {
	store, _ := newTestStore(t)
	if err := store.SaveByID(context.Background(), "session", map[string]any{"value": "original"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())

	_, err := store.TransactByID(ctx, "session", time.Hour, func(current map[string]any) (map[string]any, bool, error) {
		current["value"] = "changed"
		cancel()
		return current, true, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("TransactByID() error = %v, want context.Canceled", err)
	}
	values, err := store.LoadByID(context.Background(), "session")
	if err != nil {
		t.Fatal(err)
	}
	if values["value"] != "original" {
		t.Fatalf("stored values changed after cancellation: %+v", values)
	}
}
