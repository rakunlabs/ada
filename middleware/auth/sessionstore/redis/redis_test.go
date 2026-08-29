package redis

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
)

func newTestStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()

	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{
		Addr:         server.Addr(),
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
	}, server
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
