package oauth2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestJWKSBlockedRefreshDoesNotBlockCachedKey(t *testing.T) {
	body := testJWKS(t, "known")
	started := make(chan struct{})
	release := make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		close(started)
		<-release

		return jwksResponse(http.StatusOK, body), nil
	})}

	ks := newKeySet("https://idp.example/jwks", client)
	known := &rsa.PublicKey{N: big.NewInt(3), E: 3}
	ks.keys["known"] = known
	refreshDone := make(chan error, 1)
	go func() {
		_, err := ks.key(context.Background(), "unknown")
		refreshDone <- err
	}()
	<-started

	lookupDone := make(chan crypto.PublicKey, 1)
	go func() {
		key, _ := ks.key(context.Background(), "known")
		lookupDone <- key
	}()

	select {
	case key := <-lookupDone:
		if key != known {
			t.Fatalf("cached key = %v, want original key", key)
		}
	case <-time.After(time.Second):
		t.Fatal("cached key lookup blocked behind JWKS refresh")
	}

	close(release)
	if err := <-refreshDone; !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key error = %v", err)
	}
}

func TestJWKSConcurrentMissesCoalesce(t *testing.T) {
	body := testJWKS(t, "rotated")
	started := make(chan struct{})
	release := make(chan struct{})
	var requests atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			close(started)
		}
		<-release

		return jwksResponse(http.StatusOK, body), nil
	})}
	ks := newKeySet("https://idp.example/jwks", client)

	const callers = 16
	begin := make(chan struct{})
	errs := make(chan error, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	for range callers {
		go func() {
			ready.Done()
			<-begin
			_, err := ks.key(context.Background(), "rotated")
			errs <- err
		}()
	}
	ready.Wait()
	close(begin)
	<-started
	close(release)

	for range callers {
		if err := <-errs; err != nil {
			t.Errorf("concurrent miss: %v", err)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("JWKS requests = %d, want 1", got)
	}
}

func TestJWKSFailedFetchUsesShortRetryBackoff(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	requests := 0
	jwkBody := testJWKS(t, "current")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(jwkBody)
	}))
	t.Cleanup(server.Close)

	ks := newKeySet(server.URL, server.Client())
	ks.now = func() time.Time { return now }
	if _, err := ks.key(context.Background(), "current"); err == nil {
		t.Fatal("first fetch unexpectedly succeeded")
	}
	if _, err := ks.key(context.Background(), "current"); !errors.Is(err, ErrUnknownKey) || !strings.Contains(err.Error(), "throttled") {
		t.Fatalf("immediate retry error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("immediate retry made %d requests", requests)
	}

	now = now.Add(ks.retryRefresh)
	if _, err := ks.key(context.Background(), "current"); err != nil {
		t.Fatalf("retry after short backoff: %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestJWKSSuccessCooldownStartsAfterFetch(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	requests := 0
	body := testJWKS(t, "current")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		now = now.Add(2 * time.Minute)
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)

	ks := newKeySet(server.URL, server.Client())
	ks.now = func() time.Time { return now }
	if _, err := ks.key(context.Background(), "current"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.key(context.Background(), "rotated"); !errors.Is(err, ErrUnknownKey) || !strings.Contains(err.Error(), "throttled") {
		t.Fatalf("unknown key during success cooldown = %v", err)
	}
	if requests != 1 {
		t.Fatalf("success cooldown made %d requests", requests)
	}
}

func TestJWKSMissingKIDWithMultipleKeysIsImmediateAndAccurate(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	t.Cleanup(server.Close)

	ks := newKeySet(server.URL, server.Client())
	ks.keys = map[string]crypto.PublicKey{
		"one": &rsa.PublicKey{N: big.NewInt(3), E: 3},
		"two": &rsa.PublicKey{N: big.NewInt(5), E: 3},
	}
	for range 2 {
		_, err := ks.key(context.Background(), "")
		if !errors.Is(err, ErrMissingKeyID) || strings.Contains(err.Error(), "throttled") {
			t.Fatalf("missing kid error = %v", err)
		}
	}
	if requests != 0 {
		t.Fatalf("ambiguous missing kid triggered %d fetches", requests)
	}
}

func TestJWKSCountsMultipleUsableKeysWithoutKID(t *testing.T) {
	body, err := json.Marshal(map[string]any{"keys": []map[string]string{testJWK(t, ""), testJWK(t, "")}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(server.Close)

	ks := newKeySet(server.URL, server.Client())
	if _, err := ks.key(context.Background(), ""); !errors.Is(err, ErrMissingKeyID) {
		t.Fatalf("missing kid error = %v", err)
	}
}

func testJWKS(t *testing.T, kid string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"keys": []map[string]string{testJWK(t, kid)}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func testJWK(t *testing.T, kid string) map[string]string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e := big.NewInt(int64(key.PublicKey.E)).Bytes()
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(e),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jwksResponse(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
	}
}
