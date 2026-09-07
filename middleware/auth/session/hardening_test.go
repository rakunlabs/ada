package session_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/issuer"
	"github.com/rakunlabs/ada/middleware/auth/session"
)

type failureIssuer struct {
	issuer.Issuer
	pair                   *issuer.Pair
	resolveErr, refreshErr error
	refreshCalls           int
}

func (f *failureIssuer) Resolve(context.Context, string) (*issuer.Pair, error) {
	return f.pair, f.resolveErr
}
func (f *failureIssuer) Refresh(context.Context, string, string) (*issuer.Pair, error) {
	f.refreshCalls++
	return f.pair, f.refreshErr
}

func TestSessionFailureClassification(t *testing.T) {
	for _, phase := range []string{"resolve", "refresh"} {
		for _, failure := range []struct {
			name     string
			err      error
			terminal bool
		}{
			{"not found", issuer.ErrNotFound, true},
			{"revoked", issuer.ErrRevoked, true},
			{"access expired", issuer.ErrAccessExpired, true},
			{"refresh expired", issuer.ErrRefreshExpired, true},
			{"refresh invalid", issuer.ErrRefreshInvalid, true},
			{"conflict", issuer.ErrTransactionConflict, false},
			{"joined conflict", errors.Join(issuer.ErrRefreshInvalid, issuer.ErrTransactionConflict), false},
			{"backend", errors.New("database SECRET unavailable"), false},
			{"cancelled", context.Canceled, false},
			{"timeout", context.DeadlineExceeded, false},
		} {
			for _, redirect := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/redirect=%v", phase, failure.name, redirect), func(t *testing.T) {
					iss := &failureIssuer{pair: &issuer.Pair{Identity: &identity.Identity{Subject: "alice"}, Access: issuer.Token{Value: "access", ExpiresAt: time.Now().Add(-time.Hour)}, Refresh: issuer.Token{Value: "refresh"}}}
					err := fmt.Errorf("wrapped: %w", failure.err)
					if phase == "resolve" {
						iss.resolveErr = err
					} else {
						iss.refreshErr = err
					}
					s := &session.Session{Issuer: iss, LoginPath: "/login"}
					if err := s.Init(); err != nil {
						t.Fatal(err)
					}
					r := httptest.NewRequest("GET", "/protected", nil)
					r.AddCookie(&http.Cookie{Name: s.CookieName, Value: "keep-session"})
					if !redirect {
						r = r.WithContext(session.SetDisableRedirect(r.Context(), true))
					}
					w := httptest.NewRecorder()
					s.Require()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("reached protected handler") })).ServeHTTP(w, r)
					want := 503
					if failure.terminal {
						want = 401
						if redirect {
							want = 303
						}
					}
					if w.Code != want {
						t.Fatalf("status=%d body=%s", w.Code, w.Body)
					}
					cookies := w.Result().Cookies()
					if failure.terminal {
						if len(cookies) != 1 || cookies[0].MaxAge >= 0 {
							t.Fatal("terminal failure did not clear cookie")
						}
					} else if len(cookies) != 0 || w.Header().Get("Location") != "" {
						t.Fatal("infrastructure failure changed credentials/redirected")
					}
					if w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "SECRET") {
						t.Fatal("unsafe error response")
					}
				})
			}
		}
	}
}

func TestPendingSessionIsNotRefreshed(t *testing.T) {
	iss := &failureIssuer{pair: &issuer.Pair{Identity: &identity.Identity{Subject: "pending"}, Access: issuer.Token{ExpiresAt: time.Now().Add(-time.Hour)}}}
	s := &session.Session{Issuer: iss, RejectFn: func(*identity.Identity) bool { return true }}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: s.CookieName, Value: "pending"})
	w := httptest.NewRecorder()
	s.Require()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("reached protected handler") })).ServeHTTP(w, r)
	if iss.refreshCalls != 0 {
		t.Fatal("refreshed pending session")
	}
}
