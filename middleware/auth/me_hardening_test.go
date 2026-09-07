package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/issuer"
	"github.com/rakunlabs/ada/middleware/auth/session"
)

type snapshotIssuer struct {
	issuer.Issuer // Any accidental refresh/revoke/issue panics: /me is read-only.
	pair          *issuer.Pair
	err           error
}

func (s *snapshotIssuer) Resolve(context.Context, string) (*issuer.Pair, error) { return s.pair, s.err }

func TestMeDirectSnapshot(t *testing.T) {
	for _, name := range []string{"valid", "expired", "pending", "pending context", "backend", "conflict", "not found", "revoked", "nil pair", "nil identity", "missing cookie"} {
		t.Run(name, func(t *testing.T) {
			id := &identity.Identity{Subject: "SECRET_IDENTITY"}
			iss := &snapshotIssuer{pair: &issuer.Pair{Identity: id, Access: issuer.Token{ExpiresAt: time.Now().Add(time.Hour)}}}
			s := &session.Session{Issuer: iss}
			if err := s.Init(); err != nil {
				t.Fatal(err)
			}
			a := &Auth{issuer: iss, session: s}
			r := httptest.NewRequest("GET", "/login/me", nil)
			if name != "missing cookie" {
				r.AddCookie(&http.Cookie{Name: s.CookieName, Value: "keep-session"})
			}
			want := 401
			switch name {
			case "valid":
				want = 200
			case "expired":
				iss.pair.Access.ExpiresAt = time.Now()
			case "pending", "pending context":
				id.Claims = map[string]any{pendingClaim: true}
				if name == "pending context" {
					r = r.WithContext(identity.WithContext(r.Context(), id))
				}
			case "backend":
				iss.err = errors.New("database SECRET unavailable")
				want = 503
			case "conflict":
				iss.err = issuer.ErrTransactionConflict
				want = 503
			case "not found":
				iss.err = issuer.ErrNotFound
			case "revoked":
				iss.err = issuer.ErrRevoked
			case "nil pair":
				iss.pair = nil
				want = 503
			case "nil identity":
				iss.pair.Identity = nil
				want = 503
			}
			w := httptest.NewRecorder()
			a.handleMe(w, r)
			if w.Code != want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body)
			}
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("/me mutated credentials")
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("cacheable identity/error")
			}
			if want != 200 && strings.Contains(w.Body.String(), "SECRET") {
				t.Fatal("error leaked identity/backend details")
			}
		})
	}
}
