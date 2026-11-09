package store_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/oauthserver"
	"github.com/rakunlabs/ada/middleware/auth/password"
	"github.com/rakunlabs/ada/_examples/authkit/store"
	"github.com/rakunlabs/ada/_examples/authkit/users"

	_ "modernc.org/sqlite"
)

// backend is a database the tests run against. The example runs on SQLite;
// the same tests pass on PostgreSQL and MySQL when you add those drivers and
// backends here.
type backend struct {
	name, driver, dsn string
	dialect           store.Dialect
}

func backends(t *testing.T) []backend {
	t.Helper()

	return []backend{{name: "sqlite", driver: "sqlite", dsn: filepath.Join(t.TempDir(), "auth.db"), dialect: store.SQLite}}
}

// each runs fn against every backend, with fresh tables under a unique
// prefix so runs do not see each other's rows.
func each(t *testing.T, fn func(t *testing.T, st *store.Store)) {
	t.Helper()

	for i, b := range backends(t) {
		t.Run(b.name, func(t *testing.T) {
			db, err := sql.Open(b.driver, b.dsn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })

			prefix := fmt.Sprintf("t%d_%d_", time.Now().UnixNano()%1e9, i)

			st, err := store.New(db, store.Config{Dialect: b.dialect, TablePrefix: prefix})
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			if err := st.CreateTables(ctx); err != nil {
				t.Fatal(err)
			}
			// Idempotent: apps call it on every start.
			if err := st.CreateTables(ctx); err != nil {
				t.Fatalf("second CreateTables: %v", err)
			}

			t.Cleanup(func() {
				for _, table := range []string{"users", "clients", "codes", "tokens", "consents"} {
					_, _ = db.Exec("DROP TABLE " + prefix + table)
				}
			})

			fn(t, st)
		})
	}
}

func TestStore(t *testing.T) { each(t, testStore) }

func testStore(t *testing.T, st *store.Store) {
	ctx := context.Background()
	now := time.UnixMilli(time.Now().UnixMilli())

	client := &oauthserver.Client{ID: "c1", Name: "Claude", RedirectURIs: []string{"http://127.0.0.1/cb"}, TokenEndpointAuthMethod: "none", CreatedAt: now}
	if err := st.CreateClient(ctx, client); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetClient(ctx, "c1")
	if err != nil || got.Name != "Claude" || got.RedirectURIs[0] != "http://127.0.0.1/cb" || !got.CreatedAt.Equal(now) {
		t.Fatalf("client: %+v %v", got, err)
	}
	if _, err := st.GetClient(ctx, "nope"); !errors.Is(err, oauthserver.ErrNotFound) {
		t.Fatalf("missing client: %v", err)
	}
	if same, _ := st.ClientsByName(ctx, "Claude"); len(same) != 1 {
		t.Fatalf("by name: %d", len(same))
	}

	id := &identity.Identity{Subject: "alice", Roles: []string{"admin"}}
	code := &oauthserver.Code{Hash: "h1", ClientID: "c1", Identity: id, Scopes: []string{"a", "b"}, Extra: map[string]any{"k": "v"}, ExpiresAt: now.Add(time.Minute)}
	if err := st.SaveCode(ctx, code); err != nil {
		t.Fatal(err)
	}

	taken, err := st.TakeCode(ctx, "h1")
	if err != nil || taken.Identity.Subject != "alice" || len(taken.Scopes) != 2 || taken.Extra["k"] != "v" {
		t.Fatalf("take: %+v %v", taken, err)
	}
	if _, err := st.TakeCode(ctx, "h1"); !errors.Is(err, oauthserver.ErrNotFound) {
		t.Fatalf("code reuse: %v", err)
	}

	tok := &oauthserver.Token{
		ID: "t1", ClientID: "c1", Name: "Claude", Identity: id, Scopes: []string{"a"},
		AccessHash: "a1", AccessExpiresAt: now.Add(time.Hour), RefreshHash: "r1", RefreshExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
	}
	if err := st.SaveToken(ctx, tok); err != nil {
		t.Fatal(err)
	}

	pat := &oauthserver.Token{ID: "t2", Name: "ci", Identity: id, AccessHash: "a2", CreatedAt: now.Add(time.Second)}
	if err := st.SaveToken(ctx, pat); err != nil {
		t.Fatal(err)
	}

	if got, err := st.TokenByAccess(ctx, "a1"); err != nil || got.Subject() != "alice" || got.RefreshHash != "r1" {
		t.Fatalf("by access: %+v %v", got, err)
	}
	if got, err := st.TokenByRefresh(ctx, "r1"); err != nil || got.ID != "t1" {
		t.Fatalf("by refresh: %+v %v", got, err)
	}
	if got, err := st.TokenByAccess(ctx, "a2"); err != nil || got.RefreshHash != "" || !got.AccessExpiresAt.IsZero() {
		t.Fatalf("pat: %+v %v", got, err)
	}

	rotated := *tok
	rotated.AccessHash, rotated.RefreshHash = "a3", "r3"
	if err := st.RotateToken(ctx, "r1", &rotated); err != nil {
		t.Fatal(err)
	}
	if err := st.RotateToken(ctx, "r1", &rotated); !errors.Is(err, oauthserver.ErrConflict) {
		t.Fatalf("double rotate: %v", err)
	}
	if _, err := st.TokenByAccess(ctx, "a1"); !errors.Is(err, oauthserver.ErrNotFound) {
		t.Fatal("old access hash still resolves")
	}

	list, err := st.TokensBySubject(ctx, "alice")
	if err != nil || len(list) != 2 || list[0].ID != "t2" {
		t.Fatalf("list: %v %v", list, err)
	}

	if err := st.SaveConsent(ctx, &oauthserver.Consent{Subject: "alice", ClientID: "c1", Scopes: []string{"a"}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveConsent(ctx, &oauthserver.Consent{Subject: "alice", ClientID: "c1", Scopes: []string{"a", "b"}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if c, err := st.GetConsent(ctx, "alice", "c1"); err != nil || len(c.Scopes) != 2 {
		t.Fatalf("consent: %+v %v", c, err)
	}

	if err := st.DeleteExpired(ctx, now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.TokenByAccess(ctx, "a3"); !errors.Is(err, oauthserver.ErrNotFound) {
		t.Fatal("expired token survived")
	}
	if _, err := st.TokenByAccess(ctx, "a2"); err != nil {
		t.Fatal("non-expiring token was swept")
	}

	if err := st.DeleteClient(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetConsent(ctx, "alice", "c1"); !errors.Is(err, oauthserver.ErrNotFound) {
		t.Fatal("consent survived client deletion")
	}
}

// TestWithServer runs the server's personal-token path over the SQL store.
func TestWithServer(t *testing.T) { each(t, testWithServer) }

func testWithServer(t *testing.T, st *store.Store) {
	ctx := context.Background()

	srv, err := oauthserver.New(oauthserver.Config{Issuer: "https://app.example.com"}, st)
	if err != nil {
		t.Fatal(err)
	}

	raw, tok, err := srv.IssueToken(ctx, oauthserver.IssueRequest{Name: "ci", Identity: &identity.Identity{Subject: "bob"}, Scopes: []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}

	got, id, err := srv.Validate(ctx, raw)
	if err != nil || got.ID != tok.ID || id.Subject != "bob" || id.Scopes[0] != "x" {
		t.Fatalf("validate: %+v %+v %v", got, id, err)
	}
}

func TestUsers(t *testing.T) { each(t, testUsers) }

func testUsers(t *testing.T, st *store.Store) {
	ctx := context.Background()

	svc, err := users.New(users.Config{Hasher: &password.PBKDF2{Iterations: 1000}}, st)
	if err != nil {
		t.Fatal(err)
	}

	if n, _ := st.CountUsers(ctx); n != 0 {
		t.Fatalf("count: %d", n)
	}

	u, err := svc.Create(ctx, users.CreateRequest{Username: "Ann", Password: "longenough", Roles: []string{"admin"}, Attributes: map[string]any{"team": "data"}})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Create(ctx, users.CreateRequest{Username: "ann", Password: "longenough"}); !errors.Is(err, users.ErrExists) {
		t.Fatalf("case-insensitive duplicate: %v", err)
	}

	got, err := st.GetUserByUsername(ctx, "ANN")
	if err != nil || got.ID != u.ID || got.Attributes["team"] != "data" || got.Roles[0] != "admin" {
		t.Fatalf("by username: %+v %v", got, err)
	}

	if _, err := svc.Verifier()(ctx, "ann", "longenough"); err != nil {
		t.Fatalf("login: %v", err)
	}

	bob, _ := svc.Create(ctx, users.CreateRequest{Username: "bob", Password: "longenough"})
	taken := "ann"
	if _, err := svc.Update(ctx, bob.ID, users.UpdateRequest{Username: &taken}); !errors.Is(err, users.ErrExists) {
		t.Fatalf("rename onto taken: %v", err)
	}

	off := true
	if _, err := svc.Update(ctx, bob.ID, users.UpdateRequest{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetUser(ctx, bob.ID); !got.Disabled {
		t.Fatal("disabled not stored")
	}

	if list, _ := st.ListUsers(ctx); len(list) != 2 || list[0].Username != "Ann" {
		t.Fatalf("list: %v", list)
	}

	if err := svc.Delete(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUser(ctx, bob.ID); !errors.Is(err, users.ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
}

// The full refresh flow on SQL: rotation keeps the previous hash so a replay
// is detected and revokes the grant, and granted scopes survive narrowing.
func TestRefreshReuseOnSQL(t *testing.T) { each(t, testRefreshReuse) }

func testRefreshReuse(t *testing.T, st *store.Store) {
	ctx := context.Background()

	tok := &oauthserver.Token{
		ID: "g", ClientID: "c", Identity: &identity.Identity{Subject: "a", Claims: map[string]any{users.ClaimPermissions: []string{"x:*"}}},
		Scopes: []string{"a", "b"}, GrantedScopes: []string{"a", "b"}, AccessHash: "a1", RefreshHash: "r1", CreatedAt: time.Now(),
	}
	if err := st.SaveToken(ctx, tok); err != nil {
		t.Fatal(err)
	}

	next := *tok
	next.Scopes, next.AccessHash, next.RefreshHash, next.PreviousRefreshHash = []string{"a"}, "a2", "r2", "r1"
	if err := st.RotateToken(ctx, "r1", &next); err != nil {
		t.Fatal(err)
	}

	// The old refresh hash still finds the grant, so reuse can be detected.
	got, err := st.TokenByRefresh(ctx, "r1")
	if err != nil || got.RefreshHash != "r2" || got.PreviousRefreshHash != "r1" {
		t.Fatalf("by previous refresh: %+v %v", got, err)
	}
	if len(got.Scopes) != 1 || len(got.GrantedScopes) != 2 {
		t.Fatalf("scopes: %v granted %v", got.Scopes, got.GrantedScopes)
	}
	if perms, ok := got.Identity.Claims[users.ClaimPermissions].([]string); !ok || perms[0] != "x:*" {
		t.Fatalf("permissions claim type: %T", got.Identity.Claims[users.ClaimPermissions])
	}

	// A second rotation drops r1 from the index.
	third := *got
	third.AccessHash, third.RefreshHash, third.PreviousRefreshHash = "a3", "r3", "r2"
	if err := st.RotateToken(ctx, "r2", &third); err != nil {
		t.Fatal(err)
	}
	if _, err := st.TokenByRefresh(ctx, "r1"); !errors.Is(err, oauthserver.ErrNotFound) {
		t.Fatalf("two rotations ago: %v", err)
	}

	if err := st.SaveConsent(ctx, &oauthserver.Consent{Subject: "a", ClientID: "c", ExtraHash: "eh", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if c, err := st.GetConsent(ctx, "a", "c"); err != nil || c.ExtraHash != "eh" {
		t.Fatalf("consent extra hash: %+v %v", c, err)
	}

	long := strings.Repeat("n", 300)
	if err := st.SaveToken(ctx, &oauthserver.Token{ID: "long", Name: long, Identity: &identity.Identity{Subject: "a"}, AccessHash: "al", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("long token name: %v", err)
	}
}
