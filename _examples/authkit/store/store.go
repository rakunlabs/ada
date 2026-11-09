// Package store keeps auth data in SQL: users (users.Store) and the OAuth
// server's clients, codes, tokens and consents (oauthserver.Store), for
// PostgreSQL, SQLite and MySQL.
//
// Bring your own *sql.DB and driver. Create the tables with CreateTables, or
// copy Schema into your migrations (muz, goose, …) to keep them with the
// rest of your schema.
//
// Secrets never reach the database: codes, tokens and client secrets are
// stored as SHA-256 hashes. Identities, scopes and Extra are stored as JSON
// text, and times as Unix milliseconds, so the same schema works everywhere.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/oauthserver"
	"github.com/rakunlabs/ada/_examples/authkit/users"
)

// Dialect selects placeholder style and column types.
type Dialect string

const (
	Postgres Dialect = "postgres"
	SQLite   Dialect = "sqlite"
	MySQL    Dialect = "mysql"
)

// Config configures a Store.
type Config struct {
	// Dialect is required.
	Dialect Dialect `cfg:"dialect"`
	// TablePrefix is put in front of every table name. Default "oauth_".
	TablePrefix string `cfg:"table_prefix"`
}

// Store implements users.Store, oauthserver.Store, ClientFinder and
// ConsentStore. One value serves both; pass it as kit.Stores{Users: st,
// OAuth: st}.
type Store struct {
	db      *sql.DB
	dialect Dialect
	prefix  string

	// mu serializes access on SQLite, which allows one writer at a time and
	// answers a second one with SQLITE_BUSY instead of waiting. Without it,
	// two clients refreshing at once get a 500. It covers one process; for
	// several processes on one file add _pragma=busy_timeout(5000) to the
	// DSN.
	mu sync.Mutex
}

// lock takes mu on SQLite and returns its release; elsewhere it is a no-op.
// Only exported methods call it, so internal helpers never lock twice.
func (s *Store) lock() func() {
	if s.dialect != SQLite {
		return func() {}
	}

	s.mu.Lock()

	return s.mu.Unlock
}

var (
	_ oauthserver.Store        = (*Store)(nil)
	_ oauthserver.ClientFinder = (*Store)(nil)
	_ oauthserver.ConsentStore = (*Store)(nil)
	_ users.Store              = (*Store)(nil)
)

// New returns a Store on db.
func New(db *sql.DB, cfg Config) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("store: nil db")
	}

	switch cfg.Dialect {
	case Postgres, SQLite, MySQL:
	default:
		return nil, fmt.Errorf("store: unsupported dialect %q", cfg.Dialect)
	}

	if cfg.TablePrefix == "" {
		cfg.TablePrefix = "oauth_"
	}

	for _, c := range cfg.TablePrefix {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return nil, fmt.Errorf("store: table prefix %q may only contain letters, digits and _", cfg.TablePrefix)
		}
	}

	return &Store{db: db, dialect: cfg.Dialect, prefix: cfg.TablePrefix}, nil
}

// Schema returns the CREATE TABLE and CREATE INDEX statements for the
// dialect and prefix. Every statement is safe to run again on an existing
// schema: put them in your migrations, or call CreateTables at start.
func Schema(dialect Dialect, prefix string) []string {
	if prefix == "" {
		prefix = "oauth_"
	}

	key := "TEXT"
	if dialect == MySQL {
		key = "VARCHAR(191)"
	}

	// MySQL has no CREATE INDEX IF NOT EXISTS, so there the indexes live
	// in the table definition; elsewhere they are separate statements.
	index := func(table, name, cols string) (inline, stmt string) {
		if dialect == MySQL {
			return ",\n\tINDEX " + prefix + name + " (" + cols + ")", ""
		}

		return "", "CREATE INDEX IF NOT EXISTS " + prefix + name + " ON " + prefix + table + " (" + cols + ")"
	}

	clientsName, clientsNameStmt := index("clients", "clients_name", "name")
	tokensSubject, tokensSubjectStmt := index("tokens", "tokens_subject", "subject")
	tokensClient, tokensClientStmt := index("tokens", "tokens_client", "client_id")

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ` + prefix + `users (
	id ` + key + ` PRIMARY KEY,
	username ` + key + ` NOT NULL,
	username_key ` + key + ` NOT NULL UNIQUE,
	name TEXT NOT NULL,
	email TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	roles TEXT NOT NULL,
	disabled BOOLEAN NOT NULL,
	attributes TEXT NOT NULL,
	created_at BIGINT NOT NULL,
	updated_at BIGINT NOT NULL
)`,
		`CREATE TABLE IF NOT EXISTS ` + prefix + `clients (
	id ` + key + ` PRIMARY KEY,
	name ` + key + ` NOT NULL,
	redirect_uris TEXT NOT NULL,
	grant_types TEXT NOT NULL,
	auth_method ` + key + ` NOT NULL,
	secret_hash ` + key + ` NOT NULL,
	created_at BIGINT NOT NULL` + clientsName + `
)`,
		`CREATE TABLE IF NOT EXISTS ` + prefix + `codes (
	hash ` + key + ` PRIMARY KEY,
	client_id ` + key + ` NOT NULL,
	identity TEXT NOT NULL,
	redirect_uri TEXT NOT NULL,
	code_challenge ` + key + ` NOT NULL,
	scopes TEXT NOT NULL,
	resource TEXT NOT NULL,
	extra TEXT NOT NULL,
	expires_at BIGINT NOT NULL
)`,
		`CREATE TABLE IF NOT EXISTS ` + prefix + `tokens (
	id ` + key + ` PRIMARY KEY,
	client_id ` + key + ` NOT NULL,
	name TEXT NOT NULL,
	subject ` + key + ` NOT NULL,
	identity TEXT NOT NULL,
	scopes TEXT NOT NULL,
	granted_scopes TEXT NOT NULL,
	resource TEXT NOT NULL,
	extra TEXT NOT NULL,
	access_hash ` + key + ` NOT NULL UNIQUE,
	access_expires_at BIGINT NOT NULL,
	refresh_hash ` + key + ` NULL UNIQUE,
	previous_refresh_hash ` + key + ` NULL UNIQUE,
	refresh_expires_at BIGINT NOT NULL,
	rotated_at BIGINT NOT NULL,
	created_at BIGINT NOT NULL` + tokensSubject + tokensClient + `
)`,
		`CREATE TABLE IF NOT EXISTS ` + prefix + `consents (
	subject ` + key + ` NOT NULL,
	client_id ` + key + ` NOT NULL,
	scopes TEXT NOT NULL,
	resource TEXT NOT NULL,
	extra_hash ` + key + ` NOT NULL,
	created_at BIGINT NOT NULL,
	PRIMARY KEY (subject, client_id)
)`,
	}

	for _, stmt := range []string{clientsNameStmt, tokensSubjectStmt, tokensClientStmt} {
		if stmt != "" {
			stmts = append(stmts, stmt)
		}
	}

	return stmts
}

// CreateTables runs Schema. It is idempotent on every dialect.
func (s *Store) CreateTables(ctx context.Context) error {
	defer s.lock()()

	for _, stmt := range Schema(s.dialect, s.prefix) {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("store: create tables: %w", err)
		}
	}

	return nil
}

// q rewrites ? placeholders for the dialect and expands {p} to the prefix.
func (s *Store) q(query string) string {
	query = strings.ReplaceAll(query, "{p}", s.prefix)
	if s.dialect != Postgres {
		return query
	}

	var b strings.Builder

	n := 0
	for i := range len(query) {
		if query[i] == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))

			continue
		}

		b.WriteByte(query[i])
	}

	return b.String()
}

// ////////////////////////////////////////////////////////////////////////////
// clients

const clientCols = `id, name, redirect_uris, grant_types, auth_method, secret_hash, created_at`

// CreateClient implements oauthserver.Store.
func (s *Store) CreateClient(ctx context.Context, c *oauthserver.Client) error {
	defer s.lock()()

	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO {p}clients (`+clientCols+`) VALUES (?, ?, ?, ?, ?, ?, ?)`),
		c.ID, c.Name, mustJSON(c.RedirectURIs), mustJSON(c.GrantTypes), c.TokenEndpointAuthMethod, c.SecretHash, millis(c.CreatedAt))
	if err != nil {
		return fmt.Errorf("store: create client: %w", err)
	}

	return nil
}

// GetClient implements oauthserver.Store.
func (s *Store) GetClient(ctx context.Context, id string) (*oauthserver.Client, error) {
	defer s.lock()()

	row := s.db.QueryRowContext(ctx, s.q(`SELECT `+clientCols+` FROM {p}clients WHERE id = ?`), id)

	return scanClient(row)
}

// ClientsByName implements oauthserver.ClientFinder.
func (s *Store) ClientsByName(ctx context.Context, name string) ([]*oauthserver.Client, error) {
	defer s.lock()()

	return s.clients(ctx, s.q(`SELECT `+clientCols+` FROM {p}clients WHERE name = ? ORDER BY created_at`), name)
}

// ListClients returns every client, oldest first.
func (s *Store) ListClients(ctx context.Context) ([]*oauthserver.Client, error) {
	defer s.lock()()

	return s.clients(ctx, s.q(`SELECT `+clientCols+` FROM {p}clients ORDER BY created_at`))
}

func (s *Store) clients(ctx context.Context, query string, args ...any) ([]*oauthserver.Client, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list clients: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*oauthserver.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}

		out = append(out, c)
	}

	return out, rows.Err()
}

// DeleteClient removes a client with its tokens and consents.
func (s *Store) DeleteClient(ctx context.Context, id string) error {
	defer s.lock()()

	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, stmt := range []string{
			`DELETE FROM {p}tokens WHERE client_id = ?`,
			`DELETE FROM {p}consents WHERE client_id = ?`,
			`DELETE FROM {p}codes WHERE client_id = ?`,
			`DELETE FROM {p}clients WHERE id = ?`,
		} {
			if _, err := tx.ExecContext(ctx, s.q(stmt), id); err != nil {
				return fmt.Errorf("store: delete client: %w", err)
			}
		}

		return nil
	})
}

type scanner interface{ Scan(dest ...any) error }

func scanClient(row scanner) (*oauthserver.Client, error) {
	var (
		c              oauthserver.Client
		redirects, gts string
		created        int64
	)

	if err := row.Scan(&c.ID, &c.Name, &redirects, &gts, &c.TokenEndpointAuthMethod, &c.SecretHash, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, oauthserver.ErrNotFound
		}

		return nil, fmt.Errorf("store: scan client: %w", err)
	}

	if err := json.Unmarshal([]byte(redirects), &c.RedirectURIs); err != nil {
		return nil, fmt.Errorf("store: client redirect_uris: %w", err)
	}
	if err := json.Unmarshal([]byte(gts), &c.GrantTypes); err != nil {
		return nil, fmt.Errorf("store: client grant_types: %w", err)
	}

	c.CreatedAt = fromMillis(created)

	return &c, nil
}

// ////////////////////////////////////////////////////////////////////////////
// codes

// SaveCode implements oauthserver.Store.
func (s *Store) SaveCode(ctx context.Context, c *oauthserver.Code) error {
	defer s.lock()()

	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO {p}codes
		(hash, client_id, identity, redirect_uri, code_challenge, scopes, resource, extra, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		c.Hash, c.ClientID, mustJSON(c.Identity), c.RedirectURI, c.CodeChallenge,
		strings.Join(c.Scopes, " "), c.Resource, mustJSON(c.Extra), millis(c.ExpiresAt))
	if err != nil {
		return fmt.Errorf("store: save code: %w", err)
	}

	return nil
}

// TakeCode implements oauthserver.Store. Of two concurrent exchanges only
// the one whose DELETE removes the row gets the code.
func (s *Store) TakeCode(ctx context.Context, hash string) (*oauthserver.Code, error) {
	defer s.lock()()

	var code *oauthserver.Code

	err := s.tx(ctx, func(tx *sql.Tx) error {
		var (
			c                 oauthserver.Code
			id, scopes, extra string
			expires           int64
		)

		err := tx.QueryRowContext(ctx, s.q(`SELECT hash, client_id, identity, redirect_uri, code_challenge, scopes, resource, extra, expires_at
			FROM {p}codes WHERE hash = ?`), hash).
			Scan(&c.Hash, &c.ClientID, &id, &c.RedirectURI, &c.CodeChallenge, &scopes, &c.Resource, &extra, &expires)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return oauthserver.ErrNotFound
			}

			return fmt.Errorf("store: take code: %w", err)
		}

		res, err := tx.ExecContext(ctx, s.q(`DELETE FROM {p}codes WHERE hash = ?`), hash)
		if err != nil {
			return fmt.Errorf("store: take code: %w", err)
		}
		if n, err := res.RowsAffected(); err == nil && n == 0 {
			return oauthserver.ErrNotFound
		}

		if c.Identity, err = decodeIdentity(id); err != nil {
			return err
		}
		if c.Extra, err = decodeExtra(extra); err != nil {
			return err
		}

		c.Scopes = strings.Fields(scopes)
		c.ExpiresAt = fromMillis(expires)
		code = &c

		return nil
	})

	return code, err
}

// ////////////////////////////////////////////////////////////////////////////
// tokens

const tokenCols = `id, client_id, name, identity, scopes, granted_scopes, resource, extra,
	access_hash, access_expires_at, refresh_hash, previous_refresh_hash, refresh_expires_at, rotated_at, created_at`

// SaveToken implements oauthserver.Store.
func (s *Store) SaveToken(ctx context.Context, t *oauthserver.Token) error {
	defer s.lock()()

	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO {p}tokens (`+tokenCols+`, subject)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		t.ID, t.ClientID, t.Name, mustJSON(t.Identity), strings.Join(t.Scopes, " "), strings.Join(t.GrantedScopes, " "),
		t.Resource, mustJSON(t.Extra), t.AccessHash, millis(t.AccessExpiresAt), nullable(t.RefreshHash),
		nullable(t.PreviousRefreshHash), millis(t.RefreshExpiresAt), millis(t.RotatedAt), millis(t.CreatedAt), t.Subject())
	if err != nil {
		return fmt.Errorf("store: save token: %w", err)
	}

	return nil
}

// TokenByAccess implements oauthserver.Store.
func (s *Store) TokenByAccess(ctx context.Context, hash string) (*oauthserver.Token, error) {
	defer s.lock()()

	return scanToken(s.db.QueryRowContext(ctx, s.q(`SELECT `+tokenCols+` FROM {p}tokens WHERE access_hash = ?`), hash))
}

// TokenByRefresh implements oauthserver.Store.
func (s *Store) TokenByRefresh(ctx context.Context, hash string) (*oauthserver.Token, error) {
	defer s.lock()()

	if hash == "" {
		return nil, oauthserver.ErrNotFound
	}

	return scanToken(s.db.QueryRowContext(ctx, s.q(`SELECT `+tokenCols+` FROM {p}tokens WHERE refresh_hash = ? OR previous_refresh_hash = ?`), hash, hash))
}

// RotateToken implements oauthserver.Store with a conditional UPDATE.
func (s *Store) RotateToken(ctx context.Context, oldRefreshHash string, t *oauthserver.Token) error {
	defer s.lock()()

	res, err := s.db.ExecContext(ctx, s.q(`UPDATE {p}tokens SET
		identity = ?, scopes = ?, granted_scopes = ?, access_hash = ?, access_expires_at = ?,
		refresh_hash = ?, previous_refresh_hash = ?, refresh_expires_at = ?, rotated_at = ?, subject = ?
		WHERE id = ? AND refresh_hash = ?`),
		mustJSON(t.Identity), strings.Join(t.Scopes, " "), strings.Join(t.GrantedScopes, " "), t.AccessHash,
		millis(t.AccessExpiresAt), nullable(t.RefreshHash), nullable(t.PreviousRefreshHash), millis(t.RefreshExpiresAt),
		millis(t.RotatedAt), t.Subject(), t.ID, oldRefreshHash)
	if err != nil {
		return fmt.Errorf("store: rotate token: %w", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rotate token: %w", err)
	}
	if n == 0 {
		return oauthserver.ErrConflict
	}

	return nil
}

// DeleteToken implements oauthserver.Store.
func (s *Store) DeleteToken(ctx context.Context, id string) error {
	defer s.lock()()

	if _, err := s.db.ExecContext(ctx, s.q(`DELETE FROM {p}tokens WHERE id = ?`), id); err != nil {
		return fmt.Errorf("store: delete token: %w", err)
	}

	return nil
}

// TokensBySubject lists the tokens of a user, newest first.
func (s *Store) TokensBySubject(ctx context.Context, subject string) ([]*oauthserver.Token, error) {
	defer s.lock()()

	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+tokenCols+` FROM {p}tokens WHERE subject = ? ORDER BY created_at DESC`), subject)
	if err != nil {
		return nil, fmt.Errorf("store: list tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*oauthserver.Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}

		out = append(out, t)
	}

	return out, rows.Err()
}

// DeleteSubject removes every token and consent of a user, e.g. when the
// account is deleted.
func (s *Store) DeleteSubject(ctx context.Context, subject string) error {
	defer s.lock()()

	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, stmt := range []string{`DELETE FROM {p}tokens WHERE subject = ?`, `DELETE FROM {p}consents WHERE subject = ?`} {
			if _, err := tx.ExecContext(ctx, s.q(stmt), subject); err != nil {
				return fmt.Errorf("store: delete subject: %w", err)
			}
		}

		return nil
	})
}

// DeleteExpired removes expired codes and tokens that can no longer be used
// or refreshed. Run it periodically, e.g. from a hardloop cron.
func (s *Store) DeleteExpired(ctx context.Context, now time.Time) error {
	defer s.lock()()

	ms := millis(now)

	if _, err := s.db.ExecContext(ctx, s.q(`DELETE FROM {p}codes WHERE expires_at < ?`), ms); err != nil {
		return fmt.Errorf("store: delete expired codes: %w", err)
	}

	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM {p}tokens
		WHERE access_expires_at > 0 AND access_expires_at < ?
		AND (refresh_hash IS NULL OR (refresh_expires_at > 0 AND refresh_expires_at < ?))`), ms, ms)
	if err != nil {
		return fmt.Errorf("store: delete expired tokens: %w", err)
	}

	return nil
}

func scanToken(row scanner) (*oauthserver.Token, error) {
	var (
		t                              oauthserver.Token
		id, scopes, granted, extra     string
		refresh, previous              sql.NullString
		access, rexp, rotated, created int64
	)

	err := row.Scan(&t.ID, &t.ClientID, &t.Name, &id, &scopes, &granted, &t.Resource, &extra,
		&t.AccessHash, &access, &refresh, &previous, &rexp, &rotated, &created)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, oauthserver.ErrNotFound
		}

		return nil, fmt.Errorf("store: scan token: %w", err)
	}

	if t.Identity, err = decodeIdentity(id); err != nil {
		return nil, err
	}
	if t.Extra, err = decodeExtra(extra); err != nil {
		return nil, err
	}

	t.Scopes = strings.Fields(scopes)
	t.GrantedScopes = strings.Fields(granted)
	t.RefreshHash = refresh.String
	t.PreviousRefreshHash = previous.String
	t.AccessExpiresAt = fromMillis(access)
	t.RefreshExpiresAt = fromMillis(rexp)
	t.RotatedAt = fromMillis(rotated)
	t.CreatedAt = fromMillis(created)

	return &t, nil
}

// ////////////////////////////////////////////////////////////////////////////
// consents

// SaveConsent implements oauthserver.ConsentStore.
func (s *Store) SaveConsent(ctx context.Context, c *oauthserver.Consent) error {
	defer s.lock()()

	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, s.q(`DELETE FROM {p}consents WHERE subject = ? AND client_id = ?`), c.Subject, c.ClientID); err != nil {
			return fmt.Errorf("store: save consent: %w", err)
		}

		_, err := tx.ExecContext(ctx, s.q(`INSERT INTO {p}consents (subject, client_id, scopes, resource, extra_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)`),
			c.Subject, c.ClientID, strings.Join(c.Scopes, " "), c.Resource, c.ExtraHash, millis(c.CreatedAt))
		if err != nil {
			return fmt.Errorf("store: save consent: %w", err)
		}

		return nil
	})
}

// GetConsent implements oauthserver.ConsentStore.
func (s *Store) GetConsent(ctx context.Context, subject, clientID string) (*oauthserver.Consent, error) {
	defer s.lock()()

	var (
		c       = oauthserver.Consent{Subject: subject, ClientID: clientID}
		scopes  string
		created int64
	)

	err := s.db.QueryRowContext(ctx, s.q(`SELECT scopes, resource, extra_hash, created_at FROM {p}consents WHERE subject = ? AND client_id = ?`), subject, clientID).
		Scan(&scopes, &c.Resource, &c.ExtraHash, &created)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, oauthserver.ErrNotFound
		}

		return nil, fmt.Errorf("store: get consent: %w", err)
	}

	c.Scopes = strings.Fields(scopes)
	c.CreatedAt = fromMillis(created)

	return &c, nil
}

// DeleteConsent implements oauthserver.ConsentStore.
func (s *Store) DeleteConsent(ctx context.Context, subject, clientID string) error {
	defer s.lock()()

	if _, err := s.db.ExecContext(ctx, s.q(`DELETE FROM {p}consents WHERE subject = ? AND client_id = ?`), subject, clientID); err != nil {
		return fmt.Errorf("store: delete consent: %w", err)
	}

	return nil
}

// ////////////////////////////////////////////////////////////////////////////
// helpers

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}

	if err := fn(tx); err != nil {
		_ = tx.Rollback()

		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}

	return nil
}

func millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}

	return t.UnixMilli()
}

func fromMillis(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}

	return time.UnixMilli(ms)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}

	return s
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Only unmarshalable Extra values get here; store them as null
		// rather than fail an otherwise valid grant.
		return "null"
	}

	return string(b)
}

func decodeIdentity(raw string) (*identity.Identity, error) {
	if raw == "" || raw == "null" {
		return nil, nil
	}

	var id identity.Identity
	if err := json.Unmarshal([]byte(raw), &id); err != nil {
		return nil, fmt.Errorf("store: decode identity: %w", err)
	}

	// JSON turns []string claims into []any; give known ones back their
	// type so code reading them sees the same thing as with the memory
	// store.
	if list, ok := id.Claims[users.ClaimPermissions].([]any); ok {
		perms := make([]string, 0, len(list))
		for _, v := range list {
			if s, ok := v.(string); ok {
				perms = append(perms, s)
			}
		}

		id.Claims[users.ClaimPermissions] = perms
	}

	return &id, nil
}

func decodeExtra(raw string) (map[string]any, error) {
	if raw == "" || raw == "null" {
		return nil, nil
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("store: decode extra: %w", err)
	}

	return m, nil
}
