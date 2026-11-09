package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/rakunlabs/ada/_examples/authkit/users"
)

const userCols = `id, username, name, email, password_hash, roles, disabled, attributes, created_at, updated_at`

// usernameKey is the case-folded username the unique index is on, so "Ann"
// and "ann" cannot both exist on any database collation.
func usernameKey(name string) string { return strings.ToLower(name) }

// CreateUser implements users.Store.
func (s *Store) CreateUser(ctx context.Context, u *users.User) error {
	defer s.lock()()

	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO {p}users (`+userCols+`, username_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		u.ID, u.Username, u.Name, u.Email, u.PasswordHash, mustJSON(u.Roles), u.Disabled, mustJSON(u.Attributes),
		millis(u.CreatedAt), millis(u.UpdatedAt), usernameKey(u.Username))
	if err != nil {
		if s.usernameTaken(ctx, u.Username, u.ID) {
			return users.ErrExists
		}

		return fmt.Errorf("store: create user: %w", err)
	}

	return nil
}

// usernameTaken tells a unique violation from other failures without
// parsing driver-specific errors.
func (s *Store) usernameTaken(ctx context.Context, name, exceptID string) bool {
	var id string

	err := s.db.QueryRowContext(ctx, s.q(`SELECT id FROM {p}users WHERE username_key = ?`), usernameKey(name)).Scan(&id)

	return err == nil && id != exceptID
}

// GetUser implements users.Store.
func (s *Store) GetUser(ctx context.Context, id string) (*users.User, error) {
	defer s.lock()()

	return scanUser(s.db.QueryRowContext(ctx, s.q(`SELECT `+userCols+` FROM {p}users WHERE id = ?`), id))
}

// GetUserByUsername implements users.Store.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*users.User, error) {
	defer s.lock()()

	return scanUser(s.db.QueryRowContext(ctx, s.q(`SELECT `+userCols+` FROM {p}users WHERE username_key = ?`), usernameKey(username)))
}

// ListUsers implements users.Store.
func (s *Store) ListUsers(ctx context.Context) ([]*users.User, error) {
	defer s.lock()()

	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+userCols+` FROM {p}users ORDER BY username_key`))
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*users.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}

		out = append(out, u)
	}

	return out, rows.Err()
}

// UpdateUser implements users.Store.
func (s *Store) UpdateUser(ctx context.Context, u *users.User) error {
	defer s.lock()()

	res, err := s.db.ExecContext(ctx, s.q(`UPDATE {p}users SET
		username = ?, username_key = ?, name = ?, email = ?, password_hash = ?, roles = ?, disabled = ?, attributes = ?, updated_at = ?
		WHERE id = ?`),
		u.Username, usernameKey(u.Username), u.Name, u.Email, u.PasswordHash, mustJSON(u.Roles), u.Disabled, mustJSON(u.Attributes),
		millis(u.UpdatedAt), u.ID)
	if err != nil {
		if s.usernameTaken(ctx, u.Username, u.ID) {
			return users.ErrExists
		}

		return fmt.Errorf("store: update user: %w", err)
	}

	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return users.ErrNotFound
	}

	return nil
}

// DeleteUser implements users.Store. The user's OAuth tokens and consents
// go with it.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	defer s.lock()()

	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, s.q(`DELETE FROM {p}users WHERE id = ?`), id)
		if err != nil {
			return fmt.Errorf("store: delete user: %w", err)
		}
		if n, err := res.RowsAffected(); err == nil && n == 0 {
			return users.ErrNotFound
		}

		for _, stmt := range []string{`DELETE FROM {p}tokens WHERE subject = ?`, `DELETE FROM {p}consents WHERE subject = ?`} {
			if _, err := tx.ExecContext(ctx, s.q(stmt), id); err != nil {
				return fmt.Errorf("store: delete user: %w", err)
			}
		}

		return nil
	})
}

// CountUsers implements users.Store.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	defer s.lock()()

	var n int
	if err := s.db.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM {p}users`)).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count users: %w", err)
	}

	return n, nil
}

func scanUser(row scanner) (*users.User, error) {
	var (
		u                 users.User
		roles, attributes string
		created, updated  int64
	)

	err := row.Scan(&u.ID, &u.Username, &u.Name, &u.Email, &u.PasswordHash, &roles, &u.Disabled, &attributes, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, users.ErrNotFound
		}

		return nil, fmt.Errorf("store: scan user: %w", err)
	}

	if err := json.Unmarshal([]byte(roles), &u.Roles); err != nil {
		return nil, fmt.Errorf("store: user roles: %w", err)
	}

	if attributes != "" && attributes != "null" {
		if err := json.Unmarshal([]byte(attributes), &u.Attributes); err != nil {
			return nil, fmt.Errorf("store: user attributes: %w", err)
		}
	}

	u.CreatedAt = fromMillis(created)
	u.UpdatedAt = fromMillis(updated)

	return &u, nil
}
