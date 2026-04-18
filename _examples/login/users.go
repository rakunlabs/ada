package login

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy/local"
)

// user is a seeded demo user.
type user struct {
	subject string
	email   string
	name    string
	hashed  []byte // bcrypt hash of the password
	roles   []string
}

// usersMu guards the in-memory user directory. Seeded users are available
// from startup; new accounts from the signup flow are appended here.
var usersMu sync.RWMutex

// users is the in-memory directory the local Verifier matches against.
//
// Seeded credentials:
//
//	alice / passw0rd!
//	bob   / hunter2
//
// In a real app this would be a database lookup behind the same Verifier
// signature. The demo uses bcrypt to keep the comparison honest.
var users = func() map[string]user {
	must := func(p string) []byte {
		h, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}
		return h
	}

	return map[string]user{
		"alice@example.com": {
			subject: "alice", email: "alice@example.com", name: "Alice Example",
			hashed: must("passw0rd!"),
			roles:  []string{"admin", "user"},
		},
		"bob@example.com": {
			subject: "bob", email: "bob@example.com", name: "Bob Example",
			hashed: must("hunter2"),
			roles:  []string{"user"},
		},
	}
}()

// LocalVerifier is the demo's local-strategy credential check.
//
// The username can be the full email or the bare subject ("alice"). On match,
// it returns an Identity with the user's roles; on miss it returns
// local.ErrInvalidCredentials so the strategy responds 401.
func LocalVerifier(_ context.Context, username, password string) (*identity.Identity, error) {
	u, ok := lookup(username)
	if !ok {
		// Constant-time fake compare so timing leaks nothing about the username.
		_ = subtle.ConstantTimeCompare([]byte(password), []byte("placeholder"))

		return nil, local.ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword(u.hashed, []byte(password)); err != nil {
		return nil, local.ErrInvalidCredentials
	}

	return &identity.Identity{
		Subject:       u.subject,
		Email:         u.email,
		EmailVerified: true,
		Name:          u.name,
		Roles:         u.roles,
	}, nil
}

// LocalRegistrar is the demo's signup handler. It enforces a minimum password
// length and inserts the new account into the in-memory directory keyed by
// the subject (username). Real apps would do an INSERT against the user
// table behind the same error contract (ErrUserExists / ErrInvalidInput).
func LocalRegistrar(_ context.Context, req local.RegisterRequest) (*identity.Identity, error) {
	username := strings.TrimSpace(req.Username)
	password := req.Password

	if len(password) < 6 {
		return nil, fmt.Errorf("password must be at least 6 characters: %w", local.ErrInvalidInput)
	}

	usersMu.Lock()
	defer usersMu.Unlock()

	if _, ok := lookupLocked(username); ok {
		return nil, local.ErrUserExists
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	u := user{
		subject: username,
		name:    username,
		hashed:  hashed,
		roles:   []string{"user"},
	}
	users[username] = u

	return &identity.Identity{
		Subject: u.subject,
		Name:    u.name,
		Roles:   u.roles,
	}, nil
}

func lookup(username string) (user, bool) {
	usersMu.RLock()
	defer usersMu.RUnlock()

	return lookupLocked(username)
}

// lookupLocked is the mutex-free form; callers must hold usersMu.
func lookupLocked(username string) (user, bool) {
	if u, ok := users[username]; ok {
		return u, true
	}

	for _, u := range users {
		if u.subject == username {
			return u, true
		}
	}

	return user{}, false
}
