package login

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rakunlabs/ada"
	"github.com/rakunlabs/ada/middleware/auth"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy/passkey"
)

// PasskeyDemo wires the ada/passkey strategy into the example with an
// in-memory credential store. It returns the strategy (to register on
// the auth middleware) and a mount function (to expose the registration
// endpoints under /passkey/* on the public mux).
//
// Behavior is gated on PASSKEY_RPID — without it the demo runs unchanged
// and passkey support is simply unavailable, so the example still
// boots on a fresh checkout with no extra setup.
//
// Required env vars:
//
//	PASSKEY_RPID      bare host: "localhost", "example.com"
//	PASSKEY_ORIGINS   space-separated origins (with scheme + optional port);
//	                  e.g. "http://localhost:8080".
//
// Optional:
//
//	PASSKEY_NAME      strategy name (URL slug); default "passkey"
//	PASSKEY_LABEL     button label; default "Sign in with a passkey"
//
// The demo deliberately stores everything in memory: process restart =
// fresh enrollment table. Real deployments must persist Credential
// rows in a database keyed by both the credential id (lookup) and
// the user handle (security page listing).
func PasskeyDemo() (*passkey.Strategy, func(*ada.Mux), error) {
	rpID := os.Getenv("PASSKEY_RPID")
	if rpID == "" {
		// Not configured — caller skips passkey wiring.
		return nil, nil, nil
	}

	originsRaw := os.Getenv("PASSKEY_ORIGINS")
	if originsRaw == "" {
		return nil, nil, errors.New("passkey demo: PASSKEY_RPID set but PASSKEY_ORIGINS empty")
	}
	origins := strings.Fields(originsRaw)

	engine, err := passkey.New(&passkey.Config{
		RPID:             rpID,
		RPDisplayName:    "ADA Login Demo",
		RPOrigins:        origins,
		UserVerification: passkey.UVPreferred,
		ChallengeTTL:     5 * time.Minute,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("passkey demo: engine: %w", err)
	}

	name := os.Getenv("PASSKEY_NAME")
	if name == "" {
		name = "passkey"
	}
	label := os.Getenv("PASSKEY_LABEL")
	if label == "" {
		label = "Sign in with a passkey"
	}

	store := newDemoPasskeyStore()

	strategy, err := passkey.NewStrategy(name, engine,
		// CredentialLookup: the rawId from the assertion maps back to
		// one of the rows we stored at registration time, plus the
		// identity that should be issued on success.
		func(_ context.Context, credentialID []byte) (*passkey.Credential, *identity.Identity, error) {
			cred, id, ok := store.lookup(credentialID)
			if !ok {
				return nil, nil, passkey.ErrCredentialNotFound
			}
			return cred, id, nil
		},
		passkey.WithLabel(label),
		passkey.WithSignCountUpdater(func(_ context.Context, credentialID []byte, newCount uint32) error {
			store.updateSignCount(credentialID, newCount)
			return nil
		}),
		// Hybrid flow: when the SPA sends { username: "alice" } at
		// begin, return alice's credential ids so the authenticator
		// scopes the prompt to her passkeys only.
		passkey.WithUserCredentialsLookup(func(_ context.Context, hint passkey.UserHint) ([][]byte, error) {
			return store.credentialIDsForHint(hint), nil
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey demo: strategy: %w", err)
	}

	mountRegistration := func(mux *ada.Mux) {
		// Registration endpoints. ada doesn't mount these — the
		// relying party owns persistence and policy, so the demo
		// mounts them under /passkey/* itself. In a real app these
		// would sit behind authMW.Require() so only signed-in users
		// can enroll an additional credential; the demo accepts a
		// "username" form field instead to keep the flow standalone.
		//
		// We use mux.Wrap to bridge the ada.Context-style handler
		// (terse Bind / SendJSON helpers) onto the http.HandlerFunc
		// signature mux.POST expects.
		mux.POST("/passkey/register/begin", mux.Wrap(passkeyBeginHandler(engine, store)))
		mux.POST("/passkey/register/finish", mux.Wrap(passkeyFinishHandler(engine, store)))
	}

	return strategy, mountRegistration, nil
}

// passkeyBeginHandler returns the /passkey/register/begin handler.
// Splitting it out from PasskeyDemo keeps the latter's surface
// readable: the env-driven config wiring is one concern, the HTTP
// handlers are another.
func passkeyBeginHandler(engine *passkey.WebAuthn, store *demoPasskeyStore) func(c *ada.Context) error {
	return func(c *ada.Context) error {
		var req struct {
			Username string `json:"username"`
		}
		_ = c.Bind(&req)
		username := strings.TrimSpace(req.Username)
		if username == "" {
			return c.SetStatus(http.StatusBadRequest).SendJSON(map[string]string{
				"error":   "bad_request",
				"message": "username required",
			})
		}

		handle := store.userHandle(username)
		opts, session, err := engine.BeginRegistration(passkey.User{
			Handle:      handle,
			Name:        username,
			DisplayName: username,
		}, store.excludeFor(username))
		if err != nil {
			return c.SetStatus(http.StatusInternalServerError).SendJSON(map[string]string{
				"error":   "begin_failed",
				"message": err.Error(),
			})
		}

		sid := store.saveRegSession(username, session)
		return c.SetStatus(http.StatusOK).SendJSON(map[string]any{
			"session_id": sid,
			"options":    opts,
		})
	}
}

// passkeyFinishHandler returns the /passkey/register/finish handler.
func passkeyFinishHandler(engine *passkey.WebAuthn, store *demoPasskeyStore) func(c *ada.Context) error {
	return func(c *ada.Context) error {
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<17))
		if err != nil {
			return c.SetStatus(http.StatusBadRequest).SendJSON(map[string]string{
				"error":   "bad_request",
				"message": "read body",
			})
		}
		var req struct {
			SessionID string          `json:"session_id"`
			Response  json.RawMessage `json:"response"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return c.SetStatus(http.StatusBadRequest).SendJSON(map[string]string{
				"error":   "bad_request",
				"message": err.Error(),
			})
		}

		username, session, ok := store.takeRegSession(req.SessionID)
		if !ok {
			return c.SetStatus(http.StatusUnauthorized).SendJSON(map[string]string{
				"error":   "invalid_session",
				"message": "unknown session",
			})
		}

		cred, _, err := engine.FinishRegistration(session, req.Response)
		if err != nil {
			slog.Warn("passkey demo: finish registration", "error", err)
			return c.SetStatus(http.StatusUnauthorized).SendJSON(map[string]string{
				"error":   "finish_failed",
				"message": err.Error(),
			})
		}

		store.add(username, cred)
		return c.SetStatus(http.StatusCreated).SendJSON(map[string]any{
			"username":      username,
			"credential_id": hex.EncodeToString(cred.ID),
			"transports":    cred.Transports,
		})
	}
}

// demoPasskeyStore is a deliberately-minimal in-memory store. Real
// deployments persist these rows in a database — this implementation
// loses every enrollment on restart, which is fine for a demo but
// the wrong shape for anything else.
type demoPasskeyStore struct {
	mu sync.Mutex

	// credByID is the authoritative credential table, keyed by the
	// hex-encoded raw credential id. Two distinct creds can never
	// share an id, so we can use the slice contents as a map key
	// after hex-encoding.
	credByID map[string]*demoCredentialRow

	// userHandles caches the handle bytes for each known username
	// so registrations and lookups agree.
	userHandles map[string][]byte

	// regSessions holds enrollment ceremonies in flight, keyed by an
	// opaque session id we hand to the SPA on begin and consume
	// one-shot on finish.
	regSessions map[string]*demoRegEntry
}

type demoCredentialRow struct {
	Username string
	Cred     *passkey.Credential
}

type demoRegEntry struct {
	Username string
	Session  *passkey.SessionData
	Expires  time.Time
}

func newDemoPasskeyStore() *demoPasskeyStore {
	s := &demoPasskeyStore{
		credByID:    make(map[string]*demoCredentialRow),
		userHandles: make(map[string][]byte),
		regSessions: make(map[string]*demoRegEntry),
	}
	// Light-weight GC: drop expired registration sessions every
	// minute so a forgotten ceremony doesn't keep memory alive.
	go s.gc()
	return s
}

func (s *demoPasskeyStore) userHandle(username string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, ok := s.userHandles[username]; ok {
		return h
	}
	h := []byte(fmt.Sprintf("demo-handle-%s", username))
	s.userHandles[username] = h
	return h
}

func (s *demoPasskeyStore) excludeFor(username string) []passkey.PublicKeyCredentialDescriptor {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []passkey.PublicKeyCredentialDescriptor
	for _, row := range s.credByID {
		if row.Username == username {
			out = append(out, passkey.PublicKeyCredentialDescriptor{
				Type:       "public-key",
				ID:         passkey.Base64URLEncode(row.Cred.ID),
				Transports: row.Cred.Transports,
			})
		}
	}
	return out
}

func (s *demoPasskeyStore) saveRegSession(username string, session *passkey.SessionData) string {
	sid := newOpaqueID()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.regSessions[sid] = &demoRegEntry{
		Username: username,
		Session:  session,
		Expires:  time.Now().Add(5 * time.Minute),
	}
	return sid
}

func (s *demoPasskeyStore) takeRegSession(sid string) (string, *passkey.SessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.regSessions[sid]
	if !ok {
		return "", nil, false
	}
	delete(s.regSessions, sid)
	if time.Now().After(entry.Expires) {
		return "", nil, false
	}
	return entry.Username, entry.Session, true
}

func (s *demoPasskeyStore) add(username string, cred *passkey.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credByID[hex.EncodeToString(cred.ID)] = &demoCredentialRow{
		Username: username,
		Cred:     cred,
	}
}

func (s *demoPasskeyStore) lookup(credentialID []byte) (*passkey.Credential, *identity.Identity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.credByID[hex.EncodeToString(credentialID)]
	if !ok {
		return nil, nil, false
	}
	return row.Cred, &identity.Identity{
		Subject:  row.Username,
		Name:     row.Username,
		Provider: "passkey",
	}, true
}

func (s *demoPasskeyStore) updateSignCount(credentialID []byte, newCount uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if row, ok := s.credByID[hex.EncodeToString(credentialID)]; ok {
		row.Cred.SignCount = newCount
	}
}

// credentialIDsForHint resolves a SPA user hint to the credential ids
// the assertion ceremony will accept. Empty slice = "let the
// authenticator pick" (discoverable login). The hint can come in as
// either the WebAuthn user handle (cached by the SPA from an earlier
// session) or the typed username.
func (s *demoPasskeyStore) credentialIDsForHint(hint passkey.UserHint) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var username string
	switch {
	case len(hint.Handle) > 0:
		// Reverse-lookup: handle bytes → username. In a real app
		// you'd index this; the demo has at most a few users.
		for u, h := range s.userHandles {
			if string(h) == string(hint.Handle) {
				username = u
				break
			}
		}
	case hint.Username != "":
		username = hint.Username
	}
	if username == "" {
		return nil
	}
	var out [][]byte
	for _, row := range s.credByID {
		if row.Username == username {
			out = append(out, row.Cred.ID)
		}
	}
	return out
}

func (s *demoPasskeyStore) gc() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		s.mu.Lock()
		for id, entry := range s.regSessions {
			if now.After(entry.Expires) {
				delete(s.regSessions, id)
			}
		}
		s.mu.Unlock()
	}
}

// newOpaqueID returns a random opaque id. We could pull in
// crypto/rand here but the demo's collision surface is one user
// across a few seconds; time.Now().UnixNano() + a counter is plenty.
var (
	opaqueMu      sync.Mutex
	opaqueCounter uint64
)

func newOpaqueID() string {
	opaqueMu.Lock()
	opaqueCounter++
	n := opaqueCounter
	opaqueMu.Unlock()
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), n)
}

// wireDemoPasskey wires the passkey strategy and its registration
// endpoints onto the running example. Called from Run when
// PASSKEY_RPID is configured; otherwise the example boots without
// passkey support.
//
// This is split out from Run so login.go stays readable when the
// reader is studying the basic local/oauth wiring.
func wireDemoPasskey(_ context.Context, authMW *auth.Auth, mux *ada.Mux) {
	strategy, mount, err := PasskeyDemo()
	if err != nil {
		slog.Warn("passkey demo skipped", "error", err)
		return
	}
	if strategy == nil {
		slog.Info("passkey demo disabled (set PASSKEY_RPID + PASSKEY_ORIGINS to enable)")
		return
	}
	authMW.Strategy(strategy)
	mount(mux)
	slog.Info("passkey demo enabled",
		"name", strategy.Name(),
		"register_begin", "/passkey/register/begin",
		"register_finish", "/passkey/register/finish",
	)
}
