package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

// Strategy implements strategy.Authenticator for WebAuthn login.
//
// The strategy uses a single HTTP endpoint (the URL ada exposes at
// /login/pass/{name}) and dispatches between the "begin" and
// "finish" phases by inspecting the request body shape: a body with
// no assertion field is a begin request; a body carrying an
// assertion field is a finish request. This keeps the route count
// small and lets the existing rate-limit middleware (which matches
// on /login/pass/) cover the passkey path automatically.
//
// Registration is handled separately by HTTP endpoints the RP
// mounts itself; ada's auth mux only covers the login flow.
//
// Concurrency: safe for use across goroutines. The challenge store
// guards its own state.
type Strategy struct {
	name  string
	label string
	w     *WebAuthn

	// store keeps in-flight challenges. The default is an in-memory
	// store with TTL-based eviction; callers that need cluster-wide
	// sharing (multiple ada instances behind a load balancer) can
	// inject a shared backend by satisfying ChallengeStore.
	store ChallengeStore

	// lookup resolves a credential id to the stored credential and
	// the corresponding identity. Wraps the RP's persistent
	// credential storage.
	lookup CredentialLookup

	// userCreds, when set, lets the strategy translate an SPA-supplied
	// user hint (handle bytes or a typed username) into the list of
	// credential ids accepted by the assertion ceremony. Enables the
	// username-first flow without forcing every deployment through a
	// discoverable login. Optional: when unset the begin step always
	// produces an empty allowCredentials list and the authenticator
	// picks any resident credential.
	userCreds UserCredentialsLookup

	// updateSignCount persists the new sign counter after a
	// successful login. Best-effort: errors are logged, the login
	// still succeeds — losing one counter increment is preferable
	// to a flaky write blocking authentication.
	updateSignCount func(ctx context.Context, credentialID []byte, newCount uint32) error
}

// ChallengeStore persists in-flight WebAuthn ceremony state. The
// strategy keys entries by an opaque session id it generates per
// ceremony and hands to the client; the client echoes it back on
// finish.
//
// The implementation MUST enforce a TTL (cf. Config.ChallengeTTL) —
// otherwise expired challenges accumulate forever and become a DoS
// vector. The default in-memory store evicts on access plus on a
// background tick.
type ChallengeStore interface {
	Save(ctx context.Context, sessionID string, data *SessionData) error
	Load(ctx context.Context, sessionID string) (*SessionData, error)
	Delete(ctx context.Context, sessionID string) error
}

// CredentialLookup resolves a credential id (the rawId field from
// the assertion response) to the stored credential plus the
// identity that should be issued when verification succeeds.
//
// Returns ErrCredentialNotFound when no row matches. The strategy
// translates that into a generic "invalid credential" response so
// callers can't enumerate enrolled credentials.
type CredentialLookup func(ctx context.Context, credentialID []byte) (*Credential, *identity.Identity, error)

// UserCredentialsLookup resolves a user hint (handle bytes from the
// SPA, or a free-form username typed into a login form) to the list
// of credential ids the RP is willing to accept for that user. It is
// the bridge between a non-discoverable / "username-first" UI and
// the WebAuthn allowCredentials list.
//
// Returning a non-empty slice scopes the assertion ceremony: the
// authenticator will only offer those credentials and the platform
// UI displays the matching passkey directly instead of the chooser.
// Returning nil or an empty slice (with no error) means "fall back to
// discoverable" — the authenticator picks any resident credential and
// the rawId at finish time still binds to a specific user via
// CredentialLookup. This empty-as-fallback semantics is deliberate:
// it prevents user-enumeration timing leaks at the begin step.
//
// Returning an error logs at warn level and also falls back to
// discoverable; callers should reserve errors for genuine failures
// (DB outage, etc.), not "user doesn't exist".
type UserCredentialsLookup func(ctx context.Context, hint UserHint) ([][]byte, error)

// UserHint carries the SPA-provided pointer to a user. Exactly one
// of the fields is typically set, depending on which login flow the
// front-end runs:
//
//   - Handle is set when the SPA already knows the WebAuthn user
//     handle (e.g. after a previous discoverable login the SPA
//     cached it and now wants a step-up).
//   - Username is set when the user typed an identifier into a form
//     and the SPA hasn't (and shouldn't have) the handle yet.
//
// The RP-supplied lookup picks whichever field matches its own user
// model. The strategy does not interpret either field — it forwards
// them verbatim so the RP can map them through its own user table
// without leaking the mapping shape to the client.
type UserHint struct {
	Handle   []byte
	Username string
}

// ErrCredentialNotFound is the sentinel CredentialLookup returns
// when no row matches the supplied credential id. The strategy
// converts this into a 401 with a generic message.
var ErrCredentialNotFound = errors.New("passkey: credential not found")

// Option configures a Strategy.
type Option func(*Strategy)

// WithLabel sets the human-readable label shown in /auth/info.
// Defaults to the strategy name.
func WithLabel(label string) Option {
	return func(s *Strategy) { s.label = label }
}

// WithChallengeStore overrides the in-memory store. Use this in a
// clustered deployment where finish requests may land on a
// different instance than begin.
func WithChallengeStore(store ChallengeStore) Option {
	return func(s *Strategy) { s.store = store }
}

// WithSignCountUpdater installs a callback invoked after a
// successful login to persist the new sign counter. When unset,
// sign counts are not persisted — acceptable for platform
// authenticators (which always report 0) but defeats the
// replay-detection for hardware keys.
func WithSignCountUpdater(fn func(ctx context.Context, credentialID []byte, newCount uint32) error) Option {
	return func(s *Strategy) { s.updateSignCount = fn }
}

// WithUserCredentialsLookup installs a callback that maps a user
// hint (handle bytes or a username string) to the list of credential
// ids the assertion ceremony will accept. Use this to support the
// "username-first" login flow:
//
//  1. The user types an identifier into a form.
//  2. The SPA POSTs { username: "..." } to the begin endpoint.
//  3. The strategy invokes this callback and scopes
//     allowCredentials to the returned list.
//  4. The authenticator presents only the matching passkey.
//
// Without this option, an SPA that sends a username field gets the
// same behavior as one that sends nothing — the ceremony goes
// discoverable and any resident credential wins. Pure discoverable
// login is supported either way.
func WithUserCredentialsLookup(fn UserCredentialsLookup) Option {
	return func(s *Strategy) { s.userCreds = fn }
}

// NewStrategy wires a WebAuthn instance into a strategy.Authenticator.
// name is the URL key (/login/pass/<name>). lookup is mandatory:
// without it the strategy has no way to map an assertion to a user.
func NewStrategy(name string, w *WebAuthn, lookup CredentialLookup, opts ...Option) (*Strategy, error) {
	if name == "" {
		return nil, errors.New("passkey: strategy name required")
	}
	if w == nil {
		return nil, errors.New("passkey: WebAuthn instance required")
	}
	if lookup == nil {
		return nil, errors.New("passkey: credential lookup required")
	}
	s := &Strategy{
		name:   name,
		label:  name,
		w:      w,
		lookup: lookup,
		store:  newMemoryChallengeStore(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Name returns the strategy's URL key.
func (s *Strategy) Name() string { return s.name }

// Descriptor advertises the strategy to /auth/info. Kind "custom"
// signals to a client that it must run the WebAuthn ceremony itself
// rather than POST a form. The LoginURL is overwritten by the ada
// middleware to /login/pass/<name>; the SPA dispatches against that
// URL with its own JSON payloads.
func (s *Strategy) Descriptor() strategy.Descriptor {
	return strategy.Descriptor{
		Name:  s.name,
		Kind:  "passkey",
		Label: s.label,
	}
}

// loginPhase distinguishes a begin request from a finish request by
// inspecting the JSON body shape. We don't use HTTP query params
// because the LoginGuard rate-limiter reads the body to extract a
// per-user key and expects the body to be present.
type loginPhase int

const (
	phaseBegin  loginPhase = iota // empty body
	phaseFinish                   // body with assertion fields
)

// beginRequest is the optional payload sent by the SPA at the start
// of a ceremony. Both user_handle and username are hints used to
// scope the allowed credentials list when the RP wired a
// UserCredentialsLookup; when neither is set (or no lookup is
// configured) the ceremony falls back to discoverable login and
// the authenticator picks the credential.
//
// user_handle is the base64url-encoded WebAuthn user handle (the
// opaque bytes embedded in the credential at registration time) and
// is appropriate when the SPA already cached it from an earlier
// session. username is a free-form identifier the user typed into a
// form — the RP maps it to a handle inside its UserCredentialsLookup.
type beginRequest struct {
	SessionID  string `json:"session_id,omitempty"`
	UserHandle string `json:"user_handle,omitempty"` // base64url-encoded
	Username   string `json:"username,omitempty"`    // RP-defined identifier
}

// finishRequest carries the assertion plus the session id returned
// by the previous begin call.
type finishRequest struct {
	SessionID string                `json:"session_id"`
	Assertion AssertionResponseJSON `json:"assertion"`
}

// Login dispatches based on the request body.
//
// On a begin request we generate a challenge, store the session,
// and return the options object with a generated session id. The
// client then runs navigator.credentials.get and posts a finish
// request carrying both the session id and the assertion.
//
// We return OutcomePending on begin (the strategy already wrote
// the JSON response) and OutcomeContinue on finish success (ada
// then mints the session cookie). On error we write a 401 with a
// generic message and return OutcomeFailed.
func (s *Strategy) Login(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
		return nil, strategy.OutcomeFailed, nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<17)) // 128 KiB caps attestation+assertion bodies
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "read body")
		return nil, strategy.OutcomeFailed, nil
	}

	switch detectPhase(body) {
	case phaseBegin:
		return s.handleBegin(w, r, body)
	case phaseFinish:
		return s.handleFinish(w, r, body)
	}
	// Unreachable — detectPhase returns one of the two phases.
	writeJSONError(w, http.StatusBadRequest, "bad_request", "invalid request shape")
	return nil, strategy.OutcomeFailed, nil
}

// Logout is a no-op — the issuer handles session revocation and
// there's no provider-side state to clean up.
func (s *Strategy) Logout(_ context.Context, _ *identity.Identity) error { return nil }

func (s *Strategy) handleBegin(w http.ResponseWriter, r *http.Request, body []byte) (*identity.Identity, strategy.Outcome, error) {
	var req beginRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "bad_request", "parse begin")
			return nil, strategy.OutcomeFailed, nil
		}
	}

	// allowed is the WebAuthn allowCredentials list. Empty (the
	// default) means discoverable login: the authenticator picks any
	// resident credential and the rawId at finish time still binds
	// the assertion to a specific user via lookup(). When the RP
	// wired UserCredentialsLookup and the SPA supplied a hint, we
	// scope the ceremony to that user's enrolled credentials so the
	// platform UI presents only the matching passkey.
	var allowed [][]byte
	if s.userCreds != nil && (req.UserHandle != "" || req.Username != "") {
		var handle []byte
		if req.UserHandle != "" {
			h, err := decodeBase64URL(req.UserHandle)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "bad_request", "decode user_handle")
				return nil, strategy.OutcomeFailed, nil
			}
			handle = h
		}
		creds, err := s.userCreds(r.Context(), UserHint{Handle: handle, Username: req.Username})
		switch {
		case err != nil:
			// Genuine failure — log and fall back to discoverable.
			// We don't surface the error to the client because the
			// most common cause is "no such user" and we don't want
			// to expose that mapping (enumeration).
			slog.Warn("passkey: user creds lookup", "error", err)
		case len(creds) > 0:
			allowed = creds
		}
		// len(creds) == 0 with no error: user exists but has no
		// enrolled passkeys (or the RP wants to suppress the hint
		// silently). Either way we proceed with an empty allowList
		// so an attacker can't tell the two cases apart by timing.
	}

	opts, session, err := s.w.BeginLogin(allowed)
	if err != nil {
		slog.Error("passkey: begin login", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "begin_failed", "could not start ceremony")
		return nil, strategy.OutcomeFailed, nil
	}

	sid := encodeBase64URL(mustReadRandom(16))
	if err := s.store.Save(r.Context(), sid, session); err != nil {
		slog.Error("passkey: save session", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "begin_failed", "could not store session")
		return nil, strategy.OutcomeFailed, nil
	}

	resp := map[string]any{
		"phase":      "begin",
		"session_id": sid,
		"options":    opts,
	}
	writeJSON(w, http.StatusOK, resp)
	return nil, strategy.OutcomePending, nil
}

func (s *Strategy) handleFinish(w http.ResponseWriter, r *http.Request, body []byte) (*identity.Identity, strategy.Outcome, error) {
	var req finishRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "parse finish")
		return nil, strategy.OutcomeFailed, nil
	}
	if req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "session_id missing")
		return nil, strategy.OutcomeFailed, nil
	}

	session, err := s.store.Load(r.Context(), req.SessionID)
	if err != nil || session == nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid_session", "no such session")
		return nil, strategy.OutcomeFailed, nil
	}
	// One-shot: delete eagerly so a replay can't reuse it even if
	// the rest of verification fails. The challenge bytes are
	// already in `session`.
	_ = s.store.Delete(r.Context(), req.SessionID)

	rawID, err := decodeBase64URL(req.Assertion.RawID)
	if err != nil || len(rawID) == 0 {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "missing rawId")
		return nil, strategy.OutcomeFailed, nil
	}

	cred, id, err := s.lookup(r.Context(), rawID)
	if err != nil || cred == nil || id == nil {
		// Don't leak whether the credential is unknown vs. owned
		// by a disabled user etc. Always the same 401 to the client.
		writeJSONError(w, http.StatusUnauthorized, "invalid_credential", "passkey not recognized")
		return nil, strategy.OutcomeFailed, nil
	}

	assertionBody, err := json.Marshal(req.Assertion)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "remarshal failed")
		return nil, strategy.OutcomeFailed, nil
	}

	result, err := s.w.FinishLogin(session, cred, assertionBody)
	if err != nil {
		slog.Warn("passkey: finish login failed", "error", err)
		writeJSONError(w, http.StatusUnauthorized, "invalid_assertion", "passkey verification failed")
		return nil, strategy.OutcomeFailed, nil
	}

	if s.updateSignCount != nil && result.NewSignCount != cred.SignCount {
		if err := s.updateSignCount(r.Context(), cred.ID, result.NewSignCount); err != nil {
			// Don't fail the login on a write hiccup; log loudly so
			// operators can investigate.
			slog.Warn("passkey: persist sign count failed", "credential", encodeBase64URL(cred.ID), "error", err)
		}
	}

	id.Provider = s.name
	return id, strategy.OutcomeContinue, nil
}

// detectPhase classifies the request body. A body containing an
// "assertion" key is a finish request; anything else (including
// empty body, or just {session_id, user_handle}) is a begin.
//
// We use json.RawMessage probing rather than full decoding so we
// don't have to commit to a schema before we know the phase.
func detectPhase(body []byte) loginPhase {
	if len(body) == 0 {
		return phaseBegin
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		// Treat malformed body as begin so the handler returns a
		// uniform error path. Letting it through to phaseBegin then
		// failing inside Unmarshal there keeps error responses
		// consistent.
		return phaseBegin
	}
	if _, ok := probe["assertion"]; ok {
		return phaseFinish
	}
	return phaseBegin
}

// writeJSON / writeJSONError / mustReadRandom are tiny utilities the
// strategy uses to keep handler code uniform.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("passkey: write json", "error", err)
	}
}

func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

func mustReadRandom(n int) []byte {
	// We deliberately panic on RNG failure here because every
	// caller treats it as catastrophic — there's no graceful
	// recovery from "crypto/rand stopped working".
	b, err := newChallenge()
	if err != nil {
		panic(fmt.Errorf("passkey: rng failure: %w", err))
	}
	if n > len(b) {
		return b
	}
	return b[:n]
}

// In-memory ChallengeStore.

// memoryChallengeStore is the default ChallengeStore. It evicts
// entries on access (lazy) and on a background tick (5s) so a flood
// of begin-only callers can't exhaust memory. Tests can construct
// it directly when they need to inspect state.
type memoryChallengeStore struct {
	mu      sync.Mutex
	entries map[string]*SessionData
	stopCh  chan struct{}
}

func newMemoryChallengeStore() *memoryChallengeStore {
	s := &memoryChallengeStore{
		entries: make(map[string]*SessionData),
		stopCh:  make(chan struct{}),
	}
	go s.gc()
	return s
}

func (s *memoryChallengeStore) Save(_ context.Context, id string, d *SessionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[id] = d
	return nil
}

func (s *memoryChallengeStore) Load(_ context.Context, id string) (*SessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.entries[id]
	if !ok {
		return nil, errors.New("not found")
	}
	if d.expired(time.Now()) {
		delete(s.entries, id)
		return nil, errors.New("expired")
	}
	return d, nil
}

func (s *memoryChallengeStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, id)
	return nil
}

// gc runs in the background, periodically evicting expired entries
// so a forgotten ceremony doesn't keep memory alive forever. 5s is
// a balance between churn (we hold the mutex for the iteration) and
// promptness; entries are bounded above by ChallengeTTL anyway.
func (s *memoryChallengeStore) gc() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case now := <-t.C:
			s.mu.Lock()
			for id, d := range s.entries {
				if d.expired(now) {
					delete(s.entries, id)
				}
			}
			s.mu.Unlock()
		}
	}
}

// Close stops the GC goroutine. Optional — only required by
// long-running tests that want to avoid leaked goroutines.
func (s *memoryChallengeStore) Close() {
	close(s.stopCh)
}
