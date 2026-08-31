package passkey

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

// fakeAuthenticator simulates the WebAuthn data an authenticator
// would emit for a given keypair. It's a test-only utility: it
// builds the COSE_Key, authenticator data, and client data JSON
// from primitives we control so we can drive both ceremonies
// without a real browser/USB key.
//
// The shape mirrors what a "platform" authenticator (Windows
// Hello, Touch ID) actually sends: ES256 keypair, "none"
// attestation on registration, signature over authData‖clientHash
// on login.
type fakeAuthenticator struct {
	priv      *ecdsa.PrivateKey
	credID    []byte
	signCount uint32
	aaguid    [16]byte
}

func newFakeAuthenticator(t *testing.T) *fakeAuthenticator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatal(err)
	}
	return &fakeAuthenticator{priv: priv, credID: credID}
}

// coseKeyES256 returns the deterministic CBOR encoding of this
// authenticator's ES256 public key. Mirrors what an authenticator
// emits inside the attested credential data blob.
func (a *fakeAuthenticator) coseKeyES256(t *testing.T) []byte {
	t.Helper()
	xb := a.priv.X.FillBytes(make([]byte, 32))
	yb := a.priv.Y.FillBytes(make([]byte, 32))

	// CBOR map with 5 entries: {1:2, 3:-7, -1:1, -2:xb, -3:yb}
	out := []byte{0xa5}               // map(5)
	out = append(out, 0x01, 0x02)     // 1: 2 (kty=EC2)
	out = append(out, 0x03, 0x26)     // 3: -7 (alg=ES256)
	out = append(out, 0x20, 0x01)     // -1: 1 (crv=P-256)
	out = append(out, 0x21, 0x58, 32) // -2: bstr(32)
	out = append(out, xb...)
	out = append(out, 0x22, 0x58, 32) // -3: bstr(32)
	out = append(out, yb...)
	return out
}

// buildAuthData emits the authenticator data blob. flags is the
// raw flag byte; pass flagUserPresent|flagUserVerified for the
// usual case. credData is appended when the AT flag is set in
// flags (registration only).
func (a *fakeAuthenticator) buildAuthData(t *testing.T, rpID string, flags byte, includeCred bool) []byte {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte(rpID))
	buf := make([]byte, 0, 64)
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, flags)

	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], a.signCount)
	buf = append(buf, counter[:]...)

	if includeCred {
		buf = append(buf, a.aaguid[:]...)
		var credIDLen [2]byte
		binary.BigEndian.PutUint16(credIDLen[:], uint16(len(a.credID)))
		buf = append(buf, credIDLen[:]...)
		buf = append(buf, a.credID...)
		buf = append(buf, a.coseKeyES256(t)...)
	}
	return buf
}

// buildAttestationObject wraps authenticator data in the "none"
// attestation envelope. This is what platform authenticators emit.
func (a *fakeAuthenticator) buildAttestationObject(t *testing.T, rpID string) []byte {
	t.Helper()
	authData := a.buildAuthData(t, rpID, flagUserPresent|flagUserVerified|flagAttestedCredentialData, true)

	// CBOR map { fmt:"none", authData:bstr, attStmt:{} }
	out := []byte{0xa3}                                             // map(3)
	out = append(out, 0x63, 'f', 'm', 't')                          // text("fmt")
	out = append(out, 0x64, 'n', 'o', 'n', 'e')                     // text("none")
	out = append(out, 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a') // text("authData")
	out = append(out, encodeCBORBytes(authData)...)
	out = append(out, 0x67, 'a', 't', 't', 'S', 't', 'm', 't') // text("attStmt")
	out = append(out, 0xa0)                                    // empty map
	return out
}

// clientDataJSON emits a clientDataJSON blob for the given type
// (webauthn.create / webauthn.get), challenge and origin.
func clientDataJSON(t *testing.T, typ, challenge, origin string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"type":      typ,
		"challenge": challenge,
		"origin":    origin,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// signWith returns the ECDSA-SHA256 signature over message for the
// given key, in the DER form WebAuthn expects.
func signWith(t *testing.T, priv *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	h := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// newTestConfig returns a Config suitable for unit tests with a
// localhost-style RP.
func newTestConfig() *Config {
	return &Config{
		RPID:          "localhost",
		RPDisplayName: "Test RP",
		RPOrigins:     []string{"http://localhost"},
	}
}

func TestFullRoundTrip_RegistrationThenLogin(t *testing.T) {
	cfg := newTestConfig()
	wa, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	authn := newFakeAuthenticator(t)
	user := User{
		Handle:      []byte("user-handle-1234"),
		Name:        "alice",
		DisplayName: "Alice",
	}

	// === Registration ===
	opts, regSession, err := wa.BeginRegistration(user, nil)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if opts.Challenge == "" {
		t.Error("challenge empty")
	}

	cdj := clientDataJSON(t, clientDataTypeCreate, opts.Challenge, "http://localhost")
	attObj := authn.buildAttestationObject(t, cfg.RPID)

	regBody, err := json.Marshal(RegistrationResponseJSON{
		Type:  "public-key",
		ID:    encodeBase64URL(authn.credID),
		RawID: encodeBase64URL(authn.credID),
		Response: struct {
			ClientDataJSON    string   `json:"clientDataJSON"`
			AttestationObject string   `json:"attestationObject"`
			Transports        []string `json:"transports,omitempty"`
		}{
			ClientDataJSON:    encodeBase64URL(cdj),
			AttestationObject: encodeBase64URL(attObj),
			Transports:        []string{"internal"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	cred, attResult, err := wa.FinishRegistration(regSession, regBody)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	if attResult.AttestationType != "none" {
		t.Errorf("attestation type = %q, want 'none'", attResult.AttestationType)
	}
	if !equalBytes(cred.ID, authn.credID) {
		t.Error("credential id mismatch")
	}
	if !equalBytes(cred.UserHandle, user.Handle) {
		t.Error("user handle mismatch")
	}

	// === Login ===
	authn.signCount++ // simulate the authenticator incrementing on each use
	loginOpts, loginSession, err := wa.BeginLogin([][]byte{authn.credID})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	loginCDJ := clientDataJSON(t, clientDataTypeGet, loginOpts.Challenge, "http://localhost")
	loginAuthData := authn.buildAuthData(t, cfg.RPID, flagUserPresent|flagUserVerified, false)
	hash := sha256.Sum256(loginCDJ)
	sig := signWith(t, authn.priv, append(loginAuthData, hash[:]...))

	loginBody, err := json.Marshal(AssertionResponseJSON{
		Type:  "public-key",
		ID:    encodeBase64URL(authn.credID),
		RawID: encodeBase64URL(authn.credID),
		Response: struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AuthenticatorData string `json:"authenticatorData"`
			Signature         string `json:"signature"`
			UserHandle        string `json:"userHandle,omitempty"`
		}{
			ClientDataJSON:    encodeBase64URL(loginCDJ),
			AuthenticatorData: encodeBase64URL(loginAuthData),
			Signature:         encodeBase64URL(sig),
			UserHandle:        encodeBase64URL(user.Handle),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Inject the registered user handle into the credential so the
	// login flow can match it.
	cred.UserHandle = user.Handle

	result, err := wa.FinishLogin(loginSession, cred, loginBody)
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if result.NewSignCount != authn.signCount {
		t.Errorf("sign count = %d, want %d", result.NewSignCount, authn.signCount)
	}
	if !result.UserVerified {
		t.Error("UserVerified should be true (UV flag was set)")
	}
}

func TestLogin_rejectsChallengeReplay(t *testing.T) {
	cfg := newTestConfig()
	wa, _ := New(cfg)
	authn := newFakeAuthenticator(t)
	user := User{Handle: []byte("u1"), Name: "u1"}

	// Set up a credential first.
	cred := registerHelper(t, wa, authn, user, cfg.RPID, "http://localhost")
	cred.UserHandle = user.Handle

	_, sess, _ := wa.BeginLogin([][]byte{authn.credID})

	// Build login body using sess.Challenge.
	loginCDJ := clientDataJSON(t, clientDataTypeGet, encodeBase64URL(sess.Challenge), "http://localhost")
	authData := authn.buildAuthData(t, cfg.RPID, flagUserPresent|flagUserVerified, false)
	hash := sha256.Sum256(loginCDJ)
	sig := signWith(t, authn.priv, append(authData, hash[:]...))
	loginBody := assertionBody(t, authn.credID, loginCDJ, authData, sig, user.Handle)

	// First time succeeds.
	if _, err := wa.FinishLogin(sess, cred, loginBody); err != nil {
		t.Fatalf("first login: %v", err)
	}

	// A second FinishLogin with the SAME session and body must
	// succeed at the protocol layer (the strategy layer is what
	// makes sessions one-shot, see strategy.handleFinish). At the
	// raw ceremony layer the session is still valid, so we only
	// verify the timing-replay defense is the strategy's job —
	// the protocol per se can't tell.
	if _, err := wa.FinishLogin(sess, cred, loginBody); err != nil {
		t.Errorf("second login at protocol layer failed (this is the strategy's job): %v", err)
	}

	// But if we mutate the challenge in clientDataJSON, it must
	// fail.
	cdjBad := clientDataJSON(t, clientDataTypeGet, "AAAA", "http://localhost")
	hashBad := sha256.Sum256(cdjBad)
	sigBad := signWith(t, authn.priv, append(authData, hashBad[:]...))
	bad := assertionBody(t, authn.credID, cdjBad, authData, sigBad, user.Handle)
	if _, err := wa.FinishLogin(sess, cred, bad); err == nil {
		t.Error("expected challenge mismatch to fail")
	}
}

func TestLogin_rejectsForeignOrigin(t *testing.T) {
	cfg := newTestConfig()
	wa, _ := New(cfg)
	authn := newFakeAuthenticator(t)
	user := User{Handle: []byte("u1"), Name: "u1"}
	cred := registerHelper(t, wa, authn, user, cfg.RPID, "http://localhost")
	cred.UserHandle = user.Handle

	_, sess, _ := wa.BeginLogin([][]byte{authn.credID})
	// Build clientDataJSON with attacker-controlled origin.
	loginCDJ := clientDataJSON(t, clientDataTypeGet, encodeBase64URL(sess.Challenge), "https://evil.example")
	authData := authn.buildAuthData(t, cfg.RPID, flagUserPresent|flagUserVerified, false)
	hash := sha256.Sum256(loginCDJ)
	sig := signWith(t, authn.priv, append(authData, hash[:]...))
	body := assertionBody(t, authn.credID, loginCDJ, authData, sig, user.Handle)

	if _, err := wa.FinishLogin(sess, cred, body); err == nil {
		t.Error("expected origin mismatch to fail")
	}
}

func TestLogin_rejectsTamperedSignature(t *testing.T) {
	cfg := newTestConfig()
	wa, _ := New(cfg)
	authn := newFakeAuthenticator(t)
	user := User{Handle: []byte("u1"), Name: "u1"}
	cred := registerHelper(t, wa, authn, user, cfg.RPID, "http://localhost")
	cred.UserHandle = user.Handle

	_, sess, _ := wa.BeginLogin([][]byte{authn.credID})
	loginCDJ := clientDataJSON(t, clientDataTypeGet, encodeBase64URL(sess.Challenge), "http://localhost")
	authData := authn.buildAuthData(t, cfg.RPID, flagUserPresent|flagUserVerified, false)
	hash := sha256.Sum256(loginCDJ)
	sig := signWith(t, authn.priv, append(authData, hash[:]...))
	// Flip a byte in the signature.
	sig[len(sig)/2] ^= 0xff
	body := assertionBody(t, authn.credID, loginCDJ, authData, sig, user.Handle)

	if _, err := wa.FinishLogin(sess, cred, body); err == nil {
		t.Error("expected signature failure")
	}
}

func TestLogin_rejectsSignCountRegression(t *testing.T) {
	cfg := newTestConfig()
	wa, _ := New(cfg)
	authn := newFakeAuthenticator(t)
	user := User{Handle: []byte("u1"), Name: "u1"}
	cred := registerHelper(t, wa, authn, user, cfg.RPID, "http://localhost")
	cred.UserHandle = user.Handle
	cred.SignCount = 100 // pretend we previously saw 100

	_, sess, _ := wa.BeginLogin([][]byte{authn.credID})
	loginCDJ := clientDataJSON(t, clientDataTypeGet, encodeBase64URL(sess.Challenge), "http://localhost")
	// Authenticator presents counter=5 (below stored 100).
	authn.signCount = 5
	authData := authn.buildAuthData(t, cfg.RPID, flagUserPresent|flagUserVerified, false)
	hash := sha256.Sum256(loginCDJ)
	sig := signWith(t, authn.priv, append(authData, hash[:]...))
	body := assertionBody(t, authn.credID, loginCDJ, authData, sig, user.Handle)

	if _, err := wa.FinishLogin(sess, cred, body); err == nil {
		t.Error("expected sign-count regression to fail")
	}
}

func TestLogin_rejectsEqualNonzeroSignCount(t *testing.T) {
	cfg := newTestConfig()
	wa, _ := New(cfg)
	authn := newFakeAuthenticator(t)
	user := User{Handle: []byte("u1"), Name: "u1"}
	cred := registerHelper(t, wa, authn, user, cfg.RPID, "http://localhost")
	cred.UserHandle = user.Handle
	cred.SignCount = 7
	authn.signCount = 7

	_, session, _ := wa.BeginLogin([][]byte{authn.credID})
	clientData := clientDataJSON(t, clientDataTypeGet, encodeBase64URL(session.Challenge), "http://localhost")
	authData := authn.buildAuthData(t, cfg.RPID, flagUserPresent|flagUserVerified, false)
	hash := sha256.Sum256(clientData)
	signature := signWith(t, authn.priv, append(authData, hash[:]...))
	body := assertionBody(t, authn.credID, clientData, authData, signature, user.Handle)

	if _, err := wa.FinishLogin(session, cred, body); err == nil {
		t.Error("expected equal nonzero sign count to fail")
	}
}

func TestLogin_acceptsZeroSignCount(t *testing.T) {
	// Platform authenticators always report 0 — that's not a
	// regression, it's the documented behavior. Our verifier must
	// accept it.
	cfg := newTestConfig()
	wa, _ := New(cfg)
	authn := newFakeAuthenticator(t)
	user := User{Handle: []byte("u1"), Name: "u1"}
	cred := registerHelper(t, wa, authn, user, cfg.RPID, "http://localhost")
	cred.UserHandle = user.Handle
	cred.SignCount = 0 // never advanced

	_, sess, _ := wa.BeginLogin([][]byte{authn.credID})
	loginCDJ := clientDataJSON(t, clientDataTypeGet, encodeBase64URL(sess.Challenge), "http://localhost")
	authData := authn.buildAuthData(t, cfg.RPID, flagUserPresent|flagUserVerified, false)
	hash := sha256.Sum256(loginCDJ)
	sig := signWith(t, authn.priv, append(authData, hash[:]...))
	body := assertionBody(t, authn.credID, loginCDJ, authData, sig, user.Handle)

	if _, err := wa.FinishLogin(sess, cred, body); err != nil {
		t.Errorf("zero sign count rejected: %v", err)
	}
}

func TestRegistrationRejectsUnofferedAlgorithm(t *testing.T) {
	cfg := newTestConfig()
	cfg.Algorithms = []CredentialAlgorithm{{COSE: algEdDSA, Name: "EdDSA"}}
	wa, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	authn := newFakeAuthenticator(t)
	user := User{Handle: []byte("user"), Name: "user"}
	options, session, err := wa.BeginRegistration(user, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientData := clientDataJSON(t, clientDataTypeCreate, options.Challenge, "http://localhost")
	attestation := authn.buildAttestationObject(t, cfg.RPID)
	body, err := json.Marshal(RegistrationResponseJSON{
		Type:  "public-key",
		ID:    encodeBase64URL(authn.credID),
		RawID: encodeBase64URL(authn.credID),
		Response: struct {
			ClientDataJSON    string   `json:"clientDataJSON"`
			AttestationObject string   `json:"attestationObject"`
			Transports        []string `json:"transports,omitempty"`
		}{
			ClientDataJSON:    encodeBase64URL(clientData),
			AttestationObject: encodeBase64URL(attestation),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wa.FinishRegistration(session, body); err == nil {
		t.Fatal("FinishRegistration accepted an unoffered ES256 credential")
	}
}

func TestStrategyConcurrentSignCountUpdatesRemainMonotonic(t *testing.T) {
	cfg := newTestConfig()
	wa, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	authn := newFakeAuthenticator(t)
	user := User{Handle: []byte("user"), Name: "user"}
	registered := registerHelper(t, wa, authn, user, cfg.RPID, "http://localhost")
	registered.UserHandle = cloneBytes(user.Handle)

	var storeMu sync.Mutex
	stored := *registered
	lookup := func(_ context.Context, credentialID []byte) (*Credential, *identity.Identity, error) {
		storeMu.Lock()
		defer storeMu.Unlock()
		if !constantTimeBytesEqual(credentialID, stored.ID) {
			return nil, nil, ErrCredentialNotFound
		}
		credential := stored
		credential.ID = cloneBytes(stored.ID)
		credential.UserHandle = cloneBytes(stored.UserHandle)
		credential.PublicKey = cloneBytes(stored.PublicKey)
		return &credential, &identity.Identity{Subject: "user"}, nil
	}

	const assertions = 16
	strategy, err := NewStrategy("passkey", wa, lookup, WithSignCountUpdater(
		func(_ context.Context, _ []byte, newCount uint32) error {
			// Without per-credential serialization, delayed lower writes can
			// overwrite a newer counter after concurrent stale lookups.
			time.Sleep(time.Duration(assertions-int(newCount)) * time.Millisecond)
			storeMu.Lock()
			stored.SignCount = newCount
			storeMu.Unlock()
			return nil
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = strategy.Close() })

	bodies := make([][]byte, assertions)
	for i := range assertions {
		count := uint32(i + 1)
		_, session, err := strategy.w.BeginLogin([][]byte{authn.credID})
		if err != nil {
			t.Fatal(err)
		}
		sessionID := fmt.Sprintf("session-%d", count)
		if err := strategy.store.Save(context.Background(), sessionID, session); err != nil {
			t.Fatal(err)
		}

		authn.signCount = count
		clientData := clientDataJSON(t, clientDataTypeGet, encodeBase64URL(session.Challenge), "http://localhost")
		authData := authn.buildAuthData(t, cfg.RPID, flagUserPresent|flagUserVerified, false)
		hash := sha256.Sum256(clientData)
		signature := signWith(t, authn.priv, append(authData, hash[:]...))
		assertionJSON := assertionBody(t, authn.credID, clientData, authData, signature, user.Handle)
		var assertion AssertionResponseJSON
		if err := json.Unmarshal(assertionJSON, &assertion); err != nil {
			t.Fatal(err)
		}
		bodies[i], err = json.Marshal(finishRequest{SessionID: sessionID, Assertion: assertion})
		if err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, body := range bodies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
			_, _, _ = strategy.Login(httptest.NewRecorder(), request)
		}()
	}
	close(start)
	wg.Wait()

	storeMu.Lock()
	finalCount := stored.SignCount
	storeMu.Unlock()
	if finalCount != assertions {
		t.Fatalf("final sign count = %d, want %d", finalCount, assertions)
	}
}

// helper: full registration flow returning the stored credential.
func registerHelper(t *testing.T, wa *WebAuthn, authn *fakeAuthenticator, user User, rpID, origin string) *Credential {
	t.Helper()
	opts, sess, _ := wa.BeginRegistration(user, nil)
	cdj := clientDataJSON(t, clientDataTypeCreate, opts.Challenge, origin)
	attObj := authn.buildAttestationObject(t, rpID)
	body, _ := json.Marshal(RegistrationResponseJSON{
		Type:  "public-key",
		ID:    encodeBase64URL(authn.credID),
		RawID: encodeBase64URL(authn.credID),
		Response: struct {
			ClientDataJSON    string   `json:"clientDataJSON"`
			AttestationObject string   `json:"attestationObject"`
			Transports        []string `json:"transports,omitempty"`
		}{
			ClientDataJSON:    encodeBase64URL(cdj),
			AttestationObject: encodeBase64URL(attObj),
		},
	})
	cred, _, err := wa.FinishRegistration(sess, body)
	if err != nil {
		t.Fatalf("registerHelper: %v", err)
	}
	return cred
}

func assertionBody(t *testing.T, credID, cdj, authData, sig, userHandle []byte) []byte {
	t.Helper()
	b, _ := json.Marshal(AssertionResponseJSON{
		Type:  "public-key",
		ID:    encodeBase64URL(credID),
		RawID: encodeBase64URL(credID),
		Response: struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AuthenticatorData string `json:"authenticatorData"`
			Signature         string `json:"signature"`
			UserHandle        string `json:"userHandle,omitempty"`
		}{
			ClientDataJSON:    encodeBase64URL(cdj),
			AuthenticatorData: encodeBase64URL(authData),
			Signature:         encodeBase64URL(sig),
			UserHandle:        encodeBase64URL(userHandle),
		},
	})
	return b
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- Ed25519 (OKP) test coverage -------------------------------------------
//
// Ed25519 was added later than ES256, so the helpers below intentionally
// mirror fakeAuthenticator's shape — copy-paste rather than parametric
// because the COSE_Key, signing, and verification details differ enough
// that a single type would be more obfuscating than helpful.

// fakeEd25519Authenticator drives the ceremonies with an Ed25519 keypair
// (COSE alg=-8). Used to verify the OKP code path end-to-end.
type fakeEd25519Authenticator struct {
	priv      ed25519.PrivateKey
	pub       ed25519.PublicKey
	credID    []byte
	signCount uint32
	aaguid    [16]byte
}

func newFakeEd25519Authenticator(t *testing.T) *fakeEd25519Authenticator {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatal(err)
	}
	return &fakeEd25519Authenticator{priv: priv, pub: pub, credID: credID}
}

// coseKeyOKP emits the COSE_Key for this authenticator's Ed25519
// public key. RFC 9053 §13.2: kty=1 (OKP), alg=-8 (EdDSA), crv=6
// (Ed25519), x=32-byte public key. No y label.
func (a *fakeEd25519Authenticator) coseKeyOKP(t *testing.T) []byte {
	t.Helper()
	// CBOR map with 4 entries: {1:1, 3:-8, -1:6, -2:bstr(32)}
	out := []byte{0xa4}               // map(4)
	out = append(out, 0x01, 0x01)     // 1: 1 (kty=OKP)
	out = append(out, 0x03, 0x27)     // 3: -8 (alg=EdDSA, CBOR neg int = 0x20|7)
	out = append(out, 0x20, 0x06)     // -1: 6 (crv=Ed25519)
	out = append(out, 0x21, 0x58, 32) // -2: bstr(32)
	out = append(out, a.pub...)
	return out
}

func (a *fakeEd25519Authenticator) buildAuthData(t *testing.T, rpID string, flags byte, includeCred bool) []byte {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte(rpID))
	buf := make([]byte, 0, 64)
	buf = append(buf, rpIDHash[:]...)
	buf = append(buf, flags)

	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], a.signCount)
	buf = append(buf, counter[:]...)

	if includeCred {
		buf = append(buf, a.aaguid[:]...)
		var credIDLen [2]byte
		binary.BigEndian.PutUint16(credIDLen[:], uint16(len(a.credID)))
		buf = append(buf, credIDLen[:]...)
		buf = append(buf, a.credID...)
		buf = append(buf, a.coseKeyOKP(t)...)
	}
	return buf
}

func (a *fakeEd25519Authenticator) buildAttestationObject(t *testing.T, rpID string) []byte {
	t.Helper()
	authData := a.buildAuthData(t, rpID, flagUserPresent|flagUserVerified|flagAttestedCredentialData, true)
	// CBOR map { fmt:"none", authData:bstr, attStmt:{} }
	out := []byte{0xa3}
	out = append(out, 0x63, 'f', 'm', 't')
	out = append(out, 0x64, 'n', 'o', 'n', 'e')
	out = append(out, 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a')
	out = append(out, encodeCBORBytes(authData)...)
	out = append(out, 0x67, 'a', 't', 't', 'S', 't', 'm', 't')
	out = append(out, 0xa0)
	return out
}

// TestFullRoundTrip_Ed25519 exercises the OKP code path end-to-end:
// COSE parsing, attestation, signature verification. If any of those
// regress for Ed25519, this test fails at the same boundary the real
// world would.
func TestFullRoundTrip_Ed25519(t *testing.T) {
	cfg := newTestConfig()
	// Make EdDSA the only allowed algorithm so registration fails
	// fast if the offer list breaks. Other tests cover the default
	// (ES256-led) ordering.
	cfg.Algorithms = []CredentialAlgorithm{{COSE: algEdDSA, Name: "EdDSA"}}
	wa, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	authn := newFakeEd25519Authenticator(t)
	user := User{Handle: []byte("user-handle-ed"), Name: "alice-ed", DisplayName: "Alice"}

	// Registration.
	opts, regSession, err := wa.BeginRegistration(user, nil)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if len(opts.PubKeyCredParams) != 1 || opts.PubKeyCredParams[0].Alg != algEdDSA {
		t.Errorf("expected single EdDSA cred param, got %+v", opts.PubKeyCredParams)
	}

	cdj := clientDataJSON(t, clientDataTypeCreate, opts.Challenge, "http://localhost")
	attObj := authn.buildAttestationObject(t, cfg.RPID)
	regBody, _ := json.Marshal(RegistrationResponseJSON{
		Type:  "public-key",
		ID:    encodeBase64URL(authn.credID),
		RawID: encodeBase64URL(authn.credID),
		Response: struct {
			ClientDataJSON    string   `json:"clientDataJSON"`
			AttestationObject string   `json:"attestationObject"`
			Transports        []string `json:"transports,omitempty"`
		}{
			ClientDataJSON:    encodeBase64URL(cdj),
			AttestationObject: encodeBase64URL(attObj),
			Transports:        []string{"internal"},
		},
	})

	cred, _, err := wa.FinishRegistration(regSession, regBody)
	if err != nil {
		t.Fatalf("FinishRegistration (Ed25519): %v", err)
	}
	if !equalBytes(cred.ID, authn.credID) {
		t.Error("credential id mismatch")
	}

	// Login. PureEdDSA signs the raw authData‖clientDataHash blob
	// (no separate hash step at sign time — ed25519.Sign does it
	// internally).
	authn.signCount++
	cred.UserHandle = user.Handle
	loginOpts, loginSession, err := wa.BeginLogin([][]byte{authn.credID})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	loginCDJ := clientDataJSON(t, clientDataTypeGet, loginOpts.Challenge, "http://localhost")
	loginAuthData := authn.buildAuthData(t, cfg.RPID, flagUserPresent|flagUserVerified, false)
	hash := sha256.Sum256(loginCDJ)
	signed := append(loginAuthData[:len(loginAuthData):len(loginAuthData)], hash[:]...)
	sig := ed25519.Sign(authn.priv, signed)

	loginBody := assertionBody(t, authn.credID, loginCDJ, loginAuthData, sig, user.Handle)
	result, err := wa.FinishLogin(loginSession, cred, loginBody)
	if err != nil {
		t.Fatalf("FinishLogin (Ed25519): %v", err)
	}
	if result.NewSignCount != authn.signCount {
		t.Errorf("sign count = %d, want %d", result.NewSignCount, authn.signCount)
	}
}

// TestEd25519_rejectsTamperedSignature ensures we don't accept a
// flipped-bit signature on the OKP path. ed25519.Verify is supposed
// to fail closed; this test is the canary if the dispatch in
// verifySignature ever wires the wrong key type to the wrong verifier.
func TestEd25519_rejectsTamperedSignature(t *testing.T) {
	cfg := newTestConfig()
	cfg.Algorithms = []CredentialAlgorithm{{COSE: algEdDSA, Name: "EdDSA"}}
	wa, _ := New(cfg)
	authn := newFakeEd25519Authenticator(t)
	user := User{Handle: []byte("u-ed"), Name: "u-ed"}

	// Mini registration.
	opts, sess, _ := wa.BeginRegistration(user, nil)
	cdj := clientDataJSON(t, clientDataTypeCreate, opts.Challenge, "http://localhost")
	attObj := authn.buildAttestationObject(t, cfg.RPID)
	body, _ := json.Marshal(RegistrationResponseJSON{
		Type:  "public-key",
		ID:    encodeBase64URL(authn.credID),
		RawID: encodeBase64URL(authn.credID),
		Response: struct {
			ClientDataJSON    string   `json:"clientDataJSON"`
			AttestationObject string   `json:"attestationObject"`
			Transports        []string `json:"transports,omitempty"`
		}{
			ClientDataJSON:    encodeBase64URL(cdj),
			AttestationObject: encodeBase64URL(attObj),
		},
	})
	cred, _, err := wa.FinishRegistration(sess, body)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	cred.UserHandle = user.Handle

	// Build a tampered login.
	_, loginSess, _ := wa.BeginLogin([][]byte{authn.credID})
	loginCDJ := clientDataJSON(t, clientDataTypeGet, encodeBase64URL(loginSess.Challenge), "http://localhost")
	authData := authn.buildAuthData(t, cfg.RPID, flagUserPresent|flagUserVerified, false)
	hash := sha256.Sum256(loginCDJ)
	signed := append(authData[:len(authData):len(authData)], hash[:]...)
	sig := ed25519.Sign(authn.priv, signed)
	sig[5] ^= 0x80 // flip one bit
	bad := assertionBody(t, authn.credID, loginCDJ, authData, sig, user.Handle)

	if _, err := wa.FinishLogin(loginSess, cred, bad); err == nil {
		t.Error("expected tampered Ed25519 signature to fail")
	}
}
