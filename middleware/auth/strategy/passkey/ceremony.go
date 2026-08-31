package passkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// WebAuthn is the top-level entry point for relying-party ceremonies.
// Instantiate once at boot via New and call Begin*/Finish* methods.
// Concurrent use is safe — the type holds no mutable state.
type WebAuthn struct {
	cfg *Config
}

// New constructs a WebAuthn from a validated config. Returns an
// error if the config is missing required fields; in that case the
// caller should fail fast at boot rather than serving requests with
// a broken authenticator.
func New(cfg *Config) (*WebAuthn, error) {
	cloned, err := cloneConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &WebAuthn{cfg: cloned}, nil
}

// CredentialCreationOptions is the JSON shape passed back to the
// browser. The struct mirrors the W3C PublicKeyCredentialCreationOptions
// dictionary but uses `Base64URL` strings everywhere a `BufferSource`
// is required in the WebIDL — this matches how every browser-side
// passkey library round-trips the values today and removes the need
// for a separate ArrayBuffer ↔ string conversion in the SPA.
//
// Field names are lowerCamelCase via json tags to keep the JSON
// shape WebAuthn-conformant; the Go fields use the package's
// upper-case convention.
type CredentialCreationOptions struct {
	Challenge              string                          `json:"challenge"`
	RP                     RelyingParty                    `json:"rp"`
	User                   PublicUser                      `json:"user"`
	PubKeyCredParams       []PubKeyCredentialParameter     `json:"pubKeyCredParams"`
	Timeout                int                             `json:"timeout,omitempty"`
	ExcludeCredentials     []PublicKeyCredentialDescriptor `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection AuthenticatorSelection          `json:"authenticatorSelection,omitempty"`
	Attestation            string                          `json:"attestation,omitempty"`
}

type RelyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type PublicUser struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type PubKeyCredentialParameter struct {
	Type string `json:"type"` // always "public-key"
	Alg  int    `json:"alg"`  // COSE alg identifier
}

type PublicKeyCredentialDescriptor struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

type AuthenticatorSelection struct {
	// AuthenticatorAttachment lets the RP express a preference for
	// either a platform authenticator ("platform" — Touch ID, Windows
	// Hello, Android keystore) or a roaming one ("cross-platform" —
	// USB/NFC/BLE security key). Empty means "no preference"; the
	// browser shows the user a chooser. Most deployments leave this
	// empty and let the user pick — set it only when policy requires
	// a specific class of device.
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	UserVerification        string `json:"userVerification,omitempty"`
	RequireResidentKey      bool   `json:"requireResidentKey,omitempty"`
	ResidentKey             string `json:"residentKey,omitempty"`
}

// RegistrationOption tunes a single BeginRegistration call without
// touching the package-wide Config. The option pattern keeps the
// happy-path signature short while leaving room for rarely-used
// knobs.
type RegistrationOption func(*registrationOptions)

// registrationOptions is the internal accumulator the variadic
// options write into.
type registrationOptions struct {
	authenticatorAttachment string
}

// WithAuthenticatorAttachment scopes the ceremony to a class of
// authenticator. Accepted values are "platform" (built-in: Touch ID,
// Windows Hello, Android keystore) and "cross-platform" (roaming:
// USB/NFC/BLE security keys). Empty lets the browser offer both; any
// other value causes BeginRegistration to reject the ceremony.
//
// Use case is rare: a corporate policy that mandates security keys,
// or an account-recovery flow that explicitly wants a phone-bound
// credential. Most deployments should leave the attachment empty.
func WithAuthenticatorAttachment(attachment string) RegistrationOption {
	return func(o *registrationOptions) { o.authenticatorAttachment = attachment }
}

// BeginRegistration creates a registration challenge for the given
// user. exclude lists credentials the user already has so the
// authenticator can refuse a duplicate enrollment (or the browser
// can prompt for a different security key). The returned options
// blob is meant to be JSON-encoded and shipped to the SPA;
// SessionData must be stored by the caller and supplied to
// FinishRegistration.
//
// We always request residentKey=preferred so the credential ends up
// discoverable (i.e. usable for passwordless login) on authenticators
// that support it. Hardware keys with no resident-key support
// gracefully fall back to non-resident — the credential still works
// for username-first login flows.
//
// Pass RegistrationOption values to tweak the ceremony — currently
// only WithAuthenticatorAttachment, but the variadic shape leaves
// room to grow without breaking callers.
func (w *WebAuthn) BeginRegistration(user User, exclude []PublicKeyCredentialDescriptor, opts ...RegistrationOption) (*CredentialCreationOptions, *SessionData, error) {
	if len(user.Handle) == 0 {
		return nil, nil, errors.New("passkey: user handle required")
	}
	if len(user.Handle) > 64 {
		return nil, nil, errors.New("passkey: user handle must be ≤64 bytes (WebAuthn §5.4.3)")
	}

	var ro registrationOptions
	for _, opt := range opts {
		opt(&ro)
	}
	attachment, err := validateAuthenticatorAttachment(ro.authenticatorAttachment)
	if err != nil {
		return nil, nil, err
	}

	chal, err := newChallenge()
	if err != nil {
		return nil, nil, err
	}

	params := make([]PubKeyCredentialParameter, 0, len(w.cfg.Algorithms))
	for _, a := range w.cfg.Algorithms {
		params = append(params, PubKeyCredentialParameter{Type: "public-key", Alg: a.COSE})
	}

	excluded := cloneCredentialDescriptors(exclude)
	options := &CredentialCreationOptions{
		Challenge: encodeBase64URL(chal),
		RP: RelyingParty{
			ID:   w.cfg.RPID,
			Name: w.cfg.RPDisplayName,
		},
		User: PublicUser{
			ID:          encodeBase64URL(user.Handle),
			Name:        user.Name,
			DisplayName: user.DisplayName,
		},
		PubKeyCredParams:   params,
		Timeout:            int(w.cfg.ChallengeTTL.Milliseconds()),
		ExcludeCredentials: excluded,
		AuthenticatorSelection: AuthenticatorSelection{
			AuthenticatorAttachment: attachment,
			UserVerification:        string(w.cfg.UserVerification),
			ResidentKey:             "preferred",
			RequireResidentKey:      false,
		},
		// "none" is the default attestation conveyance and matches
		// what platform authenticators emit. Asking for "direct"
		// would force the authenticator to emit a signed attStmt,
		// which most platform authenticators decline to do (they
		// fall back to "none" anyway).
		Attestation: "none",
	}

	session := &SessionData{
		Challenge:        chal,
		UserHandle:       cloneBytes(user.Handle),
		UserVerification: w.cfg.UserVerification,
		Expires:          time.Now().Add(w.cfg.ChallengeTTL),
	}

	return options, session, nil
}

func validateAuthenticatorAttachment(s string) (string, error) {
	switch s {
	case "", "platform", "cross-platform":
		return s, nil
	default:
		return "", fmt.Errorf("passkey: invalid authenticator attachment %q", s)
	}
}

func cloneCredentialDescriptors(descriptors []PublicKeyCredentialDescriptor) []PublicKeyCredentialDescriptor {
	if descriptors == nil {
		return nil
	}
	cloned := make([]PublicKeyCredentialDescriptor, len(descriptors))
	copy(cloned, descriptors)
	for i := range cloned {
		cloned[i].Transports = append([]string(nil), descriptors[i].Transports...)
	}
	return cloned
}

// RegistrationResponseJSON is the shape the browser POSTs back to
// the RP. Mirrors AuthenticatorAttestationResponse (WebAuthn §5.2.1),
// flattened so the JSON wire format matches what
// PublicKeyCredential.toJSON() emits in current browsers.
type RegistrationResponseJSON struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string   `json:"clientDataJSON"`
		AttestationObject string   `json:"attestationObject"`
		Transports        []string `json:"transports,omitempty"`
	} `json:"response"`
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
}

// FinishRegistration validates the browser's response against the
// previously-issued SessionData and produces a Credential to persist.
//
// The returned Credential carries everything the RP needs to verify
// a future login: the credential id (lookup key), the COSE public
// key, the AAGUID, transports, sign counter, and the attestation
// trust summary. The caller stores this row keyed by the credential
// id (for assertion lookup) and indexed by user handle (for the
// security page listing).
func (w *WebAuthn) FinishRegistration(session *SessionData, body []byte) (*Credential, *AttestationResult, error) {
	if session == nil {
		return nil, nil, errors.New("passkey: missing session data")
	}
	if session.expired(time.Now()) {
		return nil, nil, errors.New("passkey: registration session expired")
	}
	if err := w.validateSessionPolicy(session); err != nil {
		return nil, nil, err
	}

	var resp RegistrationResponseJSON
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, fmt.Errorf("passkey: parse response: %w", err)
	}
	if resp.Type != "public-key" {
		return nil, nil, fmt.Errorf("passkey: response type %q is not public-key", resp.Type)
	}

	clientDataJSON, err := decodeBase64URL(resp.Response.ClientDataJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: decode clientDataJSON: %w", err)
	}
	attBlob, err := decodeBase64URL(resp.Response.AttestationObject)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: decode attestationObject: %w", err)
	}

	hash, err := verifyClientData(clientDataJSON, clientDataTypeCreate, session.Challenge, w.cfg.RPOrigins)
	if err != nil {
		return nil, nil, err
	}

	att, err := parseAttestationObject(attBlob)
	if err != nil {
		return nil, nil, err
	}

	ad, result, err := verifyAttestation(att, hash)
	if err != nil {
		return nil, nil, err
	}

	if err := verifyRPIDHash(ad, w.cfg.RPID); err != nil {
		return nil, nil, err
	}

	if ad.Flags&flagUserPresent == 0 {
		return nil, nil, errors.New("passkey: user-present flag not set")
	}
	if w.cfg.UserVerification == UVRequired && ad.Flags&flagUserVerified == 0 {
		return nil, nil, errors.New("passkey: user-verified flag required but not set")
	}

	// Parse the COSE_Key once to sanity-check the format before we
	// persist it. The raw bytes are what we store (so future
	// algorithm additions can re-parse without a schema change).
	publicKey, err := parseCOSEPublicKey(ad.AttestedCredential.PublicKeyCBOR)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: credential public key: %w", err)
	}
	if !w.algorithmAllowed(publicKey.Algorithm) {
		return nil, nil, fmt.Errorf("passkey: credential algorithm %d was not offered", publicKey.Algorithm)
	}

	cred := &Credential{
		ID:              ad.AttestedCredential.CredentialID,
		UserHandle:      cloneBytes(session.UserHandle),
		PublicKey:       ad.AttestedCredential.PublicKeyCBOR,
		AAGUID:          ad.AttestedCredential.AAGUID[:],
		SignCount:       ad.SignCount,
		Transports:      resp.Response.Transports,
		AttestationType: result.AttestationType,
		BackupEligible:  ad.Flags&flagBackupEligible != 0,
		BackupState:     ad.Flags&flagBackupState != 0,
		UserVerified:    ad.Flags&flagUserVerified != 0,
	}

	return cred, result, nil
}

// CredentialRequestOptions is the JSON shape the SPA hands to
// navigator.credentials.get() for a login ceremony.
type CredentialRequestOptions struct {
	Challenge        string                          `json:"challenge"`
	Timeout          int                             `json:"timeout,omitempty"`
	RPID             string                          `json:"rpId"`
	AllowCredentials []PublicKeyCredentialDescriptor `json:"allowCredentials,omitempty"`
	UserVerification string                          `json:"userVerification,omitempty"`
}

// BeginLogin starts an assertion ceremony.
//
// allowedCredentials lists the credential ids the RP is willing to
// accept. Pass nil/empty for a "discoverable" (passwordless) login
// where the authenticator picks the credential — the user handle
// returned in the response then identifies the user. Pass a
// per-user slice when the RP already knows who is signing in (e.g.
// step-up flow after a username prompt).
func (w *WebAuthn) BeginLogin(allowedCredentials [][]byte) (*CredentialRequestOptions, *SessionData, error) {
	chal, err := newChallenge()
	if err != nil {
		return nil, nil, err
	}

	allowed := cloneByteSlices(allowedCredentials)
	allow := make([]PublicKeyCredentialDescriptor, 0, len(allowed))
	for _, id := range allowed {
		allow = append(allow, PublicKeyCredentialDescriptor{
			Type: "public-key",
			ID:   encodeBase64URL(id),
		})
	}

	opts := &CredentialRequestOptions{
		Challenge:        encodeBase64URL(chal),
		Timeout:          int(w.cfg.ChallengeTTL.Milliseconds()),
		RPID:             w.cfg.RPID,
		AllowCredentials: allow,
		UserVerification: string(w.cfg.UserVerification),
	}

	session := &SessionData{
		Challenge:            chal,
		UserVerification:     w.cfg.UserVerification,
		Expires:              time.Now().Add(w.cfg.ChallengeTTL),
		AllowedCredentialIDs: allowed,
	}

	return opts, session, nil
}

// AssertionResponseJSON is the browser's response to a login
// ceremony. UserHandle is set when the authenticator was used in
// discoverable mode (i.e. the user picked the account inside the
// platform passkey UI).
type AssertionResponseJSON struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle,omitempty"`
	} `json:"response"`
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
}

// LoginResult bundles everything FinishLogin learned about the
// assertion. NewSignCount is the value the caller MUST persist back
// onto the credential row — without it, a future replay-detection
// check will accept stale assertions.
//
// UserHandle is non-nil in discoverable-login flows; non-discoverable
// flows leave it nil (the RP already knew who was signing in).
type LoginResult struct {
	Credential   *Credential
	NewSignCount uint32
	UserHandle   []byte
	UserVerified bool
}

// FinishLogin verifies an assertion against a stored credential.
// The caller is expected to look up the credential by ID (the
// assertion carries it in the rawId field) and pass it in here.
//
// Important: this method does NOT mutate the passed-in Credential.
// The caller must read result.NewSignCount and write it back to
// storage on success.
func (w *WebAuthn) FinishLogin(session *SessionData, cred *Credential, body []byte) (*LoginResult, error) {
	if session == nil {
		return nil, errors.New("passkey: missing session data")
	}
	if session.expired(time.Now()) {
		return nil, errors.New("passkey: login session expired")
	}
	if err := w.validateSessionPolicy(session); err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, errors.New("passkey: credential required")
	}

	var resp AssertionResponseJSON
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("passkey: parse response: %w", err)
	}
	if resp.Type != "public-key" {
		return nil, fmt.Errorf("passkey: response type %q is not public-key", resp.Type)
	}

	rawID, err := decodeBase64URL(resp.RawID)
	if err != nil {
		return nil, fmt.Errorf("passkey: decode rawId: %w", err)
	}
	if !constantTimeBytesEqual(rawID, cred.ID) {
		return nil, errors.New("passkey: rawId does not match supplied credential")
	}

	// Allowed-list check: if the ceremony was scoped to a specific
	// set of credentials, the rawId MUST be one of them. Empty list
	// is the discoverable-login case where any credential is OK.
	if len(session.AllowedCredentialIDs) > 0 {
		ok := false
		for _, id := range session.AllowedCredentialIDs {
			if constantTimeBytesEqual(id, rawID) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, errors.New("passkey: credential not in allowed list")
		}
	}

	clientDataJSON, err := decodeBase64URL(resp.Response.ClientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("passkey: decode clientDataJSON: %w", err)
	}
	authBlob, err := decodeBase64URL(resp.Response.AuthenticatorData)
	if err != nil {
		return nil, fmt.Errorf("passkey: decode authenticatorData: %w", err)
	}
	sig, err := decodeBase64URL(resp.Response.Signature)
	if err != nil {
		return nil, fmt.Errorf("passkey: decode signature: %w", err)
	}

	hash, err := verifyClientData(clientDataJSON, clientDataTypeGet, session.Challenge, w.cfg.RPOrigins)
	if err != nil {
		return nil, err
	}

	ad, err := parseAuthenticatorData(authBlob)
	if err != nil {
		return nil, err
	}
	if err := verifyRPIDHash(ad, w.cfg.RPID); err != nil {
		return nil, err
	}
	if ad.Flags&flagUserPresent == 0 {
		return nil, errors.New("passkey: user-present flag not set")
	}
	if w.cfg.UserVerification == UVRequired && ad.Flags&flagUserVerified == 0 {
		return nil, errors.New("passkey: user-verified flag required but not set")
	}

	// Signed message is authData ‖ clientDataHash (WebAuthn §7.2 step 17).
	signedMessage := make([]byte, 0, len(authBlob)+len(hash))
	signedMessage = append(signedMessage, authBlob...)
	signedMessage = append(signedMessage, hash[:]...)

	pk, err := parseCOSEPublicKey(cred.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("passkey: stored public key: %w", err)
	}
	if err := verifySignature(pk, signedMessage, sig); err != nil {
		return nil, err
	}

	// Stable zero is valid for authenticators without counters. Once either
	// side is nonzero, every assertion must strictly advance the counter.
	if (cred.SignCount != 0 || ad.SignCount != 0) && ad.SignCount <= cred.SignCount {
		return nil, fmt.Errorf("passkey: sign count did not increase (stored=%d, presented=%d)",
			cred.SignCount, ad.SignCount)
	}

	var userHandle []byte
	if resp.Response.UserHandle != "" {
		userHandle, err = decodeBase64URL(resp.Response.UserHandle)
		if err != nil {
			return nil, fmt.Errorf("passkey: decode userHandle: %w", err)
		}
		// If the credential row has a user handle (i.e. registration
		// happened with one), it MUST match the presented value;
		// otherwise an attacker could authenticate as another user
		// with their own credential.
		if len(cred.UserHandle) > 0 && !constantTimeBytesEqual(userHandle, cred.UserHandle) {
			return nil, errors.New("passkey: userHandle does not match credential")
		}
	}

	return &LoginResult{
		Credential:   cred,
		NewSignCount: ad.SignCount,
		UserHandle:   userHandle,
		UserVerified: ad.Flags&flagUserVerified != 0,
	}, nil
}

func (w *WebAuthn) validateSessionPolicy(session *SessionData) error {
	if !session.UserVerification.valid() {
		return fmt.Errorf("passkey: invalid session UserVerification %q", session.UserVerification)
	}
	if session.UserVerification != w.cfg.UserVerification {
		return errors.New("passkey: session UserVerification does not match configured policy")
	}
	return nil
}

func (w *WebAuthn) algorithmAllowed(algorithm int) bool {
	for _, allowed := range w.cfg.Algorithms {
		if allowed.COSE == algorithm {
			return true
		}
	}
	return false
}
