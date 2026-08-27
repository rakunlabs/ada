package oauth2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/rakunlabs/ada/middleware/auth/cookie"
)

// flowState is the per-authorization-request secret material the callback has
// to be able to check.
//
// It lives in one HttpOnly cookie rather than three loose ones. Splitting it
// invited the previous bug: the state cookie was created with hardcoded
// Secure=false, HttpOnly=false attributes while the PKCE cookie forced
// HttpOnly=true, so the CSRF token was the one piece of the flow that script
// on the page could read.
type flowState struct {
	State    string `json:"s"`
	Nonce    string `json:"n,omitempty"`
	Verifier string `json:"v,omitempty"`
}

func (f flowState) encode() (string, error) {
	raw, err := json.Marshal(f)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeFlowState(v string) (flowState, error) {
	var f flowState

	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return f, fmt.Errorf("oauth2: decode flow cookie: %w", err)
	}

	if err := json.Unmarshal(raw, &f); err != nil {
		return f, fmt.Errorf("oauth2: decode flow cookie: %w", err)
	}

	return f, nil
}

// flowCookieName is the single cookie carrying flowState for this strategy.
func (s *Strategy) flowCookieName() string {
	return "auth_flow_" + s.name
}

func (s *Strategy) setFlowCookie(w http.ResponseWriter, r *http.Request, f flowState) error {
	v, err := f.encode()
	if err != nil {
		return err
	}

	s.flowCookie.Set(w, r, s.flowCookieName(), v)

	return nil
}

// takeFlowCookie reads the flow state and clears the cookie in the same breath.
// One authorization response, one use.
func (s *Strategy) takeFlowCookie(w http.ResponseWriter, r *http.Request) (flowState, error) {
	c, err := r.Cookie(s.flowCookieName())

	s.flowCookie.Clear(w, r, s.flowCookieName())

	if err != nil {
		return flowState{}, errors.New("oauth2: no flow cookie")
	}

	return decodeFlowState(c.Value)
}

// checkState compares the callback's state against the cookie in constant
// time. Both are attacker-visible; a comparison that returns early on the
// first differing byte is a slow oracle for forging one.
func checkState(want, got string) error {
	if want == "" || got == "" {
		return errors.New("oauth2: missing state")
	}

	if subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return errors.New("oauth2: state mismatch")
	}

	return nil
}

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth2: read random: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// defaultFlowCookie is the policy for the short-lived authorization cookie.
// Six minutes is long enough for a human to finish a login at the IdP and
// short enough that an abandoned attempt does not linger.
func defaultFlowCookie(opts cookie.Options) cookie.Options {
	if opts.MaxAge == 0 {
		opts.MaxAge = 360
	}

	// The flow cookie must survive the cross-site redirect back from the IdP,
	// so Strict is not an option here.
	if opts.SameSite == 0 {
		opts.SameSite = http.SameSiteLaxMode
	}

	// Nothing in the browser needs to read this cookie.
	opts.DisableHTTPOnly = false

	return opts.WithDefaults()
}
