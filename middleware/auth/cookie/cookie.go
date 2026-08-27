// Package cookie holds the Set-Cookie policy shared by the session middleware
// and the strategies that need short-lived flow cookies (OAuth2 state, PKCE
// verifier).
//
// It exists so those cookies cannot drift apart. The defaults are the secure
// ones — HttpOnly on, Secure inferred from the request — and every relaxation
// has to be spelled out in configuration.
package cookie

import (
	"fmt"
	"net/http"
	"strings"
)

// SecureMode decides whether the Secure attribute is set.
type SecureMode string

// Secure modes.
const (
	// SecureAuto sets Secure when the request arrived over TLS, directly or
	// through a proxy that said so. This is the default: it protects real
	// deployments without breaking http://localhost during development.
	SecureAuto SecureMode = "auto"

	// SecureAlways always sets Secure. Correct when TLS terminates upstream
	// and the proxy does not forward a protocol hint.
	SecureAlways SecureMode = "always"

	// SecureNever never sets Secure. Only for local development.
	SecureNever SecureMode = "never"
)

// UnmarshalText lets SecureMode be written as a plain string in config files.
// An empty value means SecureAuto.
func (m *SecureMode) UnmarshalText(b []byte) error {
	switch v := SecureMode(strings.ToLower(strings.TrimSpace(string(b)))); v {
	case "":
		*m = SecureAuto
	case SecureAuto, SecureAlways, SecureNever:
		*m = v
	// Tolerate booleans: "secure: true" is the obvious thing to write.
	case "true":
		*m = SecureAlways
	case "false":
		*m = SecureNever
	default:
		return fmt.Errorf("cookie: unknown secure mode %q (want auto, always or never)", v)
	}

	return nil
}

// For reports whether Secure should be set for this request.
func (m SecureMode) For(r *http.Request) bool {
	switch m {
	case SecureAlways:
		return true
	case SecureNever:
		return false
	default:
		return IsTLS(r)
	}
}

// IsTLS reports whether the request reached the origin over TLS, either
// directly or via a proxy that set X-Forwarded-Proto.
//
// The header is only meaningful behind a proxy you control. It is used here to
// decide whether to *add* a protection, never to drop one, so a spoofed value
// cannot weaken anything.
func IsTLS(r *http.Request) bool {
	if r == nil {
		return false
	}

	if r.TLS != nil {
		return true
	}

	proto := r.Header.Get("X-Forwarded-Proto")
	if i := strings.IndexByte(proto, ','); i >= 0 {
		proto = proto[:i]
	}

	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

// Options controls Set-Cookie attributes.
type Options struct {
	Path   string `cfg:"path"`
	MaxAge int    `cfg:"max_age"`
	Domain string `cfg:"domain"`

	// Secure controls the Secure attribute. Defaults to SecureAuto.
	Secure SecureMode `cfg:"secure"`

	// DisableHTTPOnly exposes the cookie to JavaScript.
	//
	// HttpOnly is on by default. A session cookie readable by script is one
	// XSS away from being exfiltrated, and nothing in this package needs to
	// read its own cookies from the browser.
	DisableHTTPOnly bool `cfg:"disable_http_only"`

	// SameSite defaults to Lax.
	SameSite http.SameSite `cfg:"same_site"`
}

// WithDefaults fills in the unset fields.
func (o Options) WithDefaults() Options {
	if o.Path == "" {
		o.Path = "/"
	}

	if o.SameSite == 0 {
		o.SameSite = http.SameSiteLaxMode
	}

	if o.Secure == "" {
		o.Secure = SecureAuto
	}

	return o
}

// Validate rejects combinations browsers will silently drop.
func (o Options) Validate() error {
	if o.SameSite == http.SameSiteNoneMode && o.Secure == SecureNever {
		return fmt.Errorf("cookie: same_site=none requires secure; browsers reject the combination")
	}

	return nil
}

// Build returns the Set-Cookie for name/value under these options.
func (o Options) Build(r *http.Request, name, value string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     o.Path,
		Domain:   o.Domain,
		MaxAge:   o.MaxAge,
		Secure:   o.Secure.For(r),
		HttpOnly: !o.DisableHTTPOnly,
		SameSite: o.SameSite,
	}
}

// Delete returns a Set-Cookie that expires name.
//
// The attributes must match the ones the cookie was set with, or the browser
// keeps the original alongside the tombstone.
func (o Options) Delete(r *http.Request, name string) *http.Cookie {
	c := o.Build(r, name, "")
	c.MaxAge = -1

	return c
}

// Set writes the cookie to w.
func (o Options) Set(w http.ResponseWriter, r *http.Request, name, value string) {
	http.SetCookie(w, o.Build(r, name, value))
}

// Clear expires the cookie on the client.
func (o Options) Clear(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, o.Delete(r, name))
}
