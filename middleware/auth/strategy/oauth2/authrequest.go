package oauth2

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// AuthHeaderStyle is a type to set Authorization header style.
type AuthHeaderStyle int

const (
	// AuthHeaderStyleBasic sends the client credentials in the HTTP Basic
	// Authorization header (RFC 6749 §2.3.1 client_secret_basic). Default.
	AuthHeaderStyleBasic AuthHeaderStyle = iota
	// AuthHeaderStyleBearerSecret sends the client secret as a bearer token
	// in the Authorization header. Non-standard; some providers expect it.
	AuthHeaderStyleBearerSecret
	// AuthHeaderStyleParams sends the client credentials as URL query
	// parameters. Non-standard; kept for backwards compatibility. Prefer
	// AuthHeaderStylePost for providers that want credentials in the request.
	AuthHeaderStyleParams
	// AuthHeaderStylePost sends the client credentials in the request body
	// form parameters (RFC 6749 §2.3.1 client_secret_post). This is the
	// standard alternative to Basic and what most providers mean by
	// "client_secret_post".
	AuthHeaderStylePost
)

// ParseAuthHeaderStyle resolves a human-readable token-endpoint auth method
// into an AuthHeaderStyle. Matching is case-insensitive and tolerant of common
// aliases, and the legacy numeric forms ("0".."3") are still accepted so
// configs that set the old integer value keep working. ok is false when s
// names no known style; callers that want a lenient default may ignore ok and
// use the returned zero value (Basic).
func ParseAuthHeaderStyle(s string) (style AuthHeaderStyle, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "basic", "client_secret_basic", "0":
		return AuthHeaderStyleBasic, true
	case "bearer", "bearer_secret", "1":
		return AuthHeaderStyleBearerSecret, true
	case "query", "params", "2":
		return AuthHeaderStyleParams, true
	case "post", "body", "client_secret_post", "3":
		return AuthHeaderStylePost, true
	default:
		return AuthHeaderStyleBasic, false
	}
}

// String returns the canonical, config-friendly name of the style.
func (s AuthHeaderStyle) String() string {
	switch s {
	case AuthHeaderStyleBasic:
		return "client_secret_basic"
	case AuthHeaderStyleBearerSecret:
		return "bearer"
	case AuthHeaderStyleParams:
		return "query"
	case AuthHeaderStylePost:
		return "client_secret_post"
	default:
		return "client_secret_basic"
	}
}

// MarshalText implements encoding.TextMarshaler so the style round-trips as a
// readable string in JSON/YAML/config rather than a magic integer.
func (s AuthHeaderStyle) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler so config can set the
// style as a string (e.g. auth_header_style: client_secret_post). An empty
// value selects the Basic default; an unrecognized value is rejected so a
// typo surfaces instead of silently falling back.
func (s *AuthHeaderStyle) UnmarshalText(text []byte) error {
	style, ok := ParseAuthHeaderStyle(string(text))
	if !ok {
		return fmt.Errorf("oauth2: unknown auth_header_style %q", string(text))
	}

	*s = style

	return nil
}

// authBody adds the client credentials to the request body form parameters
// (RFC 6749 §2.3.1 client_secret_post). It mutates values in place and so
// MUST be called before the body is encoded onto the request.
func authBody(clientID, clientSecret string, values url.Values, style AuthHeaderStyle) {
	if style != AuthHeaderStylePost || values == nil {
		return
	}

	if clientID != "" {
		values.Set("client_id", clientID)
	}
	if clientSecret != "" {
		values.Set("client_secret", clientSecret)
	}
}

// authHeader sets the Authorization header based on the style.
func authHeader(req *http.Request, clientID, clientSecret string, style AuthHeaderStyle) {
	if req == nil {
		return
	}

	switch style {
	case AuthHeaderStyleBasic:
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	case AuthHeaderStyleBearerSecret:
		req.Header.Add("Authorization", "Bearer "+clientSecret)
	}
}

// authParams sets client credentials as URL query parameters.
func authParams(clientID, clientSecret string, req *http.Request, style AuthHeaderStyle) {
	if style != AuthHeaderStyleParams || req == nil {
		return
	}

	query := req.URL.Query()
	if clientID != "" {
		query.Add("client_id", clientID)
	}
	if clientSecret != "" {
		query.Add("client_secret", clientSecret)
	}

	req.URL.RawQuery = query.Encode()
}
