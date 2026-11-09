package oauthserver

import (
	"context"
	"errors"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

// Hooks are the application's say in what a token may do.
//
// All hooks are optional. Without them every signed-in user may approve any
// registered client for any supported scope, and a token keeps acting as the
// identity captured when it was approved.
type Hooks struct {
	// Authorize runs once the authorization request is valid and the user is
	// known, before the consent page. It may:
	//
	//   - narrow req.Scopes (never widen: the server rejects scopes the
	//     client did not ask for)
	//   - attach req.Extra, which is copied onto the code and the token
	//   - refuse with an *Error, which is sent to the client's redirect URI
	//     (e.g. &Error{Code: "invalid_target"} for a resource the user may
	//     not reach); any other error is reported as server_error
	Authorize func(ctx context.Context, req *AuthorizeRequest) error

	// Identity refreshes the identity a token acts as. It runs when a code
	// is exchanged, when a token is refreshed and every time an access token
	// is validated, so a user who was disabled or demoted loses access at
	// once rather than when the token expires.
	//
	// Return ErrAccessDenied to refuse; return the identity unchanged to
	// accept. Any other error is an outage (500).
	Identity func(ctx context.Context, t *Token) (*identity.Identity, error)

	// TokenTTL lets the application choose lifetimes per token, e.g. a
	// shorter refresh lifetime for a sensitive client. Zero values keep the
	// configured defaults; a negative refresh TTL issues no refresh token.
	TokenTTL func(ctx context.Context, t *Token) (access, refresh time.Duration)
}

// AuthorizeRequest is a validated authorization request.
type AuthorizeRequest struct {
	Client   *Client
	Identity *identity.Identity

	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	// Scopes are the requested scopes, or Config.DefaultScopes when the
	// client asked for none.
	Scopes []string
	// Resource is the RFC 8707 resource indicator, if any.
	Resource string
	// Extra is copied onto the issued token. Set it from Hooks.Authorize.
	Extra map[string]any
}

// Error is an OAuth error a hook wants the client to receive.
type Error struct {
	Code        string
	Description string
}

func (e *Error) Error() string {
	if e.Description == "" {
		return e.Code
	}

	return e.Code + ": " + e.Description
}

// asOAuthError extracts an *Error, or nil.
func asOAuthError(err error) *Error {
	var oe *Error
	if errors.As(err, &oe) {
		return oe
	}

	return nil
}
