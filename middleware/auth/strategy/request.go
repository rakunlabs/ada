package strategy

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

var (
	// ErrNoCredentials is returned by
	// RequestAuthenticator.AuthenticateRequest when the request carries
	// none of the strategy's credentials. It means "not my request", not
	// "rejected" — the middleware moves on to the next strategy and
	// ultimately to the session cookie.
	ErrNoCredentials = errors.New("strategy: no credentials in request")

	// ErrInvalidCredentials is returned when the request carried this
	// strategy's credentials but they were rejected. Require renders it
	// as 401. Any other error is treated as a fault in the strategy or
	// its backing store and rendered as 500, so a database outage is
	// never reported to the caller as "your token is bad".
	ErrInvalidCredentials = errors.New("strategy: invalid credentials")
)

// RequestAuthenticator is an optional interface for strategies whose
// credential travels on the request itself — an API key header, a signed
// header from a trusted proxy — rather than being exchanged for a session
// at a login endpoint.
//
// Auth.Require consults every registered RequestAuthenticator before
// falling back to the session cookie. Without this, a programmatic client
// presenting a valid API key on a protected route is answered with a
// redirect to the login page: correct for a browser, useless for a client
// that has no cookie jar and no way to complete an interactive flow.
//
// Authentication here is per request and stateless. No session is created,
// no cookie is set, and nothing is persisted — presenting the credential
// again on the next request is the whole protocol.
type RequestAuthenticator interface {
	Authenticator

	// AuthenticateRequest resolves the credentials carried by r.
	//
	//   - (id, nil)                  — authenticated.
	//   - (nil, ErrNoCredentials)    — r carries none of this strategy's
	//     credentials; the middleware tries the next strategy.
	//   - (nil, err)                 — credentials were present but bad.
	//     The middleware rejects the request instead of falling through,
	//     so an invalid token is never silently downgraded to anonymous
	//     and then redirected to a login page.
	//
	// Implementations must not write to the response: Require owns the
	// error rendering so every strategy fails the same way.
	AuthenticateRequest(ctx context.Context, r *http.Request) (*identity.Identity, error)
}

// AuthenticateRequest walks the registry in registration order and returns
// the first successful authentication.
//
// The first strategy to report an error other than ErrNoCredentials stops
// the walk. Presenting a malformed or revoked credential is a deliberate
// act; continuing past it to try other strategies would turn a clear 401
// into a confusing redirect, and would let a caller probe which strategy
// owns which header by watching the response change.
//
// Returns (nil, ErrNoCredentials) when no strategy recognized the request.
func (r *Registry) AuthenticateRequest(ctx context.Context, req *http.Request) (*identity.Identity, error) {
	for _, s := range r.List() {
		ra, ok := s.(RequestAuthenticator)
		if !ok {
			continue
		}

		id, err := ra.AuthenticateRequest(ctx, req)
		if errors.Is(err, ErrNoCredentials) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if id == nil {
			continue
		}

		return id, nil
	}

	return nil, ErrNoCredentials
}

// HasRequestAuthenticator reports whether any registered strategy can
// authenticate straight from a request. Used to skip the per-request walk
// entirely on deployments that only run interactive strategies.
func (r *Registry) HasRequestAuthenticator() bool {
	for _, s := range r.List() {
		if _, ok := s.(RequestAuthenticator); ok {
			return true
		}
	}

	return false
}

// Challenger is an optional interface for strategies that can describe
// themselves as an HTTP authentication challenge (RFC 9110 §11.6.1).
//
// A 401 response is required to carry a WWW-Authenticate header naming a
// scheme the client can actually use. Hardcoding one would be a guess —
// a deployment running only OAuth2 has no bearer-key endpoint to point a
// client at — so the challenge is assembled from whatever is registered.
type Challenger interface {
	// Challenge returns one WWW-Authenticate value, e.g. `Bearer` or
	// `Basic realm="Restricted"`. An empty string contributes nothing.
	Challenge() string
}

// RequestChallenger is an optional interface for strategies whose challenge
// depends on the request being rejected.
//
// A bare `Bearer` is a complete challenge only if the client already knows
// where to get a token. RFC 9728 §5.1 closes that gap with a
// resource_metadata parameter pointing at this resource's metadata document
// — and that URL is derived from the request's own origin whenever the
// deployment has not pinned one, so it cannot be computed at construction.
//
// A strategy implementing this takes precedence over its own Challenge()
// for requests; Challenge() remains the answer when no request is in hand.
type RequestChallenger interface {
	Challenger

	// ChallengeRequest returns one WWW-Authenticate value for r. An empty
	// string contributes nothing.
	ChallengeRequest(r *http.Request) string
}

// Challenge assembles the WWW-Authenticate value advertising every
// registered strategy that can authenticate a request directly.
//
// Multiple challenges are comma-separated, which RFC 9110 §11.6.1 allows
// and clients are expected to choose from. Returns "" when no registered
// strategy accepts credentials on the request — a cookie-only deployment
// has no scheme to offer, and inventing one would send clients chasing an
// endpoint that does not exist.
func (r *Registry) Challenge() string {
	return r.ChallengeRequest(nil)
}

// ChallengeRequest is Challenge for a specific request, letting strategies
// that implement RequestChallenger tailor their parameters to it.
//
// A nil request is allowed and falls back to the static Challenge() of every
// strategy, so callers with no request in hand keep working.
func (r *Registry) ChallengeRequest(req *http.Request) string {
	var challenges []string

	for _, s := range r.List() {
		c, ok := s.(Challenger)
		if !ok {
			continue
		}

		v := ""
		if rc, ok := s.(RequestChallenger); ok && req != nil {
			v = rc.ChallengeRequest(req)
		} else {
			v = c.Challenge()
		}

		if v != "" {
			challenges = append(challenges, v)
		}
	}

	return strings.Join(challenges, ", ")
}
