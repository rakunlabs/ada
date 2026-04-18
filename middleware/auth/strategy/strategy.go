// Package strategy defines the pluggable authentication interface.
//
// Each Authenticator is responsible for one login mechanism (OAuth2 code flow,
// local credentials, LDAP, etc). The auth middleware orchestrates strategies:
// it routes /auth/login/{name} and /auth/callback/{name} to the matching
// strategy and, on success, hands the returned Identity to the issuer for
// session minting.
package strategy

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

// Authenticator is implemented by every login mechanism.
type Authenticator interface {
	// Name is the stable URL key (e.g. "google", "local"). Must be URL-safe.
	Name() string

	// Descriptor describes the strategy to the login UI.
	Descriptor() Descriptor

	// Login runs the HTTP-facing login step.
	//
	// Possible outcomes:
	//   - (*Identity, OutcomeContinue, nil): identity ready, the auth middleware
	//     issues a session and writes the response.
	//   - (nil, OutcomePending, nil): the strategy already wrote the response
	//     (e.g. a 307 redirect to an IdP). The middleware must not write again.
	//   - (nil, OutcomeFailed, nil): the strategy already wrote an error response.
	//   - (*, *, err): unexpected error; the middleware writes a 500.
	Login(w http.ResponseWriter, r *http.Request) (*identity.Identity, Outcome, error)

	// Logout is optional provider-side cleanup (e.g. revoke an OAuth2 token).
	// Best-effort; errors are logged, not surfaced to the user.
	Logout(ctx context.Context, id *identity.Identity) error
}

// Outcome tells the auth middleware what to do after Login returns.
type Outcome int

const (
	// OutcomeContinue means the strategy returned a valid Identity and the
	// middleware should issue a session and write the success response.
	OutcomeContinue Outcome = iota
	// OutcomePending means the strategy already wrote the response (typically a
	// redirect for the next step in a multi-step flow).
	OutcomePending
	// OutcomeFailed means the strategy already wrote an error response and the
	// middleware should not touch the writer further.
	OutcomeFailed
)

// Descriptor is the UI-facing summary of a strategy. Returned from /auth/info
// so the login page can render the right widget per strategy.
type Descriptor struct {
	Name     string        `json:"name"`
	Kind     string        `json:"kind"`               // "oauth2" | "password" | "custom"
	Label    string        `json:"label"`              // human-readable label
	LoginURL string        `json:"url"`                // where the UI navigates/POSTs
	Fields   []Field       `json:"fields,omitempty"`   // for password/custom forms
	Register *RegisterInfo `json:"register,omitempty"` // set when the strategy supports signup
	Priority int           `json:"-"`                  // sort order, lower = earlier
	Hidden   bool          `json:"-"`                  // hide from /auth/info
}

// RegisterInfo is the UI-facing description of a strategy's signup endpoint.
// A nil *RegisterInfo in a Descriptor means the strategy does not support
// registration.
type RegisterInfo struct {
	URL    string  `json:"url"`              // POST target for signup
	Fields []Field `json:"fields,omitempty"` // register-specific inputs
}

// Field describes one input on a strategy's login form.
type Field struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Type        string `json:"type"` // text | password | email
	Placeholder string `json:"placeholder,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// Registerer is an optional interface implemented by strategies that support
// self-service account creation. The middleware routes POST
// {base}/login/register/{name} to Register when a strategy satisfies this
// interface; strategies that don't (e.g. OAuth2) are skipped.
//
// Register mirrors Authenticator.Login semantics:
//   - (id, OutcomeContinue, nil): auto-login requested; middleware issues a
//     session using id and writes the standard success response.
//   - (nil, OutcomePending, nil): strategy already wrote the response (e.g.
//     "account created, please sign in" when auto-login is disabled).
//   - (nil, OutcomeFailed, nil): strategy already wrote a 4xx error response.
//   - (*, *, err): unexpected error; middleware writes a 500.
type Registerer interface {
	Register(w http.ResponseWriter, r *http.Request) (*identity.Identity, Outcome, error)
}

// Registry holds the active strategies keyed by Name(). Safe for concurrent
// reads after Init; writes (Add) are serialized.
type Registry struct {
	mu    sync.RWMutex
	items map[string]Authenticator
	order []string
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{items: make(map[string]Authenticator)}
}

// Add registers a strategy. Returns an error if a strategy with the same name
// is already registered.
func (r *Registry) Add(s Authenticator) error {
	if s == nil {
		return fmt.Errorf("strategy: nil authenticator")
	}

	name := s.Name()
	if name == "" {
		return fmt.Errorf("strategy: empty name")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.items[name]; exists {
		return fmt.Errorf("strategy: %q already registered", name)
	}

	r.items[name] = s
	r.order = append(r.order, name)

	return nil
}

// Get returns the strategy with the given name, or nil if absent.
func (r *Registry) Get(name string) Authenticator {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.items[name]
}

// List returns all strategies in registration order.
func (r *Registry) List() []Authenticator {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Authenticator, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.items[name])
	}

	return out
}

// Descriptors returns descriptors for all non-hidden strategies, sorted by
// (Priority asc, Name asc) so the login UI always renders in a stable order.
func (r *Registry) Descriptors() []Descriptor {
	all := r.List()

	out := make([]Descriptor, 0, len(all))
	for _, s := range all {
		d := s.Descriptor()
		if d.Hidden {
			continue
		}
		out = append(out, d)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}

		return out[i].Name < out[j].Name
	})

	return out
}
