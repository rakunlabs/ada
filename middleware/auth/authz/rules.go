package authz

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/rakunlabs/ada/middleware/auth/identity"
)

// Rule binds a set of requests to the roles and scopes needed to make them.
//
// This is the configuration-driven half of the package: a deployment can move
// its policy into a config file instead of threading middleware through every
// route.
type Rule struct {
	// Name is a label used in logs. Optional.
	Name string `cfg:"name"`

	// Hosts limits the rule to matching Host headers. Empty means any host.
	Hosts []string `cfg:"hosts"`

	// Methods limits the rule to these HTTP methods, case-insensitively.
	// Empty, or a single "*", means any method.
	Methods []string `cfg:"methods"`

	// Paths are glob patterns (see Match) matched against the request path.
	// A rule with no paths matches nothing — an empty selector that matched
	// everything would be a footgun aimed squarely at whoever forgot to fill
	// it in.
	Paths []string `cfg:"paths"`

	// Excluded carves holes in this rule. Exclusions are evaluated first, so
	// `paths: ["/api/**"], excluded: [{paths: ["/api/health"]}]` behaves the
	// way it reads.
	Excluded []Rule `cfg:"excluded"`

	// Public allows anonymous access to the matched requests.
	Public bool `cfg:"public"`

	// Roles required. All of them, unless AnyRole is set.
	Roles []string `cfg:"roles"`

	// Scopes required. All of them, unless AnyScope is set.
	Scopes []string `cfg:"scopes"`

	// AnyRole switches Roles from "all of" to "at least one of".
	AnyRole bool `cfg:"any_role"`

	// AnyScope switches Scopes from "all of" to "at least one of".
	AnyScope bool `cfg:"any_scope"`
}

// Matches reports whether the rule selects this request.
func (r Rule) Matches(req *http.Request) bool {
	for _, ex := range r.Excluded {
		if ex.Matches(req) {
			return false
		}
	}

	if !r.matchHost(req.Host) {
		return false
	}

	if !r.matchMethod(req.Method) {
		return false
	}

	return MatchAny(r.Paths, req.URL.Path)
}

func (r Rule) matchHost(host string) bool {
	if len(r.Hosts) == 0 {
		return true
	}

	// Compare on the hostname only: ":8080" is a deployment detail, not part
	// of anybody's intended policy.
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}

	return MatchAny(r.Hosts, host)
}

func (r Rule) matchMethod(method string) bool {
	if len(r.Methods) == 0 {
		return true
	}

	for _, m := range r.Methods {
		if m == "*" || strings.EqualFold(m, method) {
			return true
		}
	}

	return false
}

// Requirement returns the Requirement this rule imposes.
func (r Rule) Requirement() Requirement {
	if r.Public {
		return Public
	}

	var reqs All

	if len(r.Roles) > 0 {
		if r.AnyRole {
			reqs = append(reqs, AnyRole(r.Roles))
		} else {
			reqs = append(reqs, Role(r.Roles))
		}
	}

	if len(r.Scopes) > 0 {
		if r.AnyScope {
			reqs = append(reqs, AnyScope(r.Scopes))
		} else {
			reqs = append(reqs, Scope(r.Scopes))
		}
	}

	if len(reqs) == 0 {
		// A rule that names no roles and no scopes still means something:
		// "you have to be logged in".
		return Authenticated
	}

	return append(All{Authenticated}, reqs...)
}

// Validate reports configuration mistakes that would otherwise fail silently.
func (r Rule) Validate() error {
	if len(r.Paths) == 0 {
		return fmt.Errorf("authz: rule %q has no paths", r.Name)
	}

	if r.Public && (len(r.Roles) > 0 || len(r.Scopes) > 0) {
		return fmt.Errorf("authz: rule %q is public but also requires roles/scopes", r.Name)
	}

	for _, ex := range r.Excluded {
		if len(ex.Paths) == 0 {
			return fmt.Errorf("authz: rule %q has an exclusion with no paths", r.Name)
		}
	}

	return nil
}

// Rules is an ordered policy table. The first matching rule decides; later
// rules are not consulted.
//
// Order is significant and explicit, rather than "most specific wins". Longest
// prefix matching reads well until two rules tie, at which point the effective
// policy depends on map iteration order.
type Rules struct {
	// Rules in evaluation order.
	Rules []Rule `cfg:"rules"`

	// Default applies when no rule matches. Nil means Authenticated.
	//
	// Set it to Public for an allow-list deployment where only the listed
	// paths are protected.
	Default Requirement `cfg:"-"`
}

// Validate checks every rule.
func (rs Rules) Validate() error {
	for i, r := range rs.Rules {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("rule[%d]: %w", i, err)
		}
	}

	return nil
}

// For returns the Requirement that applies to req.
func (rs Rules) For(req *http.Request) Requirement {
	for _, r := range rs.Rules {
		if r.Matches(req) {
			return r.Requirement()
		}
	}

	if rs.Default != nil {
		return rs.Default
	}

	return Authenticated
}

// Allow reports whether id may perform req under this policy.
func (rs Rules) Allow(req *http.Request, id *identity.Identity) bool {
	return rs.For(req).Allow(id)
}

// Middleware enforces the table.
func (rs Rules) Middleware(opts ...Option) func(http.Handler) http.Handler {
	cfg := newConfig(opts)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			req := rs.For(r)
			id := identity.FromContext(r.Context())

			if req.Allow(id) {
				next.ServeHTTP(w, r)

				return
			}

			cfg.deny(w, r, id, req.Describe())
		})
	}
}

// PublicPaths returns the path patterns reachable without authentication.
//
// Useful for wiring: these are the routes that should bypass Auth.Require
// entirely, rather than being authenticated and then allowed.
func (rs Rules) PublicPaths() []string {
	var out []string

	for _, r := range rs.Rules {
		if r.Public {
			out = append(out, r.Paths...)
		}
	}

	return out
}
