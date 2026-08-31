// Package guard rate-limits and locks out repeated authentication attempts.
//
// Nothing else in middleware/auth counts failures. Without this, a password
// verifier, an LDAP bind or a magic-link sender will happily service an
// unbounded stream of guesses, and the only cost to the attacker is
// bandwidth.
//
// The guard is deliberately small and in-process. It is not a distributed rate
// limiter: with several replicas behind a load balancer, each keeps its own
// counters and the effective limit multiplies by the replica count. That is
// still a hard ceiling per attacker per replica, which is the property that
// matters. Deployments that need an exact global budget should supply their
// own Store.
package guard

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/proxy"
)

// Decision is the result of asking the guard whether an attempt may proceed.
type Decision struct {
	// Allowed is false when the key is locked out.
	Allowed bool

	// RetryAfter is how long the caller should wait. Zero when allowed.
	RetryAfter time.Duration

	// Failures is the number of consecutive failures recorded for the key.
	Failures int
}

// Config tunes the guard.
type Config struct {
	// MaxFailures is how many consecutive failures are tolerated before the
	// key is locked. Default 5.
	MaxFailures int `cfg:"max_failures"`

	// Window is how long a failure counts against the key. Each new failure
	// restarts it. Default 15 minutes.
	Window time.Duration `cfg:"window"`

	// Lockout is how long a locked key stays locked. Default 15 minutes.
	//
	// Lockout is exponential up to MaxLockout: doubling on each failure past
	// the threshold, so a persistent attacker pays a rapidly rising price
	// while a user who mistyped their password twice does not.
	Lockout time.Duration `cfg:"lockout"`

	// MaxLockout caps the exponential backoff. Default 1 hour.
	MaxLockout time.Duration `cfg:"max_lockout"`

	// Now is the time source; defaults to time.Now. Tests override.
	Now func() time.Time `cfg:"-"`
}

func (c Config) withDefaults() Config {
	if c.MaxFailures <= 0 {
		c.MaxFailures = 5
	}

	if c.Window <= 0 {
		c.Window = 15 * time.Minute
	}

	if c.Lockout <= 0 {
		c.Lockout = 15 * time.Minute
	}

	if c.MaxLockout <= 0 {
		c.MaxLockout = time.Hour
	}

	if c.MaxLockout < c.Lockout {
		c.MaxLockout = c.Lockout
	}

	if c.Now == nil {
		c.Now = time.Now
	}

	return c
}

// Guard tracks consecutive failures per key.
type Guard struct {
	cfg Config

	mu      sync.Mutex
	entries map[string]*entry

	stop   chan struct{}
	closed sync.Once
}

type entry struct {
	failures    int
	lastFailure time.Time
	lockedUntil time.Time
}

// New returns a Guard and starts its janitor. Call Close to stop it.
func New(cfg Config) *Guard {
	g := &Guard{
		cfg:     cfg.withDefaults(),
		entries: make(map[string]*entry),
		stop:    make(chan struct{}),
	}

	go g.janitor()

	return g
}

// Close stops the janitor.
func (g *Guard) Close() error {
	g.closed.Do(func() { close(g.stop) })

	return nil
}

// Check reports whether an attempt for key may proceed.
func (g *Guard) Check(key string) Decision {
	if key == "" {
		return Decision{Allowed: true}
	}

	now := g.cfg.Now()

	g.mu.Lock()
	defer g.mu.Unlock()

	e, ok := g.entries[key]
	if !ok {
		return Decision{Allowed: true}
	}

	if now.Before(e.lockedUntil) {
		return Decision{
			RetryAfter: e.lockedUntil.Sub(now).Round(time.Second),
			Failures:   e.failures,
		}
	}

	// The window elapsed with no further failure: forget the key entirely, so
	// an occasional typo never accumulates into a lockout.
	if now.Sub(e.lastFailure) > g.cfg.Window {
		delete(g.entries, key)

		return Decision{Allowed: true}
	}

	return Decision{Allowed: true, Failures: e.failures}
}

// Fail records a failed attempt and returns the resulting decision. The
// returned Decision describes the state *after* this failure, so a caller can
// tell the difference between "wrong password" and "wrong password, and you
// are now locked out".
func (g *Guard) Fail(key string) Decision {
	if key == "" {
		return Decision{Allowed: true}
	}

	now := g.cfg.Now()

	g.mu.Lock()
	defer g.mu.Unlock()

	e, ok := g.entries[key]
	if !ok || now.Sub(e.lastFailure) > g.cfg.Window {
		e = &entry{}
		g.entries[key] = e
	}

	e.failures++
	e.lastFailure = now

	if e.failures >= g.cfg.MaxFailures {
		e.lockedUntil = now.Add(g.backoff(e.failures))
	}

	if now.Before(e.lockedUntil) {
		return Decision{
			RetryAfter: e.lockedUntil.Sub(now).Round(time.Second),
			Failures:   e.failures,
		}
	}

	return Decision{Allowed: true, Failures: e.failures}
}

// Succeed clears the failure record for key.
func (g *Guard) Succeed(key string) {
	if key == "" {
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	delete(g.entries, key)
}

// backoff doubles the lockout for each failure past the threshold.
func (g *Guard) backoff(failures int) time.Duration {
	d := g.cfg.Lockout

	for i := g.cfg.MaxFailures; i < failures; i++ {
		d *= 2
		if d >= g.cfg.MaxLockout {
			return g.cfg.MaxLockout
		}
	}

	if d > g.cfg.MaxLockout {
		return g.cfg.MaxLockout
	}

	return d
}

// Len reports the number of tracked keys. Intended for tests and metrics.
func (g *Guard) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()

	return len(g.entries)
}

func (g *Guard) janitor() {
	t := time.NewTicker(g.cfg.Window)
	defer t.Stop()

	for {
		select {
		case <-g.stop:
			return
		case <-t.C:
			g.sweep()
		}
	}
}

func (g *Guard) sweep() {
	now := g.cfg.Now()

	g.mu.Lock()
	defer g.mu.Unlock()

	for k, e := range g.entries {
		if now.Before(e.lockedUntil) {
			continue
		}

		if now.Sub(e.lastFailure) > g.cfg.Window {
			delete(g.entries, k)
		}
	}
}

// ClientIP extracts the caller's address for use as a guard key.
//
// trusted is the set of peers allowed to speak for someone else. Its zero value
// uses the peer address verbatim: an attacker who can set X-Forwarded-For would
// otherwise get an unlimited supply of fresh identities and defeat the guard
// entirely.
//
// The derivation itself lives in the proxy package. A guard key and a logged
// address must agree on who the client is, and two implementations of that
// question drift apart in exactly the direction an attacker wants.
func ClientIP(r *http.Request, trusted proxy.Policy) string {
	if ip, err := trusted.ClientIP(r); err == nil {
		return ip
	}

	// A malformed forwarding header must not mint a new key. Fall back to the
	// immediate peer, which is always attributable.
	return proxy.RealIP(r)
}

// ParseCIDRs parses a list of CIDR strings, tolerating bare IPs.
func ParseCIDRs(values []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(values))

	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		if !strings.Contains(v, "/") {
			ip := net.ParseIP(v)
			if ip == nil {
				return nil, &net.ParseError{Type: "IP address", Text: v}
			}

			bits := 32
			if ip.To4() == nil {
				bits = 128
			}

			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})

			continue
		}

		_, n, err := net.ParseCIDR(v)
		if err != nil {
			return nil, err
		}

		out = append(out, n)
	}

	return out, nil
}

// Limiter is the subset of Guard that strategies depend on. Deployments that
// need shared state across replicas can implement it against Redis.
type Limiter interface {
	Check(key string) Decision
	Fail(key string) Decision
	Succeed(key string)
}

var _ Limiter = (*Guard)(nil)

// WriteLocked answers a request that the guard refused.
//
// 429 rather than 401: the credentials were never examined, and telling the
// caller "unauthorized" would invite them to keep trying.
func WriteLocked(w http.ResponseWriter, d Decision) {
	if d.RetryAfter > 0 {
		w.Header().Set("Retry-After", formatSeconds(d.RetryAfter))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)

	_, _ = w.Write([]byte(`{"error":"too_many_attempts","message":"too many failed attempts, try again later"}` + "\n"))
}

func formatSeconds(d time.Duration) string {
	secs := int64(d / time.Second)
	if secs < 1 {
		secs = 1
	}

	return itoa(secs)
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}

	var buf [20]byte

	i := len(buf)

	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}

	return string(buf[i:])
}

// ContextKey is unused today; kept so future middleware can stash a Decision.
type contextKey struct{}

// WithDecision stores d in ctx.
func WithDecision(ctx context.Context, d Decision) context.Context {
	return context.WithValue(ctx, contextKey{}, d)
}

// FromContext returns the Decision stored by WithDecision.
func FromContext(ctx context.Context) (Decision, bool) {
	d, ok := ctx.Value(contextKey{}).(Decision)

	return d, ok
}
