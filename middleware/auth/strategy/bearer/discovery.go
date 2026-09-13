package bearer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/internal/bodylimit"
	"github.com/rakunlabs/ada/middleware/auth/internal/jwt"
)

// ErrIssuerMismatch means a metadata document claimed an issuer other than
// the one it was fetched for.
//
// This is not pedantry. RFC 8414 §3.3 makes the check mandatory because
// without it, an attacker who can influence the discovery URL can point a
// resource server at metadata naming their own JWKS, and every token they
// mint verifies.
var ErrIssuerMismatch = errors.New("bearer: discovery document issuer does not match")

// metadata is the subset of RFC 8414 / OpenID Discovery this package reads.
type metadata struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// discoveryCache resolves and caches an issuer's JWKS endpoint.
//
// Resolution is lazy rather than done at construction: an authorization
// server that happens to be restarting should not prevent the process it
// protects from starting up.
type discoveryCache struct {
	issuer string
	client *http.Client

	mu     sync.Mutex
	keys   *jwt.KeySet
	failed time.Time
	now    func() time.Time
}

// retryDiscovery is the cooldown after a failed discovery attempt, so a
// stream of requests carrying tokens does not become a stream of requests
// against a struggling authorization server.
const retryDiscovery = 5 * time.Second

func newDiscoveryCache(issuer string, client *http.Client) *discoveryCache {
	return &discoveryCache{issuer: issuer, client: client, now: time.Now}
}

func (d *discoveryCache) keySet(ctx context.Context) (*jwt.KeySet, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.keys != nil {
		return d.keys, nil
	}
	if !d.failed.IsZero() && d.now().Sub(d.failed) < retryDiscovery {
		return nil, fmt.Errorf("bearer: discovery for %q unavailable", d.issuer)
	}

	doc, err := discover(ctx, d.client, d.issuer)
	if err != nil {
		d.failed = d.now()

		return nil, err
	}

	d.keys = jwt.NewKeySet(doc.JWKSURI, d.client, maxUpstreamResponseBytes)
	d.failed = time.Time{}

	return d.keys, nil
}

// discover fetches authorization server metadata for issuer.
//
// Three URLs are tried in the order RFC 8414 §5 and OpenID Connect Discovery
// 1.0 leave the ecosystem in. The first two apply RFC 8414's path-insertion
// rule, which multi-tenant deployments need; the third is the older OIDC
// layout that most issuers still serve and some serve only.
func discover(ctx context.Context, client *http.Client, issuer string) (metadata, error) {
	candidates, err := discoveryURLs(issuer)
	if err != nil {
		return metadata{}, err
	}

	var errs []error

	for _, candidate := range candidates {
		doc, err := fetchMetadata(ctx, client, candidate)
		if err != nil {
			errs = append(errs, err)

			continue
		}

		// RFC 8414 §3.3: the issuer in the document must match the one the
		// document was requested for.
		if doc.Issuer != issuer {
			return metadata{}, fmt.Errorf("%w: requested %q, document says %q", ErrIssuerMismatch, issuer, doc.Issuer)
		}
		if doc.JWKSURI == "" {
			errs = append(errs, fmt.Errorf("bearer: %s has no jwks_uri", candidate))

			continue
		}

		return doc, nil
	}

	return metadata{}, fmt.Errorf("bearer: discover %q: %w", issuer, errors.Join(errs...))
}

// discoveryURLs returns the metadata URLs to try for issuer.
func discoveryURLs(issuer string) ([]string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("bearer: issuer %q: %w", issuer, err)
	}

	scheme := strings.ToLower(u.Scheme)
	if (scheme != "https" && scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("bearer: issuer %q must be an absolute http(s) URL", issuer)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("bearer: issuer %q must not contain a query or fragment", issuer)
	}

	origin := scheme + "://" + u.Host
	path := strings.TrimSuffix(u.EscapedPath(), "/")

	return []string{
		origin + "/.well-known/oauth-authorization-server" + path,
		origin + "/.well-known/openid-configuration" + path,
		origin + path + "/.well-known/openid-configuration",
	}, nil
}

func fetchMetadata(ctx context.Context, client *http.Client, endpoint string) (metadata, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && client.Timeout <= 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return metadata{}, err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return metadata{}, fmt.Errorf("bearer: fetch %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := bodylimit.ReadUpstream(resp.Body, maxUpstreamResponseBytes)
	if err != nil {
		return metadata{}, fmt.Errorf("bearer: read %s: %w", endpoint, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return metadata{}, fmt.Errorf("bearer: %s returned %d", endpoint, resp.StatusCode)
	}

	var doc metadata
	if err := json.Unmarshal(body, &doc); err != nil {
		return metadata{}, fmt.Errorf("bearer: decode %s: %w", endpoint, err)
	}

	return doc, nil
}
