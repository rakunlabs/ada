package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DiscoveryDocument is the subset of the OpenID Connect Discovery 1.0 response
// that we use. See https://openid.net/specs/openid-connect-discovery-1_0.html
type DiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// discoveryCache caches a fetched discovery document for a configured TTL.
type discoveryCache struct {
	mu        sync.RWMutex
	doc       *DiscoveryDocument
	fetchedAt time.Time
	ttl       time.Duration
}

func newDiscoveryCache(ttl time.Duration) *discoveryCache {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}

	return &discoveryCache{ttl: ttl}
}

func (c *discoveryCache) get() *DiscoveryDocument {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.doc != nil && time.Since(c.fetchedAt) < c.ttl {
		return c.doc
	}

	return nil
}

func (c *discoveryCache) set(doc *DiscoveryDocument) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.doc = doc
	c.fetchedAt = time.Now()
}

// Discover fetches the OIDC discovery document from the issuer's
// .well-known/openid-configuration endpoint.
func Discover(ctx context.Context, client *http.Client, issuerURL string) (*DiscoveryDocument, error) {
	if client == nil {
		client = http.DefaultClient
	}

	wellKnown := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("discovery: build request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("discovery: read body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("discovery: %s returned %d: %s", wellKnown, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var doc DiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("discovery: decode: %w", err)
	}

	return &doc, nil
}

// applyDiscovery fills empty Config fields from a DiscoveryDocument.
// Fields that are already set in cfg are not overwritten.
func applyDiscovery(cfg *Config, doc *DiscoveryDocument) {
	if cfg.AuthURL == "" {
		cfg.AuthURL = doc.AuthorizationEndpoint
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = doc.TokenEndpoint
	}
	if cfg.UserInfoURL == "" {
		cfg.UserInfoURL = doc.UserInfoEndpoint
	}
	if cfg.RevocationURL == "" {
		cfg.RevocationURL = doc.RevocationEndpoint
	}
	if cfg.LogoutURL == "" {
		cfg.LogoutURL = doc.EndSessionEndpoint
	}
	if cfg.JWKSURL == "" {
		cfg.JWKSURL = doc.JWKSURI
	}
}
