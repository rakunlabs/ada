// Package mtls authenticates callers by their TLS client certificate.
//
// Two deployment shapes are supported:
//
//   - Native: TLS terminates in this process. The certificate is taken from
//     tls.ConnectionState.VerifiedChains, i.e. only after the standard library
//     has validated it against the configured ClientCAs.
//
//   - Proxy: TLS terminates upstream and the proxy forwards the certificate in
//     a header. This is only as trustworthy as the network path, so it
//     requires an explicit list of proxy CIDRs and, optionally, a header the
//     proxy sets to report its own verification result.
//
// The strategy implements strategy.RequestAuthenticator, so a client
// presenting a certificate is authenticated on protected routes directly,
// without a session.
package mtls

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/guard"
	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
)

// Verifier turns a validated client certificate into an Identity.
//
// Return strategy.ErrInvalidCredentials to reject a certificate that is
// cryptographically fine but belongs to nobody the application knows.
//
// A nil Verifier means the strategy derives the Identity from the certificate
// itself: Subject is the SHA-256 fingerprint, Name the CN, Email the first
// email SAN.
type Verifier func(ctx context.Context, cert *x509.Certificate) (*identity.Identity, error)

// ProxyConfig describes how a terminating proxy forwards the client
// certificate.
type ProxyConfig struct {
	// TrustedCIDRs are the networks allowed to present forwarded
	// certificates. Required — without it, any client could forge the header
	// and become anyone.
	TrustedCIDRs []string `cfg:"trusted_cidrs"`

	// CertHeader carries the client certificate, PEM or base64-DER, usually
	// URL-encoded. Default "X-Forwarded-Tls-Client-Cert".
	CertHeader string `cfg:"cert_header"`

	// VerifyHeader, when set, must equal VerifyValue for the certificate to be
	// accepted. This is how a proxy reports "I checked the chain"; without it
	// the strategy is trusting the proxy to only forward what it validated.
	VerifyHeader string `cfg:"verify_header"`

	// VerifyValue is the value VerifyHeader must carry. Default "SUCCESS".
	VerifyValue string `cfg:"verify_value"`
}

// Strategy implements strategy.Authenticator using TLS client certificates.
type Strategy struct {
	name     string
	label    string
	priority int
	hidden   bool

	verifier Verifier

	proxy      *ProxyConfig
	proxyNets  []*net.IPNet
	certHeader string

	now func() time.Time
}

// Option configures a Strategy.
type Option func(*Strategy)

// WithLabel sets the human-readable label shown in the login UI.
func WithLabel(label string) Option {
	return func(s *Strategy) { s.label = label }
}

// WithPriority sets the sort order in the login UI (lower = earlier).
func WithPriority(p int) Option {
	return func(s *Strategy) { s.priority = p }
}

// WithVisible un-hides the strategy in the login UI. Hidden by default:
// there is no form to render, the browser either has a certificate or it does
// not.
func WithVisible() Option {
	return func(s *Strategy) { s.hidden = false }
}

// WithProxy enables forwarded-certificate mode.
func WithProxy(cfg ProxyConfig) Option {
	return func(s *Strategy) {
		c := cfg
		if c.CertHeader == "" {
			c.CertHeader = "X-Forwarded-Tls-Client-Cert"
		}

		if c.VerifyValue == "" {
			c.VerifyValue = "SUCCESS"
		}

		s.proxy = &c
	}
}

// New returns an mTLS strategy.
//
// It returns an error rather than panicking on a bad proxy CIDR: that value
// usually comes from configuration, and a typo there should surface at startup
// as a message, not a stack trace.
func New(name string, verifier Verifier, opts ...Option) (*Strategy, error) {
	s := &Strategy{
		name:     name,
		label:    name,
		hidden:   true,
		verifier: verifier,
		now:      time.Now,
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.proxy != nil {
		if len(s.proxy.TrustedCIDRs) == 0 {
			return nil, fmt.Errorf("mtls: proxy mode requires trusted_cidrs")
		}

		nets, err := guard.ParseCIDRs(s.proxy.TrustedCIDRs)
		if err != nil {
			return nil, fmt.Errorf("mtls: trusted_cidrs: %w", err)
		}

		s.proxyNets = nets
		s.certHeader = s.proxy.CertHeader
	}

	return s, nil
}

// Name returns the strategy's URL key.
func (s *Strategy) Name() string { return s.name }

// Descriptor returns the UI-facing description.
func (s *Strategy) Descriptor() strategy.Descriptor {
	return strategy.Descriptor{
		Name:     s.name,
		Kind:     "mtls",
		Label:    s.label,
		Priority: s.priority,
		Hidden:   s.hidden,
	}
}

// Login authenticates the request's client certificate and mints a session.
func (s *Strategy) Login(w http.ResponseWriter, r *http.Request) (*identity.Identity, strategy.Outcome, error) {
	id, err := s.AuthenticateRequest(r.Context(), r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "no_client_certificate", "a valid TLS client certificate is required")

		return nil, strategy.OutcomeFailed, nil
	}

	return id, strategy.OutcomeContinue, nil
}

// Logout is a no-op: a certificate cannot be revoked from here.
func (s *Strategy) Logout(_ context.Context, _ *identity.Identity) error { return nil }

// AuthenticateRequest implements strategy.RequestAuthenticator.
func (s *Strategy) AuthenticateRequest(ctx context.Context, r *http.Request) (*identity.Identity, error) {
	cert, err := s.certificate(r)
	if err != nil {
		return nil, err
	}

	// Validity is checked here even in native mode. crypto/tls verifies the
	// chain at handshake time, but a connection can outlive the leaf's
	// notAfter, and a keep-alive request on such a connection would otherwise
	// sail through with an expired certificate.
	now := s.now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, strategy.ErrInvalidCredentials
	}

	if s.verifier != nil {
		id, err := s.verifier(ctx, cert)
		if err != nil {
			return nil, err
		}

		if id == nil {
			return nil, strategy.ErrInvalidCredentials
		}

		id.Provider = s.name

		if id.IssuedAt.IsZero() {
			id.IssuedAt = now
		}

		return id, nil
	}

	return s.identityFromCert(cert, now), nil
}

// Challenge implements strategy.Challenger.
//
// There is no HTTP authentication scheme for mTLS — the credential lives in
// the transport. RFC 9110 still wants a scheme name on a 401, and naming a
// scheme the client cannot use would be worse than saying nothing, so this
// strategy contributes no challenge.
func (s *Strategy) Challenge() string { return "" }

// certificate extracts the client certificate for this request.
func (s *Strategy) certificate(r *http.Request) (*x509.Certificate, error) {
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
		// VerifiedChains, not PeerCertificates: the latter is whatever the
		// client sent, verified or not. With ClientAuth set to
		// RequestClientCert or VerifyClientCertIfGiven, PeerCertificates is
		// populated for certificates that failed validation too.
		return r.TLS.VerifiedChains[0][0], nil
	}

	if s.proxy == nil {
		return nil, strategy.ErrNoCredentials
	}

	if !s.fromTrustedProxy(r) {
		return nil, strategy.ErrNoCredentials
	}

	if s.proxy.VerifyHeader != "" {
		if !strings.EqualFold(r.Header.Get(s.proxy.VerifyHeader), s.proxy.VerifyValue) {
			return nil, strategy.ErrInvalidCredentials
		}
	}

	raw := r.Header.Get(s.certHeader)
	if raw == "" {
		return nil, strategy.ErrNoCredentials
	}

	cert, err := parseForwardedCert(raw)
	if err != nil {
		return nil, strategy.ErrInvalidCredentials
	}

	return cert, nil
}

// fromTrustedProxy checks the immediate peer, never X-Forwarded-For. The
// header being checked is exactly the kind of thing a spoofed forwarding chain
// is used to authorise.
func (s *Strategy) fromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, n := range s.proxyNets {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

// parseForwardedCert accepts the shapes proxies actually send: URL-encoded
// PEM (Traefik), raw PEM, or bare base64 DER (nginx with $ssl_client_escaped_cert
// variants).
func parseForwardedCert(raw string) (*x509.Certificate, error) {
	candidates := []string{strings.TrimSpace(raw)}

	// Percent-decode only when there is something to decode, and with
	// PathUnescape rather than QueryUnescape: the latter turns "+" into a
	// space, which silently corrupts every base64 body containing one.
	if strings.Contains(raw, "%") {
		if decoded, err := url.PathUnescape(raw); err == nil {
			candidates = append(candidates, strings.TrimSpace(decoded))
		}

		// And once more with "+" read as a space, which is what a proxy using
		// query-escaping produces for the spaces in "BEGIN CERTIFICATE".
		if decoded, err := url.QueryUnescape(raw); err == nil {
			candidates = append(candidates, strings.TrimSpace(decoded))
		}
	}

	var lastErr error

	for _, c := range candidates {
		cert, err := parseCertBlob(c)
		if err == nil {
			return cert, nil
		}

		lastErr = err
	}

	return nil, lastErr
}

func parseCertBlob(raw string) (*x509.Certificate, error) {
	if strings.Contains(raw, "BEGIN CERTIFICATE") {
		// Some proxies flatten the PEM onto one line.
		if !strings.Contains(raw, "\n") {
			raw = strings.ReplaceAll(raw, "-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")
			raw = strings.ReplaceAll(raw, "-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----")
		}

		block, _ := pem.Decode([]byte(raw))
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("mtls: no PEM certificate in header")
		}

		return x509.ParseCertificate(block.Bytes)
	}

	der, err := decodeBase64(raw)
	if err != nil {
		return nil, fmt.Errorf("mtls: decode forwarded certificate: %w", err)
	}

	return x509.ParseCertificate(der)
}

// identityFromCert is the no-verifier fallback.
func (s *Strategy) identityFromCert(cert *x509.Certificate, now time.Time) *identity.Identity {
	id := &identity.Identity{
		// The fingerprint, not the CN. A CN is not unique and not controlled
		// by anything: two CAs can happily issue "admin".
		Subject:  Fingerprint(cert),
		Name:     cert.Subject.CommonName,
		Provider: s.name,
		IssuedAt: now,
		Claims: map[string]any{
			"cert_subject":     cert.Subject.String(),
			"cert_issuer":      cert.Issuer.String(),
			"cert_serial":      cert.SerialNumber.String(),
			"cert_not_after":   cert.NotAfter.UTC().Format(time.RFC3339),
			"cert_fingerprint": Fingerprint(cert),
		},
	}

	if len(cert.EmailAddresses) > 0 {
		id.Email = cert.EmailAddresses[0]
	}

	if len(cert.Subject.OrganizationalUnit) > 0 {
		id.Roles = append([]string(nil), cert.Subject.OrganizationalUnit...)
	}

	return id
}

// Fingerprint returns the lowercase hex SHA-256 of the certificate's DER
// encoding — the same value as `openssl x509 -fingerprint -sha256`, minus the
// colons.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)

	return hex.EncodeToString(sum[:])
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

// decodeBase64 accepts standard and URL alphabets, padded or not. Proxies are
// not consistent about which they use.
func decodeBase64(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")

	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}

	return nil, fmt.Errorf("not base64")
}
