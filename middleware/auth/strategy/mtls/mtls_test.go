package mtls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/identity"
	"github.com/rakunlabs/ada/middleware/auth/strategy"
	"github.com/rakunlabs/ada/middleware/auth/strategy/mtls"
)

func makeCert(t *testing.T, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(42),
		Subject:        pkix.Name{CommonName: cn, OrganizationalUnit: []string{"eng"}},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		EmailAddresses: []string{cn + "@example.com"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	return cert
}

func validCert(t *testing.T) *x509.Certificate {
	return makeCert(t, "alice", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func nativeRequest(cert *x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{cert}},
	}

	return r
}

func TestNativeIdentityFromCert(t *testing.T) {
	s, err := mtls.New("mtls", nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	cert := validCert(t)

	id, err := s.AuthenticateRequest(context.Background(), nativeRequest(cert))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	// The fingerprint, not the CN: a CN is neither unique nor authoritative.
	if id.Subject != mtls.Fingerprint(cert) {
		t.Errorf("subject = %q", id.Subject)
	}

	if id.Name != "alice" || id.Email != "alice@example.com" {
		t.Errorf("identity = %+v", id)
	}

	if len(id.Roles) != 1 || id.Roles[0] != "eng" {
		t.Errorf("roles = %v", id.Roles)
	}
}

// PeerCertificates holds whatever the client sent, verified or not. Only
// VerifiedChains means the standard library validated it.
func TestUnverifiedPeerCertificateIsIgnored(t *testing.T) {
	s, _ := mtls.New("mtls", nil)

	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{validCert(t)},
	}

	if _, err := s.AuthenticateRequest(context.Background(), r); !errors.Is(err, strategy.ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials", err)
	}
}

func TestExpiredCertificateIsRejected(t *testing.T) {
	s, _ := mtls.New("mtls", nil)

	expired := makeCert(t, "alice", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))

	if _, err := s.AuthenticateRequest(context.Background(), nativeRequest(expired)); !errors.Is(err, strategy.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestNoCertificateIsNoCredentials(t *testing.T) {
	s, _ := mtls.New("mtls", nil)

	r := httptest.NewRequest(http.MethodGet, "/private", nil)

	if _, err := s.AuthenticateRequest(context.Background(), r); !errors.Is(err, strategy.ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials", err)
	}
}

func TestVerifierIsConsulted(t *testing.T) {
	want := &identity.Identity{Subject: "service-a", Roles: []string{"writer"}}

	s, _ := mtls.New("mtls", func(_ context.Context, cert *x509.Certificate) (*identity.Identity, error) {
		if cert.Subject.CommonName != "alice" {
			return nil, strategy.ErrInvalidCredentials
		}

		return want, nil
	})

	id, err := s.AuthenticateRequest(context.Background(), nativeRequest(validCert(t)))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	if id.Subject != "service-a" || id.Provider != "mtls" {
		t.Fatalf("identity = %+v", id)
	}

	// An unknown certificate is rejected by the verifier.
	other := makeCert(t, "mallory", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	if _, err := s.AuthenticateRequest(context.Background(), nativeRequest(other)); !errors.Is(err, strategy.ErrInvalidCredentials) {
		t.Fatalf("err = %v", err)
	}
}

func TestProxyModeRequiresTrustedCIDRs(t *testing.T) {
	if _, err := mtls.New("mtls", nil, mtls.WithProxy(mtls.ProxyConfig{})); err == nil {
		t.Fatal("proxy mode without trusted CIDRs must not be constructible")
	}

	if _, err := mtls.New("mtls", nil, mtls.WithProxy(mtls.ProxyConfig{
		TrustedCIDRs: []string{"garbage"},
	})); err == nil {
		t.Fatal("a bad CIDR must be reported")
	}
}

func proxyRequest(cert *x509.Certificate, remote string, encode func(*x509.Certificate) string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.RemoteAddr = remote
	r.Header.Set("X-Forwarded-Tls-Client-Cert", encode(cert))
	r.Header.Set("X-Forwarded-Tls-Client-Cert-Info", "SUCCESS")

	return r
}

func pemEncoded(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func urlEncodedPEM(cert *x509.Certificate) string {
	return url.QueryEscape(pemEncoded(cert))
}

func bareBase64(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

func TestProxyModeAcceptsEveryCommonEncoding(t *testing.T) {
	s, err := mtls.New("mtls", nil, mtls.WithProxy(mtls.ProxyConfig{
		TrustedCIDRs: []string{"10.0.0.0/8"},
		VerifyHeader: "X-Forwarded-Tls-Client-Cert-Info",
	}))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	cert := validCert(t)

	for name, enc := range map[string]func(*x509.Certificate) string{
		"pem":      pemEncoded,
		"url-pem":  urlEncodedPEM,
		"bare-b64": bareBase64,
	} {
		id, err := s.AuthenticateRequest(context.Background(), proxyRequest(cert, "10.1.2.3:9000", enc))
		if err != nil {
			t.Errorf("%s: %v", name, err)

			continue
		}

		if id.Subject != mtls.Fingerprint(cert) {
			t.Errorf("%s: subject = %q", name, id.Subject)
		}
	}
}

func TestProxyModeRejectsUntrustedPeer(t *testing.T) {
	s, _ := mtls.New("mtls", nil, mtls.WithProxy(mtls.ProxyConfig{
		TrustedCIDRs: []string{"10.0.0.0/8"},
	}))

	r := proxyRequest(validCert(t), "203.0.113.9:9000", pemEncoded)

	if _, err := s.AuthenticateRequest(context.Background(), r); !errors.Is(err, strategy.ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials", err)
	}
}

func TestProxyModeRequiresVerifyHeaderWhenConfigured(t *testing.T) {
	s, _ := mtls.New("mtls", nil, mtls.WithProxy(mtls.ProxyConfig{
		TrustedCIDRs: []string{"10.0.0.0/8"},
		VerifyHeader: "X-Forwarded-Tls-Client-Cert-Info",
	}))

	r := proxyRequest(validCert(t), "10.1.2.3:9000", pemEncoded)
	r.Header.Set("X-Forwarded-Tls-Client-Cert-Info", "FAILED")

	if _, err := s.AuthenticateRequest(context.Background(), r); !errors.Is(err, strategy.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestProxyModeRejectsGarbageCertificate(t *testing.T) {
	s, _ := mtls.New("mtls", nil, mtls.WithProxy(mtls.ProxyConfig{
		TrustedCIDRs: []string{"10.0.0.0/8"},
	}))

	r := httptest.NewRequest(http.MethodGet, "/private", nil)
	r.RemoteAddr = "10.1.2.3:9000"
	r.Header.Set("X-Forwarded-Tls-Client-Cert", "not-a-certificate!!!")

	if _, err := s.AuthenticateRequest(context.Background(), r); !errors.Is(err, strategy.ErrInvalidCredentials) {
		t.Fatalf("err = %v", err)
	}
}

func TestNativeTakesPrecedenceOverForwardedHeader(t *testing.T) {
	s, _ := mtls.New("mtls", nil, mtls.WithProxy(mtls.ProxyConfig{
		TrustedCIDRs: []string{"10.0.0.0/8"},
	}))

	real := validCert(t)
	forged := makeCert(t, "mallory", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	r := nativeRequest(real)
	r.RemoteAddr = "10.1.2.3:9000"
	r.Header.Set("X-Forwarded-Tls-Client-Cert", pemEncoded(forged))

	id, err := s.AuthenticateRequest(context.Background(), r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	if id.Subject != mtls.Fingerprint(real) {
		t.Fatal("a forwarded header must not override a real TLS certificate")
	}
}

func TestLoginMintsSession(t *testing.T) {
	s, _ := mtls.New("mtls", nil)

	rec := httptest.NewRecorder()

	id, outcome, err := s.Login(rec, nativeRequest(validCert(t)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if outcome != strategy.OutcomeContinue || id == nil {
		t.Fatalf("outcome = %v", outcome)
	}

	rec = httptest.NewRecorder()

	_, outcome, _ = s.Login(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if outcome != strategy.OutcomeFailed {
		t.Fatal("a request without a certificate must fail")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("code = %d", rec.Code)
	}
}

// mTLS has no HTTP authentication scheme, so it contributes no challenge.
func TestNoChallenge(t *testing.T) {
	s, _ := mtls.New("mtls", nil)

	if got := s.Challenge(); got != "" {
		t.Errorf("challenge = %q, want empty", got)
	}
}

var _ strategy.RequestAuthenticator = (*mtls.Strategy)(nil)
