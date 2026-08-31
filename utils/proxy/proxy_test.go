package proxy_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rakunlabs/ada/utils/proxy"
)

func request(remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://internal.example/resource", nil)
	r.RemoteAddr = remote
	for name, value := range headers {
		r.Header.Set(name, value)
	}

	return r
}

func TestSafeClientIPIgnoresSpoofedHeaders(t *testing.T) {
	r := request("[2001:db8::1]:1234", map[string]string{
		"True-Client-IP":  "198.51.100.1",
		"X-Forwarded-For": "198.51.100.2",
		"X-Real-IP":       "198.51.100.3",
	})

	got, err := proxy.ClientIP(r)
	if err != nil {
		t.Fatalf("ClientIP: %v", err)
	}
	if got != "2001:db8::1" {
		t.Fatalf("ClientIP = %q, want immediate IPv6 peer", got)
	}
}

func TestNonIPPeersUseStableBoundedIdentity(t *testing.T) {
	tests := []struct {
		name   string
		remote string
		sameAs string
	}{
		{name: "Unix socket", remote: "/run/ada.sock", sameAs: "/run/ada.sock"},
		{name: "hostname ports", remote: "Internal.Example:1000", sameAs: "internal.example:2000"},
		{name: "scoped IPv6 ports", remote: "[fe80:0:0::1%eth0]:1000", sameAs: "[fe80::1%eth0]:2000"},
		{name: "scoped IPv6 without port", remote: "fe80:0:0::1%eth0", sameAs: "[fe80::1%eth0]:2000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := proxy.ClientIP(request(tt.remote, nil))
			if err != nil {
				t.Fatalf("ClientIP: %v", err)
			}
			other, err := proxy.ClientIP(request(tt.sameAs, nil))
			if err != nil {
				t.Fatalf("ClientIP equivalent peer: %v", err)
			}
			if got == "" || got != other {
				t.Fatalf("ClientIP identities = %q and %q, want same non-empty value", got, other)
			}
			if len(got) > 80 {
				t.Fatalf("ClientIP identity length = %d, want at most 80", len(got))
			}
		})
	}

	first, _ := proxy.ClientIP(request("/run/ada.sock", nil))
	second, _ := proxy.ClientIP(request("/run/other.sock", nil))
	if first == second {
		t.Fatal("different Unix socket peers received the same identity")
	}

	long, err := proxy.ClientIP(request(strings.Repeat("x", 4096), nil))
	if err != nil {
		t.Fatalf("long ClientIP: %v", err)
	}
	if long == "" || len(long) > 80 {
		t.Fatalf("long ClientIP identity length = %d, want non-empty and at most 80", len(long))
	}
}

func TestNonIPPeersCannotSupplyTrustedForwardingHeaders(t *testing.T) {
	p := proxy.MustNew("fe80::/10")
	for _, remote := range []string{"/run/ada.sock", "[fe80::1%eth0]:443"} {
		r := request(remote, map[string]string{"X-Real-IP": "198.51.100.8"})
		got, err := p.ClientIP(r)
		if err != nil {
			t.Fatalf("ClientIP(%q): %v", remote, err)
		}
		peer, err := proxy.ClientIP(request(remote, nil))
		if err != nil {
			t.Fatalf("safe ClientIP(%q): %v", remote, err)
		}
		if got != peer {
			t.Fatalf("ClientIP(%q) = %q, want immediate peer identity %q", remote, got, peer)
		}
	}
}

func TestUntrustedPeerHeadersAreIgnored(t *testing.T) {
	p := proxy.MustNew("10.0.0.0/8")
	r := request("203.0.113.9:1234", map[string]string{
		"True-Client-IP":  "not-an-ip",
		"X-Forwarded-For": "198.51.100.8, 10.2.3.4",
	})

	got, err := p.ClientIP(r)
	if err != nil {
		t.Fatalf("ClientIP: %v", err)
	}
	if got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want untrusted immediate peer", got)
	}
}

func TestTrustedProxyWalksForwardedForRightToLeft(t *testing.T) {
	p := proxy.MustNew("10.0.0.0/8", "2001:db8:ffff::/48")
	tests := []struct {
		name   string
		remote string
		xff    string
		want   string
	}{
		{
			name:   "spoofed prefix before client",
			remote: "10.0.0.3:443",
			xff:    "192.0.2.99, 198.51.100.7, 10.0.0.2",
			want:   "198.51.100.7",
		},
		{
			name:   "IPv6 chain",
			remote: "[2001:db8:ffff::3]:443",
			xff:    "2001:db8:1234::7, 2001:db8:ffff::2",
			want:   "2001:db8:1234::7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := p.ClientIP(request(tt.remote, map[string]string{"X-Forwarded-For": tt.xff}))
			if err != nil {
				t.Fatalf("ClientIP: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ClientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTrustedProxyPrefersValidatedForwardedChain(t *testing.T) {
	p := proxy.MustNew("10.0.0.0/8")
	r := request("10.0.0.3:443", map[string]string{
		"True-Client-IP":  "192.0.2.99",
		"X-Real-IP":       "192.0.2.98",
		"X-Forwarded-For": "198.51.100.7, 10.0.0.2",
	})

	got, err := p.ClientIP(r)
	if err != nil {
		t.Fatalf("ClientIP: %v", err)
	}
	if got != "198.51.100.7" {
		t.Fatalf("ClientIP = %q, want validated X-Forwarded-For client", got)
	}
}

func TestTrustedSingleIPHeadersAreCanonicalized(t *testing.T) {
	p := proxy.MustNew("10.0.0.0/8")
	r := request("10.0.0.1:443", map[string]string{"True-Client-IP": "::ffff:192.0.2.8"})

	got, err := p.ClientIP(r)
	if err != nil {
		t.Fatalf("ClientIP: %v", err)
	}
	if got != "192.0.2.8" {
		t.Fatalf("ClientIP = %q", got)
	}
}

func TestMalformedForwardingValuesAreRejected(t *testing.T) {
	p := proxy.MustNew("10.0.0.0/8")
	for name, headers := range map[string]map[string]string{
		"bad true client": {"True-Client-IP": "192.0.2.1:80"},
		"empty XFF hop":   {"X-Forwarded-For": "198.51.100.1, , 10.0.0.2"},
		"bad XFF hop":     {"X-Forwarded-For": "unknown, 10.0.0.2"},
		"all trusted":     {"X-Forwarded-For": "10.0.0.2, 10.0.0.3"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := p.ClientIP(request("10.0.0.1:443", headers)); err == nil {
				t.Fatal("malformed forwarding value was accepted")
			}
		})
	}
}

func TestTrustedCIDRsValidateAtSetup(t *testing.T) {
	for _, cidr := range []string{"", " 10.0.0.0/8", "10.0.0.0/99", "not-an-ip"} {
		if _, err := proxy.New(cidr); err == nil {
			t.Errorf("New(%q) succeeded", cidr)
		}
	}

	p, err := proxy.New("192.0.2.8", "2001:db8::/32")
	if err != nil {
		t.Fatalf("valid CIDRs: %v", err)
	}
	if !p.TrustedPeer(request("192.0.2.8:80", nil)) || !p.TrustedPeer(request("[2001:db8::8]:80", nil)) {
		t.Fatal("bare IPv4 or IPv6 CIDR did not match")
	}
}

func TestOriginUsesForwardingOnlyForTrustedPeer(t *testing.T) {
	p := proxy.MustNew("10.0.0.0/8")
	headers := map[string]string{
		"X-Forwarded-Host":  "Public.Example:8443",
		"X-Forwarded-Proto": "https",
	}

	trusted, err := p.Origin(request("10.0.0.1:443", headers))
	if err != nil {
		t.Fatalf("trusted origin: %v", err)
	}
	if trusted.String() != "https://public.example:8443" {
		t.Fatalf("trusted origin = %q", trusted.String())
	}

	untrusted, err := p.Origin(request("203.0.113.1:443", headers))
	if err != nil {
		t.Fatalf("untrusted origin: %v", err)
	}
	if untrusted.String() != "http://internal.example" {
		t.Fatalf("untrusted origin = %q", untrusted.String())
	}
}

func TestOriginCanonicalizesIPv6AndRejectsMalformedForwarding(t *testing.T) {
	p := proxy.MustNew("2001:db8::/32")
	r := request("[2001:db8::1]:443", map[string]string{
		"X-Forwarded-Host":  "[2001:0db8:0:0::8]:8443",
		"X-Forwarded-Proto": "https",
	})
	origin, err := p.Origin(r)
	if err != nil {
		t.Fatalf("Origin: %v", err)
	}
	if origin.String() != "https://[2001:db8::8]:8443" {
		t.Fatalf("origin = %q", origin.String())
	}

	for name, headers := range map[string]map[string]string{
		"bad scheme": {"X-Forwarded-Proto": "javascript", "X-Forwarded-Host": "public.example"},
		"proto list": {"X-Forwarded-Proto": "https, http", "X-Forwarded-Host": "public.example"},
		"host list":  {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "public.example, evil.example"},
		"userinfo":   {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "user@public.example"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := p.Origin(request("[2001:db8::1]:443", headers)); err == nil {
				t.Fatal("malformed origin was accepted")
			}
		})
	}
}

func TestUnsafeCompatibilityHelpers(t *testing.T) {
	r := request("203.0.113.1:443", map[string]string{
		"X-Forwarded-For":   "198.51.100.8, 10.0.0.2",
		"X-Forwarded-Host":  "public.example",
		"X-Forwarded-Proto": "https",
	})
	r.TLS = &tls.ConnectionState{}

	ip, err := proxy.UnsafeClientIP(r)
	if err != nil || ip != "198.51.100.8" {
		t.Fatalf("UnsafeClientIP = %q, %v", ip, err)
	}
	origin, err := proxy.UnsafeOrigin(r)
	if err != nil || origin.String() != "https://public.example" {
		t.Fatalf("UnsafeOrigin = %q, %v", origin.String(), err)
	}
}
