// Package proxy derives request metadata across an explicitly configured
// trusted-proxy boundary.
package proxy

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const (
	headerTrueClientIP    = "True-Client-IP"
	headerXForwardedFor   = "X-Forwarded-For"
	headerXForwardedHost  = "X-Forwarded-Host"
	headerXForwardedProto = "X-Forwarded-Proto"
	headerXRealIP         = "X-Real-IP"
)

// Policy identifies the network peers allowed to supply forwarding headers.
// Its zero value is safe and ignores all forwarding headers.
type Policy struct {
	trusted []netip.Prefix
}

// Origin is a validated HTTP origin.
type Origin struct {
	Scheme string
	Host   string
}

// String returns the canonical origin URL without a trailing slash.
func (o Origin) String() string {
	return (&url.URL{Scheme: o.Scheme, Host: o.Host}).String()
}

// New validates trusted proxy CIDRs and returns an immutable policy. Bare IPs
// are accepted as single-address prefixes.
func New(trustedCIDRs ...string) (Policy, error) {
	p := Policy{trusted: make([]netip.Prefix, 0, len(trustedCIDRs))}
	for _, raw := range trustedCIDRs {
		prefix, err := parsePrefix(raw)
		if err != nil {
			return Policy{}, fmt.Errorf("trusted CIDR %q: %w", raw, err)
		}

		p.trusted = append(p.trusted, prefix)
	}

	return p, nil
}

// MustNew is like New but panics if any trusted CIDR is invalid.
func MustNew(trustedCIDRs ...string) Policy {
	p, err := New(trustedCIDRs...)
	if err != nil {
		panic(err)
	}

	return p
}

// TrustedPeer reports whether the request's immediate network peer is trusted.
// Forwarding headers never participate in this decision.
func (p Policy) TrustedPeer(r *http.Request) bool {
	peer, err := peerIP(r.RemoteAddr)
	return err == nil && p.contains(peer)
}

// ClientIP derives the client address directly from RemoteAddr and ignores all
// forwarding headers. A non-IP transport receives a stable, bounded identity.
func ClientIP(r *http.Request) (string, error) {
	return Policy{}.ClientIP(r)
}

// ClientIP derives the canonical client address. If the immediate peer is
// trusted, X-Forwarded-For is walked from right to left until the first
// untrusted hop. Single-address headers are considered only when X-Forwarded-For
// is absent. Otherwise, all forwarding headers are ignored. Non-IP transports
// cannot be trusted and receive a stable, bounded identity instead.
func (p Policy) ClientIP(r *http.Request) (string, error) {
	peer, err := peerIP(r.RemoteAddr)
	if err != nil {
		// RemoteAddr can legitimately identify a non-IP transport, such as a
		// Unix socket. Keep it useful as a bounded identity without allowing
		// such peers to cross the trusted-proxy boundary.
		return peerFallback(r.RemoteAddr), nil
	}
	if !p.contains(peer) {
		return peer.String(), nil
	}

	hops, ok, err := forwardedFor(r.Header)
	if err != nil {
		return "", err
	}
	if ok {
		for i := len(hops) - 1; i >= 0; i-- {
			if !p.contains(hops[i]) {
				return hops[i].String(), nil
			}
		}

		return "", fmt.Errorf("%s contains no untrusted client hop", headerXForwardedFor)
	}

	if raw, ok, err := singleHeader(r.Header, headerTrueClientIP); err != nil {
		return "", err
	} else if ok {
		return forwardedIP(headerTrueClientIP, raw)
	}

	if raw, ok, err := singleHeader(r.Header, headerXRealIP); err != nil {
		return "", err
	} else if ok {
		return forwardedIP(headerXRealIP, raw)
	}

	return peer.String(), nil
}

// UnsafeClientIP trusts common forwarding headers from any peer. It exists for
// compatibility with deployments that enforce their proxy boundary outside
// the process. New code should use a Policy with explicit trusted CIDRs.
func UnsafeClientIP(r *http.Request) (string, error) {
	if raw, ok, err := singleHeader(r.Header, headerTrueClientIP); err != nil {
		return "", err
	} else if ok {
		return forwardedIP(headerTrueClientIP, raw)
	}

	if raw, ok, err := singleHeader(r.Header, headerXRealIP); err != nil {
		return "", err
	} else if ok {
		return forwardedIP(headerXRealIP, raw)
	}

	hops, ok, err := forwardedFor(r.Header)
	if err != nil {
		return "", err
	}
	if ok {
		return hops[0].String(), nil
	}

	return ClientIP(r)
}

// Origin derives and validates the request origin. Forwarded host and protocol
// are considered only when the immediate peer is trusted.
func (p Policy) Origin(r *http.Request) (Origin, error) {
	trusted := false
	if len(p.trusted) > 0 {
		peer, err := peerIP(r.RemoteAddr)
		if err != nil {
			return Origin{}, err
		}
		trusted = p.contains(peer)
	}

	return requestOrigin(r, trusted)
}

// UnsafeOrigin derives and validates the request origin while trusting
// forwarded host and protocol from any peer.
func UnsafeOrigin(r *http.Request) (Origin, error) {
	return requestOrigin(r, true)
}

// ParseOrigin validates an absolute HTTP(S) origin containing only a scheme
// and host. A single trailing slash is accepted and removed.
func ParseOrigin(raw string) (Origin, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return Origin{}, fmt.Errorf("origin must not be empty or surrounded by whitespace")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return Origin{}, fmt.Errorf("parse origin: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Host == "" {
		return Origin{}, fmt.Errorf("origin must be absolute HTTP(S)")
	}
	if u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return Origin{}, fmt.Errorf("origin must contain only scheme and host")
	}

	host, err := canonicalHost(u.Host)
	if err != nil {
		return Origin{}, err
	}

	return Origin{Scheme: scheme, Host: host}, nil
}

func requestOrigin(r *http.Request, trustForwarded bool) (Origin, error) {
	scheme := "http"
	if r.URL != nil && r.URL.Scheme != "" {
		scheme = strings.ToLower(r.URL.Scheme)
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host

	if trustForwarded {
		if raw, ok, err := singleHeader(r.Header, headerXForwardedProto); err != nil {
			return Origin{}, err
		} else if ok {
			scheme = strings.ToLower(strings.TrimSpace(raw))
		}

		if raw, ok, err := singleHeader(r.Header, headerXForwardedHost); err != nil {
			return Origin{}, err
		} else if ok {
			host = strings.TrimSpace(raw)
		}
	}

	return ParseOrigin(scheme + "://" + host)
}

func parsePrefix(raw string) (netip.Prefix, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return netip.Prefix{}, fmt.Errorf("must not be empty or surrounded by whitespace")
	}

	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return canonicalPrefix(prefix)
	}

	addr, err := parseAddr(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP prefix")
	}

	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func canonicalPrefix(prefix netip.Prefix) (netip.Prefix, error) {
	addr := prefix.Addr()
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("zones are not valid in a trusted CIDR")
	}
	if addr.Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("IPv4-mapped prefix is broader than IPv4")
		}
		return netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96).Masked(), nil
	}

	return prefix.Masked(), nil
}

func peerIP(remoteAddr string) (netip.Addr, error) {
	raw := strings.TrimSpace(remoteAddr)
	if addrPort, err := netip.ParseAddrPort(raw); err == nil {
		addr, err := canonicalAddr(addrPort.Addr())
		if err == nil {
			return addr, nil
		}
	}

	addr, err := parseAddr(raw)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid RemoteAddr %q", remoteAddr)
	}

	return addr, nil
}

func peerFallback(remoteAddr string) string {
	identity := strings.TrimSpace(remoteAddr)
	if addrPort, err := netip.ParseAddrPort(identity); err == nil {
		identity = addrPort.Addr().Unmap().String()
	} else if addr, err := netip.ParseAddr(identity); err == nil {
		identity = addr.Unmap().String()
	} else if !strings.ContainsRune(identity, '/') && !strings.HasPrefix(identity, "@") {
		host, port, err := net.SplitHostPort(identity)
		if err == nil {
			_, err = strconv.ParseUint(port, 10, 16)
		}
		if err == nil {
			identity = strings.ToLower(host)
			if addr, err := netip.ParseAddr(identity); err == nil {
				identity = addr.Unmap().String()
			}
		}
	}

	return fmt.Sprintf("peer:%x", sha256.Sum256([]byte(identity)))
}

func forwardedIP(header, raw string) (string, error) {
	addr, err := parseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid %s value %q", header, raw)
	}

	return addr.String(), nil
}

func forwardedFor(header http.Header) ([]netip.Addr, bool, error) {
	values := header.Values(headerXForwardedFor)
	if len(values) == 0 {
		return nil, false, nil
	}

	hops := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		for _, raw := range strings.Split(value, ",") {
			addr, err := parseAddr(strings.TrimSpace(raw))
			if err != nil {
				return nil, true, fmt.Errorf("invalid %s value %q", headerXForwardedFor, raw)
			}
			hops = append(hops, addr)
		}
	}

	return hops, true, nil
}

func singleHeader(header http.Header, name string) (string, bool, error) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 || strings.Contains(values[0], ",") || strings.TrimSpace(values[0]) == "" {
		return "", true, fmt.Errorf("invalid %s value", name)
	}

	return values[0], true, nil
}

func parseAddr(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, err
	}

	return canonicalAddr(addr)
}

func canonicalAddr(addr netip.Addr) (netip.Addr, error) {
	if !addr.IsValid() || addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid IP address")
	}

	return addr.Unmap(), nil
}

func (p Policy) contains(addr netip.Addr) bool {
	for _, prefix := range p.trusted {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

func canonicalHost(raw string) (string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return "", fmt.Errorf("origin host must not be empty or surrounded by whitespace")
	}
	for i := range len(raw) {
		if raw[i] <= 0x20 || raw[i] >= 0x7f || strings.ContainsRune("\\/?#@,", rune(raw[i])) {
			return "", fmt.Errorf("origin host %q is invalid", raw)
		}
	}

	host := raw
	port := ""
	if strings.HasPrefix(raw, "[") {
		end := strings.IndexByte(raw, ']')
		if end < 0 {
			return "", fmt.Errorf("origin host %q is invalid", raw)
		}
		host = raw[1:end]
		rest := raw[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", fmt.Errorf("origin host %q is invalid", raw)
			}
			port = rest[1:]
		}

		addr, err := parseAddr(host)
		if err != nil || !addr.Is6() {
			return "", fmt.Errorf("origin host %q is not a valid IPv6 address", raw)
		}
		host = "[" + addr.String() + "]"
	} else {
		if strings.Count(raw, ":") > 1 {
			return "", fmt.Errorf("IPv6 origin hosts must be bracketed")
		}
		if before, after, ok := strings.Cut(raw, ":"); ok {
			host, port = before, after
		}
		if addr, err := parseAddr(host); err == nil {
			host = addr.String()
		} else {
			var err error
			host, err = canonicalHostname(host)
			if err != nil {
				return "", err
			}
		}
	}

	if port != "" {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return "", fmt.Errorf("origin port %q is invalid", port)
		}
		return host + ":" + port, nil
	}
	if strings.HasSuffix(raw, ":") {
		return "", fmt.Errorf("origin port is empty")
	}

	return host, nil
}

func canonicalHostname(host string) (string, error) {
	if host == "" || len(host) > 253 {
		return "", fmt.Errorf("origin hostname %q is invalid", host)
	}

	name := strings.TrimSuffix(host, ".")
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("origin hostname %q is invalid", host)
		}
		for i := range len(label) {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return "", fmt.Errorf("origin hostname %q is invalid", host)
			}
		}
	}

	return strings.ToLower(host), nil
}
