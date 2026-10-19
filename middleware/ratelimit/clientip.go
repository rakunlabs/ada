package ratelimit

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// DefaultIPv6Prefix is the prefix length IPv6 clients are aggregated to when
// keyed by address. A single subscriber is routinely delegated a whole /64, so
// keying on the full address would let one client rotate through 2^64
// identities and both bypass the limit and grow the key space without bound.
const DefaultIPv6Prefix = 64

// clientKey returns the limiter key for the immediate peer of r: the
// canonical IPv4 address, or the IPv6 network of length ipv6Prefix.
//
// Forwarding headers are never consulted. An attacker who can set
// X-Forwarded-For would otherwise mint a fresh limiter key per request and
// defeat the limiter entirely. Deployments that terminate behind a proxy pass
// their own resolver to LimitByKey; github.com/rakunlabs/ada/middleware/auth/proxy
// provides one backed by explicit trusted CIDRs.
//
// A peer that is not an IP transport, a Unix socket for example, receives a
// stable bounded identity so it can never grow the limiter's key space without
// bound.
func clientKey(r *http.Request, ipv6Prefix int) string {
	raw := strings.TrimSpace(r.RemoteAddr)

	if addr, err := peerAddr(raw); err == nil {
		return addrKey(addr, ipv6Prefix)
	}

	return boundedPeer(raw)
}

// addrKey keys an unmapped address. IPv4 addresses, including 4-in-6 forms
// already unmapped by the caller, are always kept whole; IPv6 addresses are
// masked to ipv6Prefix and rendered in CIDR form.
func addrKey(addr netip.Addr, ipv6Prefix int) string {
	if addr.Is4() || ipv6Prefix >= 128 {
		return addr.String()
	}

	prefix, err := addr.Prefix(ipv6Prefix)
	if err != nil {
		return addr.String()
	}

	return prefix.String()
}

// maskIPKey applies the IPv6 prefix to a key that is a bare IP address, as
// returned by proxy-aware resolvers. Any other key is returned unchanged.
func maskIPKey(key string, ipv6Prefix int) string {
	addr, err := netip.ParseAddr(key)
	if err != nil || addr.Zone() != "" {
		return key
	}

	return addrKey(addr.Unmap(), ipv6Prefix)
}

// peerAddr parses RemoteAddr into a canonical address: 4-in-6 forms are
// unmapped so a single client cannot present as two identities, and scoped
// addresses are rejected because the zone is meaningless off this host.
func peerAddr(raw string) (netip.Addr, error) {
	if addrPort, err := netip.ParseAddrPort(raw); err == nil {
		if addr := addrPort.Addr(); addr.IsValid() && addr.Zone() == "" {
			return addr.Unmap(), nil
		}
	}

	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.IsValid() || addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid RemoteAddr %q", raw)
	}

	return addr.Unmap(), nil
}

// boundedPeer maps a non-IP peer to a stable fixed-length identity. The value
// is normalised before hashing so that equivalent spellings of the same peer
// collapse to one identity.
func boundedPeer(raw string) string {
	identity := raw

	switch {
	case isAddrPort(raw):
		addrPort, _ := netip.ParseAddrPort(raw)
		identity = addrPort.Addr().Unmap().String()
	case isAddr(raw):
		addr, _ := netip.ParseAddr(raw)
		identity = addr.Unmap().String()
	case !strings.ContainsRune(raw, '/') && !strings.HasPrefix(raw, "@"):
		if host, ok := splitHostPortLower(raw); ok {
			identity = host
		}
	}

	return fmt.Sprintf("peer:%x", sha256.Sum256([]byte(identity)))
}

func isAddrPort(raw string) bool {
	_, err := netip.ParseAddrPort(raw)

	return err == nil
}

func isAddr(raw string) bool {
	_, err := netip.ParseAddr(raw)

	return err == nil
}

func splitHostPortLower(raw string) (string, bool) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", false
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", false
	}

	host = strings.ToLower(host)
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.Unmap().String()
	}

	return host, true
}
