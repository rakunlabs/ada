package log

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// clientIP returns the canonical immediate peer address of r.
//
// Forwarding headers are never consulted. An attacker sets X-Forwarded-For as
// easily as any other header, so honouring it without a proxy boundary makes
// the logged address worthless. Deployments that terminate behind a proxy pass
// their own resolver to WithRealIP; github.com/rakunlabs/ada/middleware/auth/proxy
// provides one backed by explicit trusted CIDRs.
//
// A peer that is not an IP transport, a Unix socket for example, receives a
// stable bounded identity rather than an unbounded path.
func clientIP(r *http.Request) string {
	raw := strings.TrimSpace(r.RemoteAddr)

	if addr, err := peerAddr(raw); err == nil {
		return addr.String()
	}

	return boundedPeer(raw)
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
