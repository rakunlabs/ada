package proxy

import (
	"fmt"
	"net/http"
)

// TrustedRealIP returns a client IP resolver backed by validated trusted proxy
// CIDRs. It panics if a CIDR is malformed, so a deployment mistake surfaces at
// startup rather than as a silently permissive trust boundary under load.
//
// It exists to be handed to middleware that need a client IP but hold no proxy
// policy themselves:
//
//	mlog.New(mlog.WithRealIP(proxy.TrustedRealIP("10.0.0.0/8")))
//	ratelimit.LimitByKey(100, time.Minute, proxy.TrustedRealIP("10.0.0.0/8"))
//	telemetry.Middleware(telemetry.WithClientIP(proxy.TrustedRealIP("10.0.0.0/8")))
//
// A malformed forwarding header yields the immediate peer rather than an error
// or an empty string. Callers use the result as a log field or a limiter key,
// and both are worse off with a hole in them than with a coarser value.
func TrustedRealIP(cidrs ...string) func(*http.Request) string {
	policy, err := New(cidrs...)
	if err != nil {
		panic(fmt.Errorf("proxy: trusted proxies: %w", err))
	}

	return func(r *http.Request) string {
		if ip, err := policy.ClientIP(r); err == nil {
			return ip
		}

		return RealIP(r)
	}
}

// UnsafeRealIP trusts common client IP forwarding headers from every peer.
//
// It is only correct when the trust boundary is enforced outside the process,
// so that nothing unvetted can reach this port. Prefer TrustedRealIP, which
// states the boundary in code where it can be checked.
func UnsafeRealIP(r *http.Request) string {
	if ip, err := UnsafeClientIP(r); err == nil {
		return ip
	}

	return RealIP(r)
}

// RealIP returns the canonical immediate peer address, ignoring all forwarding
// headers. It is the safe default when no proxy boundary is configured.
func RealIP(r *http.Request) string {
	ip, _ := ClientIP(r)

	return ip
}
