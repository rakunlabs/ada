package strategy

import (
	"github.com/rakunlabs/ada/middleware/auth/resource"
)

// ResourceBinder is an optional interface implemented by strategies that can
// point a client at this deployment's RFC 9728 protected resource metadata.
//
// The auth middleware calls SetProtectedResource once at Mount time with the
// server it publishes metadata from, so a strategy does not have to be handed
// the same instance by the caller. It mirrors CallbackBinder, including its
// contract: implementations MUST NOT overwrite an explicit, user-supplied
// value.
type ResourceBinder interface {
	SetProtectedResource(rs *resource.Server)
}
