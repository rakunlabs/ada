package identity

import "context"

type ctxKey int

const ctxKeyIdentity ctxKey = iota

// WithContext returns a new context carrying the identity.
func WithContext(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, ctxKeyIdentity, id)
}

// FromContext returns the identity stored in ctx, or nil if none.
func FromContext(ctx context.Context) *Identity {
	if v, ok := ctx.Value(ctxKeyIdentity).(*Identity); ok {
		return v
	}

	return nil
}
