package backend

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/issuer"
)

// Namespace isolates one logical issuer inside a shared Backend. Session IDs
// exposed to callers remain unchanged; only storage keys and persisted
// Pair.SessionID values receive the namespace prefix.
//
// The separator is outside issuer.Default's base64url token alphabet, so a
// generated session ID cannot collide with a namespaced storage key.
type Namespace struct {
	backend issuer.Backend
	prefix  string
}

var _ issuer.AtomicBackend = (*Namespace)(nil)

// NewNamespace returns a backend view isolated under namespace.
func NewNamespace(backend issuer.Backend, namespace string) (*Namespace, error) {
	if backend == nil {
		return nil, fmt.Errorf("backend: nil namespace backend")
	}
	if namespace == "" || strings.ContainsAny(namespace, "~/\\.") {
		return nil, fmt.Errorf("backend: invalid namespace %q", namespace)
	}

	return &Namespace{backend: backend, prefix: namespace + "~"}, nil
}

func (n *Namespace) storageID(sessionID string) string {
	return n.prefix + sessionID
}

func (n *Namespace) toStoragePair(pair *issuer.Pair) (*issuer.Pair, error) {
	if pair == nil || pair.SessionID == "" {
		return nil, fmt.Errorf("backend: pair without session id")
	}

	stored := clonePair(pair)
	stored.SessionID = n.storageID(pair.SessionID)

	return stored, nil
}

func (n *Namespace) fromStoragePair(sessionID string, stored *issuer.Pair) (*issuer.Pair, error) {
	if stored == nil || stored.SessionID != n.storageID(sessionID) {
		return nil, fmt.Errorf("backend: namespaced pair does not match storage key")
	}

	pair := clonePair(stored)
	pair.SessionID = sessionID

	return pair, nil
}

// LoadPair implements issuer.Backend.
func (n *Namespace) LoadPair(ctx context.Context, sessionID string) (*issuer.Pair, error) {
	stored, err := n.backend.LoadPair(ctx, n.storageID(sessionID))
	if err != nil {
		return nil, err
	}

	return n.fromStoragePair(sessionID, stored)
}

// SavePair implements issuer.Backend.
func (n *Namespace) SavePair(ctx context.Context, pair *issuer.Pair, ttl time.Duration) error {
	stored, err := n.toStoragePair(pair)
	if err != nil {
		return err
	}

	return n.backend.SavePair(ctx, stored, ttl)
}

// DeletePair implements issuer.Backend.
func (n *Namespace) DeletePair(ctx context.Context, sessionID string) error {
	return n.backend.DeletePair(ctx, n.storageID(sessionID))
}

// AtomicTransactionsSupported preserves the wrapped backend's capability.
func (n *Namespace) AtomicTransactionsSupported() bool {
	atomic, ok := n.backend.(issuer.AtomicBackend)

	return ok && atomic.AtomicTransactionsSupported()
}

// TransactPair implements issuer.AtomicBackend while translating both the
// storage key and Pair.SessionID across the namespace boundary.
func (n *Namespace) TransactPair(
	ctx context.Context,
	sessionID string,
	ttl time.Duration,
	fn issuer.PairTransaction,
) (*issuer.Pair, error) {
	atomic, ok := n.backend.(issuer.AtomicBackend)
	if !ok || !atomic.AtomicTransactionsSupported() {
		return nil, fmt.Errorf("backend: atomic transactions unavailable")
	}

	stored, err := atomic.TransactPair(ctx, n.storageID(sessionID), ttl, func(current *issuer.Pair) (*issuer.Pair, bool, error) {
		pair, err := n.fromStoragePair(sessionID, current)
		if err != nil {
			return nil, false, err
		}

		replacement, commit, txErr := fn(pair)
		if !commit || replacement == nil {
			return nil, commit, txErr
		}
		if replacement.SessionID != sessionID {
			return nil, false, fmt.Errorf("backend: transaction changed session id")
		}

		next, err := n.toStoragePair(replacement)
		if err != nil {
			return nil, false, err
		}

		return next, true, txErr
	})
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, nil
	}

	return n.fromStoragePair(sessionID, stored)
}
