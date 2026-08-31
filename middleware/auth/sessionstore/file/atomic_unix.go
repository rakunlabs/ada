//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd

package file

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/rakunlabs/ada/middleware/auth/sessionstore"
)

var _ sessionstore.AtomicDirectStore = (*Store)(nil)

// TransactByID implements sessionstore.AtomicDirectStore. An advisory file lock
// serializes transactions for the same ID across Store instances and processes
// sharing the session directory. Non-positive TTLs retain the on-disk expiry.
func (s *Store) TransactByID(
	ctx context.Context,
	id string,
	ttl time.Duration,
	fn sessionstore.AtomicTransaction,
) (map[string]any, error) {
	if !safeID(id) {
		return nil, sessionstore.ErrNoSession
	}

	unlock, err := s.lockTransaction(ctx, id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, sessionstore.ErrNoSession
		}

		return nil, err
	}
	defer unlock()

	rec, err := s.liveRecordLocked(id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, sessionstore.ErrNoSession
		}

		return nil, err
	}

	replacement, commit, txErr := fn(recordValues(rec))
	if !commit {
		return nil, txErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if replacement == nil {
		if err := s.deleteLocked(id); err != nil {
			return nil, err
		}
	} else {
		rec.Values = replacement
		if ttl > 0 {
			rec.ExpiresAt = s.now().Add(ttl).Unix()
		}
		data, err := s.marshalRecordEnvelope(rec)
		if err != nil {
			return nil, err
		}
		if err := s.writeRecord(id, data); err != nil {
			return nil, err
		}
	}

	return replacement, txErr
}
