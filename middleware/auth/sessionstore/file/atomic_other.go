//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package file

import "context"

var processLockStripes = newProcessLockStripes()

func newProcessLockStripes() [transactionLockStripes]chan struct{} {
	var stripes [transactionLockStripes]chan struct{}
	for i := range stripes {
		stripes[i] = make(chan struct{}, 1)
		stripes[i] <- struct{}{}
	}

	return stripes
}

// lockTransaction provides process-local serialization on platforms where the
// file store does not expose cross-process atomic transactions.
func (s *Store) lockTransaction(ctx context.Context, id string) (func(), error) {
	lock := processLockStripes[transactionLockStripe(id)]
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-lock:
		return func() { lock <- struct{}{} }, nil
	}
}
