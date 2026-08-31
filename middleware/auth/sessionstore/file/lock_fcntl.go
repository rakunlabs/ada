//go:build aix || solaris

package file

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

var fcntlProcessLockStripes = newFcntlProcessLockStripes()

func newFcntlProcessLockStripes() [transactionLockStripes]chan struct{} {
	var stripes [transactionLockStripes]chan struct{}
	for i := range stripes {
		stripes[i] = make(chan struct{}, 1)
		stripes[i] <- struct{}{}
	}

	return stripes
}

func (s *Store) lockTransaction(ctx context.Context, id string) (func(), error) {
	processLock := fcntlProcessLockStripes[transactionLockStripe(id)]
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-processLock:
	}

	file, err := os.OpenFile(s.transactionLockPath(id), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		processLock <- struct{}{}

		return nil, err
	}

	lock := syscall.Flock_t{Type: syscall.F_WRLCK}
	for {
		err = syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &lock)
		if err == nil {
			return func() {
				unlock := syscall.Flock_t{Type: syscall.F_UNLCK}
				_ = syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &unlock)
				_ = file.Close()
				processLock <- struct{}{}
			}, nil
		}
		if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			processLock <- struct{}{}

			return nil, err
		}

		select {
		case <-ctx.Done():
			_ = file.Close()
			processLock <- struct{}{}

			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}
