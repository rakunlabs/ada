//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package file

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
)

func (s *Store) lockTransaction(ctx context.Context, id string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(s.transactionLockPath(id), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}

	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()

			return nil, err
		}

		select {
		case <-ctx.Done():
			_ = file.Close()

			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}
