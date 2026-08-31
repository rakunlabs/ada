//go:build windows

package file

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2
	errorLockViolation      = syscall.Errno(33)
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	lockFileExProc   = kernel32.NewProc("LockFileEx")
	unlockFileExProc = kernel32.NewProc("UnlockFileEx")
	windowsLocks     = newWindowsProcessLockStripes()
)

func newWindowsProcessLockStripes() [transactionLockStripes]chan struct{} {
	var stripes [transactionLockStripes]chan struct{}
	for i := range stripes {
		stripes[i] = make(chan struct{}, 1)
		stripes[i] <- struct{}{}
	}

	return stripes
}

func (s *Store) lockTransaction(ctx context.Context, id string) (func(), error) {
	processLock := windowsLocks[transactionLockStripe(id)]
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

	overlapped := new(syscall.Overlapped)
	for {
		result, _, callErr := lockFileExProc.Call(
			file.Fd(),
			lockfileFailImmediately|lockfileExclusiveLock,
			0,
			1,
			0,
			uintptr(unsafe.Pointer(overlapped)),
		)
		if result != 0 {
			return func() {
				_, _, _ = unlockFileExProc.Call(
					file.Fd(),
					0,
					1,
					0,
					uintptr(unsafe.Pointer(overlapped)),
				)
				_ = file.Close()
				processLock <- struct{}{}
			}, nil
		}
		if !errors.Is(callErr, errorLockViolation) {
			_ = file.Close()
			processLock <- struct{}{}

			return nil, callErr
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
