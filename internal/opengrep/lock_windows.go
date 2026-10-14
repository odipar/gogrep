//go:build windows

package opengrep

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2

	errorLockViolation syscall.Errno = 33
)

// tryLock takes the exclusive lock on f's first byte without waiting, and
// reports whether it has it.
func tryLock(f *os.File) (bool, error) {
	var ol syscall.Overlapped
	r, _, err := procLockFileEx.Call(f.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	switch {
	case r != 0:
		return true, nil
	case errors.Is(err, errorLockViolation):
		return false, nil
	}
	return false, err
}

func unlockFile(f *os.File) error {
	var ol syscall.Overlapped
	if r, _, err := procUnlockFileEx.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ol))); r == 0 {
		return err
	}
	return nil
}
