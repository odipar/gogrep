//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package opengrep

import (
	"errors"
	"os"
	"syscall"
)

// tryLock takes the exclusive lock on f without waiting, and reports
// whether it has it.
func tryLock(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
