//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd || windows)

package opengrep

import (
	"errors"
	"os"
)

// tryLock reports that this system has no file locks gogrep uses.
func tryLock(*os.File) (bool, error) { return false, errors.ErrUnsupported }

func unlockFile(*os.File) error { return nil }
