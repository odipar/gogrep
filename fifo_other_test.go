//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package gogrep

import "errors"

// mkfifo reports that this system has no named pipes in the file system.
func mkfifo(string) error { return errors.ErrUnsupported }
