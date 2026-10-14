//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package gogrep

import "syscall"

// mkfifo creates a named pipe, a special file, at path.
func mkfifo(path string) error { return syscall.Mkfifo(path, 0o600) }
