//go:build !unix

package gogrep

import (
	"os"
	"syscall"
)

// interrupts are the signals that interrupt gogrep test: on Windows, Ctrl-C
// and Ctrl-Break arrive as os.Interrupt, and closing the console as SIGTERM.
var interrupts = []os.Signal{os.Interrupt, syscall.SIGTERM}
