//go:build unix

package gogrep

import (
	"os"
	"syscall"
)

// interrupts are the signals that interrupt gogrep test. Since the opengrep
// processes are in process groups of their own, the signals a terminal sends
// its foreground group (Ctrl-C, Ctrl-\, a hangup) reach gogrep alone, which
// must catch them to kill those groups.
var interrupts = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}
