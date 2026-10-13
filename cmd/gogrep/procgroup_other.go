//go:build !unix && !windows

package gogrep

import (
	"os"
	"os/exec"
	"syscall"
)

// interrupts are the signals that interrupt gogrep test.
var interrupts = []os.Signal{os.Interrupt, syscall.SIGTERM}

// killTree leaves cmd as it is, so cancelling its context kills cmd alone.
// opengrep ships only for Linux, macOS and Windows; this keeps gogrep
// building for other systems.
func killTree(*exec.Cmd) {}
