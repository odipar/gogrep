//go:build !unix && !windows

package opengrep

import (
	"os"
	"os/exec"
)

// killTree leaves cmd as it is, so cancelling its context kills cmd alone.
// opengrep ships only for Linux, macOS and Windows; this keeps gogrep
// building for other systems.
func killTree(*exec.Cmd) (reap func()) { return func() {} }

// SignalGroup sends sig to p alone: gogrep uses no process groups on this
// system.
func SignalGroup(p *os.Process, sig os.Signal) error { return p.Signal(sig) }

// textBusy reports whether err is a start that failed because the
// executable was open for writing.
func textBusy(error) bool { return false }
