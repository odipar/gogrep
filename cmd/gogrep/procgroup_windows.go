//go:build windows

package gogrep

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// interrupts are the signals that interrupt gogrep test: Ctrl-C and
// Ctrl-Break arrive as os.Interrupt, and closing the console as SIGTERM.
var interrupts = []os.Signal{os.Interrupt, syscall.SIGTERM}

// killTree makes cancelling cmd's context kill cmd and every process it
// started: opengrep's launcher does not pass a kill on to its children,
// which would scan on.
func killTree(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run() == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
}
