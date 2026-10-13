//go:build unix

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// killTree makes cancelling cmd's context kill cmd and every process it
// started: opengrep's launcher does not pass a kill on to opengrep-cli and
// opengrep-core, which would scan on. cmd leads a process group of its own,
// so Ctrl-C reaches only gogrep, which then kills the group.
func killTree(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}
