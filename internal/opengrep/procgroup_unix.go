//go:build unix

package opengrep

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// killTree makes cmd lead a process group of its own, and cancelling its
// context kill that whole group. A terminal's Ctrl-C then reaches only the
// caller, which must catch it and cancel the context.
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

// textBusy reports whether err is a start that failed because the
// executable was open for writing.
func textBusy(err error) bool { return errors.Is(err, syscall.ETXTBSY) }
