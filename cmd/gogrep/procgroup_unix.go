//go:build unix

package gogrep

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// interrupts are the signals that interrupt gogrep test. Since the opengrep
// processes are in process groups of their own, the signals a terminal sends
// its foreground group (Ctrl-C, Ctrl-\, a hangup) reach gogrep alone, which
// must catch them to kill those groups.
var interrupts = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

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
