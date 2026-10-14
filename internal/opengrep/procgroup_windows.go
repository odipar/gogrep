//go:build windows

package opengrep

import (
	"os"
	"os/exec"
	"strconv"
)

// killTree makes cancelling cmd's context kill cmd and every process it
// started. reap has nothing to wait for.
func killTree(cmd *exec.Cmd) (reap func()) {
	cmd.Cancel = func() error {
		if exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run() == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	return func() {}
}

// SignalGroup sends sig to p alone: Windows has no process groups that
// gogrep uses.
func SignalGroup(p *os.Process, sig os.Signal) error { return p.Signal(sig) }

// textBusy reports whether err is a start that failed because the
// executable was open for writing, which Windows does not report so.
func textBusy(error) bool { return false }
