//go:build windows

package opengrep

import (
	"os/exec"
	"strconv"
)

// killTree makes cancelling cmd's context kill cmd and every process it
// started.
func killTree(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run() == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
}

// textBusy reports whether err is a start that failed because the
// executable was open for writing, which Windows does not report so.
func textBusy(error) bool { return false }
