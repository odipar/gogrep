//go:build windows

package main

import (
	"os/exec"
	"strconv"
)

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
