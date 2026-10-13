package opengrep

import (
	"os/exec"
	"strconv"
	"strings"
)

// running reports whether the process pid runs.
func running(pid int) bool {
	out, err := exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(pid), "/NH", "/FO", "CSV").Output()
	return err == nil && strings.Contains(string(out), `"`+strconv.Itoa(pid)+`"`)
}
