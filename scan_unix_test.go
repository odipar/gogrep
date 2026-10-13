//go:build unix

package gogrep

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// canKill is set where the tests can check that a process is gone.
const canKill = true

// checkGone checks that the process pid stops running within a second.
func checkGone(t *testing.T, pid string) {
	t.Helper()
	n, err := strconv.Atoi(pid)
	if err != nil {
		t.Fatalf("pid %q: %v", pid, err)
	}
	for deadline := time.Now().Add(time.Second); running(n); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Errorf("process %d still runs", n)
			return
		}
	}
}

// running reports whether the process pid runs: it exists and has not
// exited, waiting to be reaped. Linux tells from /proc, as the ps of busybox
// (Alpine) has no -p.
func running(pid int) bool {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return false
	}
	if stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		// The state follows the command name, in parentheses.
		fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:]))
		return len(fields) > 0 && fields[0] != "Z"
	}
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	return err == nil && !strings.HasPrefix(strings.TrimSpace(string(out)), "Z")
}
