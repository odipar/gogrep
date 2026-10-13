//go:build unix

package engine

import (
	"errors"
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
// exited, waiting to be reaped.
func running(pid int) bool {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return false
	}
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	return err == nil && !strings.HasPrefix(strings.TrimSpace(string(out)), "Z")
}
