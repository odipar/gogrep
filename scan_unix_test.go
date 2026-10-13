//go:build unix

package gogrep

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
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

// A directory that cannot be searched cannot be entered either, which is
// named as such.
func TestUnsearchableDirectory(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root enters any directory")
	}
	e := newFakeEngine(t)
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	_, err := e.Scan(context.Background(), dir, nil)
	if !errors.Is(err, fs.ErrPermission) || errors.Is(err, ErrNoOpengrep) || !strings.HasPrefix(err.Error(), fmt.Sprintf("directory %q: ", dir)) {
		t.Errorf("Scan of an unsearchable directory = %v; want a permission error that names it", err)
	}
}

// Signal reaches the running opengrep's whole process group, and fails when
// none runs.
func TestCmdSignal(t *testing.T) {
	t.Parallel()
	ready := filepath.Join(t.TempDir(), "ready")
	e := newFakeEngine(t, "GOGREP_TEST_FAKE_WAIT="+ready, "GOGREP_TEST_FAKE_CHILD=1", "PATH="+os.Getenv("PATH"))
	cmd, err := e.Command(context.Background(), t.TempDir(), nil, "scan")
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Signal(os.Interrupt); err == nil {
		t.Errorf("Signal before Run = nil, want an error")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	var pid []byte
	for deadline := time.Now().Add(10 * time.Second); len(pid) == 0; time.Sleep(10 * time.Millisecond) {
		pid, _ = os.ReadFile(ready)
		if time.Now().After(deadline) {
			t.Fatal("the fake opengrep never started")
		}
	}
	if err := cmd.Signal(syscall.SIGTERM); err != nil {
		t.Errorf("Signal while Run runs = %v", err)
	}
	var exitErr *ExitError
	select {
	case err := <-done:
		if !errors.As(err, &exitErr) || exitErr.Code != -1 {
			t.Errorf("Run, sent SIGTERM = %v, want an *ExitError for a signal", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run still runs after SIGTERM")
	}
	checkGone(t, string(pid))
	if err := cmd.Signal(os.Interrupt); err == nil {
		t.Errorf("Signal after Run = nil, want an error")
	}
}
