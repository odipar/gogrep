//go:build unix

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// An interrupt kills not only opengrep's launcher but also the processes
// it started.
func TestExecFixtureKillsTree(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		// The shell stands in for the launcher, sleep for opengrep-core.
		_, _, _, err := execFixture(ctx, dir, []string{"/bin/sh", "-c", "sleep 60 & echo $! >pid; wait"})
		done <- err
	}()

	var pid int
	for deadline := time.Now().Add(10 * time.Second); pid == 0; time.Sleep(10 * time.Millisecond) {
		data, _ := os.ReadFile(filepath.Join(dir, "pid"))
		pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
		if time.Now().After(deadline) {
			t.Fatal("the shell started no child")
		}
	}
	cancel()
	if err := <-done; err == nil {
		t.Error("execFixture, cancelled: no error")
	}
	for deadline := time.Now().Add(5 * time.Second); running(pid); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the shell's child %d still runs", pid)
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
