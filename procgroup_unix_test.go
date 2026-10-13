//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
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

// The signals a terminal sends its foreground group do not reach the opengrep
// processes, so gogrep test catches them too.
func TestTestTerminalSignals(t *testing.T) {
	useFakeOpengrep(t, 0)
	testProject(t, brokenFiles)
	for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGQUIT} {
		if signal.Ignored(sig) {
			continue // gogrep leaves it ignored, as under nohup
		}
		ready := filepath.Join(t.TempDir(), "ready")
		t.Setenv("GOGREP_TEST_FAKE_WAIT", ready)
		done := make(chan string, 1)
		go func() {
			code, _, stderr := runGogrep("test", testRoot+"/go/exec-command")
			done <- fmt.Sprintf("%d, %q", code, stderr)
		}()
		for _, err := os.Stat(ready); err != nil; _, err = os.Stat(ready) {
			select {
			case got := <-done:
				t.Fatalf("gogrep test = %s before opengrep ran", got)
			case <-time.After(10 * time.Millisecond):
			}
		}
		syscall.Kill(os.Getpid(), sig)
		if got, want := <-done, `130, "gogrep: interrupted\n"`; got != want {
			t.Errorf("gogrep test, sent %v = %s; want %s", sig, got, want)
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
