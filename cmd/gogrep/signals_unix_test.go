//go:build unix

package main

import (
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

// A scan's opengrep runs in a process group of its own, so the signals a
// terminal sends its foreground group reach gogrep alone, which kills
// opengrep with the processes it started, says so and exits 130.
func TestScanInterrupted(t *testing.T) {
	useFakeOpengrep(t, 0)
	t.Chdir(t.TempDir())
	t.Setenv("GOGREP_TEST_FAKE_CHILD", "1")
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		t.Run(sig.String(), func(t *testing.T) {
			// The pass-through of an earlier test ignores SIGINT and SIGTERM
			// for good; catching a signal undoes that, and also keeps it
			// from ending the test.
			caught := make(chan os.Signal, 1)
			signal.Notify(caught, sig)
			defer signal.Stop(caught)
			ready := filepath.Join(t.TempDir(), "ready")
			t.Setenv("GOGREP_TEST_FAKE_WAIT", ready)
			done := make(chan string, 1)
			go func() {
				code, stdout, stderr := runGogrep("scan", "--config", "r.yaml", "--sarif", ".")
				done <- fmt.Sprintf("%d, %q, %q", code, stdout, stderr)
			}()
			for _, err := os.Stat(ready); err != nil; _, err = os.Stat(ready) {
				select {
				case got := <-done:
					t.Fatalf("gogrep scan = %s before opengrep ran", got)
				case <-time.After(10 * time.Millisecond):
				}
			}
			data, err := os.ReadFile(ready)
			child, _ := strconv.Atoi(string(data))
			if err != nil || child == 0 {
				t.Fatalf("the fake opengrep started no child: %q, %v", data, err)
			}
			syscall.Kill(os.Getpid(), sig)
			if got, want := <-done, `130, "", "gogrep: interrupted\n"`; got != want {
				t.Errorf("gogrep scan, sent %v = %s; want %s", sig, got, want)
			}
			for deadline := time.Now().Add(5 * time.Second); running(child); time.Sleep(10 * time.Millisecond) {
				if time.Now().After(deadline) {
					syscall.Kill(child, syscall.SIGKILL)
					t.Fatalf("opengrep's child %d still runs", child)
				}
			}
		})
	}
}

// A scan leaves the signal dispositions alone: a process started after it
// does not start with SIGINT ignored, as it did when every scan made gogrep
// ignore SIGINT and SIGTERM for good.
func TestScanLeavesSignals(t *testing.T) {
	useFakeOpengrep(t, 0)
	t.Chdir(t.TempDir())
	// Catching SIGINT undoes an earlier test's pass-through, which ignores
	// it for good; a later Ignore would undo the catch.
	caught := make(chan os.Signal, 1)
	signal.Notify(caught, os.Interrupt)
	defer signal.Stop(caught)
	exe := os.Getenv("OPENGREP_BIN")
	probe := func() string {
		cmd := exec.Command(exe)
		cmd.Env = append(os.Environ(), "GOGREP_TEST_SIGPROBE=1")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("the probe: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	if got := probe(); got != "false" {
		t.Fatalf("a probe started before the scan reports SIGINT ignored: %s", got)
	}
	if code, _, stderr := runGogrep("scan", "--config", "r.yaml", "."); code != 0 {
		t.Fatalf("gogrep scan = %d, %q", code, stderr)
	}
	if got := probe(); got != "false" {
		t.Errorf("a probe started after the scan reports SIGINT ignored: %s", got)
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
