//go:build unix

package opengrep

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

// opengrep leads a process group of its own, so that a terminal's Ctrl-C
// reaches only the caller; with Foreground it stays in the caller's, and
// cancelling kills it alone.
func TestRunProcessGroup(t *testing.T) {
	t.Parallel()
	for _, foreground := range []bool{false, true} {
		t.Run("Foreground "+strconv.FormatBool(foreground), func(t *testing.T) {
			t.Parallel()
			pids := filepath.Join(t.TempDir(), "pids")
			c := helperCmd(t, "tree", "GOGREP_TEST_PIDS="+pids)
			c.Foreground = foreground
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := runAsync(ctx, c)
			pid, child := waitPids(t, pids, done)

			group, err := syscall.Getpgid(pid)
			want := pid
			if foreground {
				want = syscall.Getpgrp()
			}
			if err != nil || group != want {
				t.Errorf("the process's group = %d, %v; want %d", group, err, want)
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Errorf("Run, cancelled = %v, want context.Canceled", err)
			}
			time.Sleep(100 * time.Millisecond)
			if alive := running(child); alive != foreground {
				t.Errorf("after the cancel, the launcher's child runs: %v; want %v", alive, foreground)
			}
		})
	}
}

// Run retries a start that failed with ETXTBSY with a new exec.Cmd, and
// gives up after startRetries retries.
func TestRunRetriesTextBusy(t *testing.T) {
	t.Parallel()
	busy := &os.PathError{Op: "fork/exec", Path: "opengrep", Err: syscall.ETXTBSY}
	tests := []struct {
		name   string
		fails  int   // how many starts fail with err
		err    error // what they fail with
		starts int   // how many starts Run makes
		ok     bool  // whether the process runs
	}{
		{"busy twice", 2, busy, 3, true},
		{"busy always", 100, busy, startRetries + 1, false},
		{"another error", 100, os.ErrPermission, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := helperCmd(t, "echo")
			var out strings.Builder
			c.Stdin, c.Stdout = strings.NewReader("in"), &out
			var cmds []*exec.Cmd
			c.start = func(cmd *exec.Cmd) error {
				for _, old := range cmds {
					if old == cmd {
						t.Error("Run starts an exec.Cmd twice")
					}
				}
				cmds = append(cmds, cmd)
				if len(cmds) <= tt.fails {
					return tt.err
				}
				return cmd.Start()
			}
			err := c.Run(context.Background())
			if len(cmds) != tt.starts {
				t.Errorf("Run made %d starts, want %d", len(cmds), tt.starts)
			}
			if tt.ok {
				// The failed starts read no stdin.
				if err != nil || !strings.HasSuffix(out.String(), "\nin") {
					t.Errorf("Run = %v, stdout %q; want no error and the stdin", err, out.String())
				}
			} else if !errors.Is(err, tt.err) {
				t.Errorf("Run = %v, want %v", err, tt.err)
			}
		})
	}

	t.Run("ctx done while waiting", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		c := helperCmd(t, "echo")
		c.start = func(*exec.Cmd) error { return busy }
		start := time.Now()
		err := c.Run(ctx)
		// Retrying for good would take 620 ms.
		if d := time.Since(start); !errors.Is(err, context.DeadlineExceeded) || d > 400*time.Millisecond {
			t.Errorf("Run = %v after %v; want context.DeadlineExceeded after about 50ms", err, d)
		}
	})
}
