package opengrep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestMain lets the test binary stand in for opengrep and the processes it
// starts: run with GOGREP_TEST_HELPER set, it is helper.
func TestMain(m *testing.M) {
	if mode := os.Getenv("GOGREP_TEST_HELPER"); mode != "" {
		os.Exit(helper(mode, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// helper is a process in one of these modes:
//
//   - echo prints its working directory, $GOGREP_TEST_VAR, its args and
//     its stdin to stdout, "stderr" to stderr, and exits with
//     $GOGREP_TEST_EXIT;
//   - tree starts a child in mode sleep that shares its stdout, as
//     opengrep's launcher starts opengrep-cli and opengrep-core, writes its
//     own pid and the child's to $GOGREP_TEST_PIDS, and sleeps;
//   - orphan does as tree, but exits at once;
//   - sleep sleeps for a minute.
func helper(mode string, args []string) int {
	switch mode {
	case "echo":
		wd, _ := os.Getwd()
		in, _ := io.ReadAll(os.Stdin)
		fmt.Printf("%s\n%s\n%s\n%s", wd, os.Getenv("GOGREP_TEST_VAR"), strings.Join(args, " "), in)
		fmt.Fprint(os.Stderr, "stderr")
		code, _ := strconv.Atoi(os.Getenv("GOGREP_TEST_EXIT"))
		return code
	case "tree", "orphan":
		child := exec.Command(os.Args[0])
		child.Env = append(os.Environ(), "GOGREP_TEST_HELPER=sleep")
		child.Stdout = os.Stdout
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		pids, tmp := os.Getenv("GOGREP_TEST_PIDS"), os.Getenv("GOGREP_TEST_PIDS")+".tmp"
		if os.WriteFile(tmp, fmt.Appendf(nil, "%d %d", os.Getpid(), child.Process.Pid), 0o600) != nil || os.Rename(tmp, pids) != nil {
			return 2
		}
		if mode == "orphan" {
			return 0
		}
		fallthrough
	case "sleep":
		time.Sleep(time.Minute)
		return 0
	}
	return 2
}

// helperCmd returns a Cmd that runs the test binary as helper in mode, with
// env added to its environment.
func helperCmd(t *testing.T, mode string, env ...string) *Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return &Cmd{Path: exe, Env: append(append(os.Environ(), "GOGREP_TEST_HELPER="+mode), env...)}
}

// runAsync runs c under ctx and sends Run's result on the returned channel.
func runAsync(ctx context.Context, c *Cmd) <-chan error {
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	return done
}

// waitPids waits until the helper in mode tree or orphan wrote the file
// pids, and returns its pid and its child's. The child is killed when the
// test ends.
func waitPids(t *testing.T, pids string, done <-chan error) (pid, child int) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if data, err := os.ReadFile(pids); err == nil {
			if _, err := fmt.Sscan(string(data), &pid, &child); err != nil {
				t.Fatalf("%s holds %q: %v", pids, data, err)
			}
			break
		}
		select {
		case err := <-done:
			t.Fatalf("Run = %v before the helper started its child", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the helper started no child")
		}
	}
	t.Cleanup(func() {
		if p, err := os.FindProcess(child); err == nil && running(child) {
			p.Kill()
		}
	})
	return pid, child
}

func TestRun(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := helperCmd(t, "echo", "GOGREP_TEST_VAR=from Env")
	c.Args, c.Dir = []string{"scan", "--sarif", "."}, dir
	var out, errb bytes.Buffer
	c.Stdin, c.Stdout, c.Stderr = strings.NewReader("from Stdin"), &out, &errb
	if err := c.Run(context.Background()); err != nil {
		t.Fatalf("Run = %v, stderr %q", err, errb.String())
	}
	lines := strings.Split(out.String(), "\n")
	if len(lines) != 4 || lines[1] != "from Env" || lines[2] != "scan --sarif ." || lines[3] != "from Stdin" || errb.String() != "stderr" {
		t.Fatalf("Run wrote %q and %q to stdout and stderr", out.String(), errb.String())
	}
	wd, err1 := os.Stat(lines[0])
	want, err2 := os.Stat(dir)
	if err1 != nil || err2 != nil || !os.SameFile(wd, want) {
		t.Errorf("the process ran in %s, want %s", lines[0], dir)
	}

	t.Run("exit code, null device", func(t *testing.T) {
		t.Parallel()
		c := helperCmd(t, "echo", "GOGREP_TEST_EXIT=7")
		var out bytes.Buffer
		c.Stdout = &out
		err := c.Run(context.Background())
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
			t.Errorf("Run = %v, want an *exec.ExitError with code 7", err)
		}
		if lines := strings.Split(out.String(), "\n"); len(lines) != 4 || lines[3] != "" {
			t.Errorf("Run wrote %q to stdout, want an empty stdin", out.String())
		}
	})

	t.Run("no executable", func(t *testing.T) {
		t.Parallel()
		c := &Cmd{Path: filepath.Join(t.TempDir(), "opengrep")}
		err := c.Run(context.Background())
		var exitErr *exec.ExitError
		if err == nil || errors.As(err, &exitErr) {
			t.Errorf("Run of a missing executable = %v, want a start error", err)
		}
	})

	t.Run("ctx already done", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c := helperCmd(t, "echo")
		var out bytes.Buffer
		c.Stdout = &out
		if err := c.Run(ctx); !errors.Is(err, context.Canceled) || out.Len() != 0 {
			t.Errorf("Run = %v, stdout %q; want context.Canceled and no process", err, out.String())
		}
	})
}

// A process that exits but leaves a child holding its stdout cannot keep Run
// waiting.
func TestRunWaitDelay(t *testing.T) {
	t.Parallel()
	pids := filepath.Join(t.TempDir(), "pids")
	c := helperCmd(t, "orphan", "GOGREP_TEST_PIDS="+pids)
	c.Stdout = new(bytes.Buffer)
	start := time.Now()
	done := runAsync(context.Background(), c)
	waitPids(t, pids, done)
	select {
	case err := <-done:
		if !errors.Is(err, exec.ErrWaitDelay) {
			t.Errorf("Run = %v, want exec.ErrWaitDelay", err)
		}
	case <-time.After(waitDelay + 10*time.Second):
		t.Fatalf("Run still waits after %v", time.Since(start))
	}
}
