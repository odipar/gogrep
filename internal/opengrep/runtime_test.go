package opengrep

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// unpackHelper stands in for opengrep's first run. It records itself in the
// directory $GOGREP_TEST_RUNS as a file named after its pid, and as active
// while it runs, creating overlap there if another run is active. It
// writes to $SEMGREP_LOG_FILE, creates $GOGREP_TEST_READY if set, waits
// $GOGREP_TEST_DELAY (100 ms by default), unpacks a runtime into
// $XDG_CACHE_HOME/opengrep/v1.30.2 if that is set, prints its version and
// exits with $GOGREP_TEST_EXIT.
func unpackHelper() int {
	runs := os.Getenv("GOGREP_TEST_RUNS")
	active := filepath.Join(runs, "active")
	if f, err := os.OpenFile(active, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil {
		os.WriteFile(filepath.Join(runs, "overlap"), nil, 0o600)
	} else {
		f.Close()
		defer os.Remove(active)
	}
	os.WriteFile(filepath.Join(runs, strconv.Itoa(os.Getpid())), nil, 0o600)
	if log := os.Getenv("SEMGREP_LOG_FILE"); log != "" {
		os.WriteFile(log, []byte("logged\n"), 0o600)
	}
	if ready := os.Getenv("GOGREP_TEST_READY"); ready != "" {
		os.WriteFile(ready, nil, 0o600)
	}
	delay, _ := time.ParseDuration(os.Getenv("GOGREP_TEST_DELAY"))
	time.Sleep(cmp.Or(delay, 100*time.Millisecond))
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		dir := filepath.Join(xdg, "opengrep", "v1.30.2")
		if os.MkdirAll(dir, 0o700) != nil || os.WriteFile(filepath.Join(dir, "Python"), []byte("runtime"), 0o600) != nil {
			return 2
		}
	}
	fmt.Println("1.30.2")
	code, _ := strconv.Atoi(os.Getenv("GOGREP_TEST_EXIT"))
	return code
}

// unpacker returns the test binary as the opengrep that unpackHelper stands
// in for: its path, its SHA-256 and an environment that has it record its
// runs in the directory runs, with env added.
func unpacker(t *testing.T, env ...string) (exe, sum string, environ []string, runs string) {
	t.Helper()
	exe, err := os.Executable()
	if err == nil {
		sum, err = FileSHA256(exe)
	}
	if err != nil {
		t.Fatal(err)
	}
	runs = t.TempDir()
	return exe, sum, append(append(os.Environ(), "GOGREP_TEST_HELPER=unpack", "GOGREP_TEST_RUNS="+runs), env...), runs
}

// countRuns returns how many runs recorded themselves in runs, and whether
// two ever ran at once.
func countRuns(t *testing.T, runs string) (n int, overlap bool) {
	t.Helper()
	entries, err := os.ReadDir(runs)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		switch e.Name() {
		case "overlap":
			overlap = true
		case "active":
		default:
			n++
		}
	}
	return n, overlap
}

// checkPrepared checks that dir holds the runtime prepared for sum and,
// apart from locks, nothing else.
func checkPrepared(t *testing.T, dir, sum, xdg string) {
	t.Helper()
	ready := filepath.Join(dir, "runtime-"+sum[:16])
	if runtime.GOOS == "windows" {
		if xdg != "" {
			t.Errorf("PrepareRuntime = %q, want \"\" on Windows", xdg)
		}
		if fi, err := os.Stat(ready + ".ready"); err != nil || !fi.Mode().IsRegular() {
			t.Errorf("no marker %s.ready: %v", ready, err)
		}
	} else {
		if xdg != ready {
			t.Errorf("PrepareRuntime = %q, want %s", xdg, ready)
		}
		if data, err := os.ReadFile(filepath.Join(ready, "opengrep", "v1.30.2", "Python")); err != nil || string(data) != "runtime" {
			t.Errorf("the prepared runtime holds %q, %v; want the unpacked one", data, err)
		}
		if fi, err := os.Stat(ready); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v, %v; want mode 0700", ready, fi.Mode(), err)
		}
	}
	checkNoTemp(t, dir)
}

// checkNoTemp checks that dir holds no temporary runtime directory or log.
func checkNoTemp(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".runtime-") {
			t.Errorf("%s is left in the cache", e.Name())
		}
	}
	if logs, _ := os.ReadDir(filepath.Join(dir, "logs")); len(logs) != 0 {
		t.Errorf("logs left: %v", logs)
	}
}

func TestPrepareRuntime(t *testing.T) {
	t.Parallel()
	exe, sum, env, runs := unpacker(t)
	dir := t.TempDir()
	var log bytes.Buffer
	xdg, err := PrepareRuntime(context.Background(), exe, sum, dir, env, slog.New(slog.NewTextHandler(&log, nil)))
	if err != nil {
		t.Fatal(err)
	}
	checkPrepared(t, dir, sum, xdg)
	if runtime.GOOS != "windows" {
		if _, err := os.Stat(filepath.Join(xdg, "log")); err == nil {
			t.Errorf("the preparation's log is left in the runtime")
		}
	}
	if !strings.Contains(log.String(), "prepared opengrep's runtime") {
		t.Errorf("PrepareRuntime logged\n%s\nwant that it prepared the runtime", log.String())
	}

	// Once prepared, a runtime is used as it is.
	again, err := PrepareRuntime(context.Background(), exe, sum, dir, env, slog.New(slog.DiscardHandler))
	if n, _ := countRuns(t, runs); err != nil || again != xdg || n != 1 {
		t.Errorf("PrepareRuntime again = %q, %v after %d runs; want %q after 1", again, err, n, xdg)
	}
}

// A failed preparation publishes nothing, and the run goes ahead without
// it.
func TestPrepareRuntimeFails(t *testing.T) {
	t.Parallel()
	exe, sum, env, runs := unpacker(t, "GOGREP_TEST_EXIT=3")
	dir := t.TempDir()
	var log bytes.Buffer
	for i := 1; i <= 2; i++ {
		xdg, err := PrepareRuntime(context.Background(), exe, sum, dir, env, slog.New(slog.NewTextHandler(&log, nil)))
		if n, _ := countRuns(t, runs); xdg != "" || err != nil || n != i {
			t.Errorf("PrepareRuntime of a failing opengrep = %q, %v after %d runs; want \"\" after %d", xdg, err, n, i)
		}
	}
	if !strings.Contains(log.String(), "could not prepare opengrep's runtime") || !strings.Contains(log.String(), "exit status 3") {
		t.Errorf("PrepareRuntime logged\n%s\nwant why it failed", log.String())
	}
	for _, name := range []string{"runtime-" + sum[:16], "runtime-" + sum[:16] + ".ready"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("a failed preparation published %s", name)
		}
	}
	checkNoTemp(t, dir)

	// A cache that cannot be written is the same.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if xdg, err := PrepareRuntime(context.Background(), exe, sum, filepath.Join(file, "cache"), env, slog.New(slog.DiscardHandler)); xdg != "" || err != nil {
		t.Errorf("PrepareRuntime in an impossible cache = %q, %v; want \"\" and no error", xdg, err)
	}
}

func TestPrepareRuntimeCancelled(t *testing.T) {
	t.Parallel()
	ready := filepath.Join(t.TempDir(), "ready")
	exe, sum, env, _ := unpacker(t, "GOGREP_TEST_DELAY=1m", "GOGREP_TEST_READY="+ready)
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := PrepareRuntime(ctx, exe, sum, dir, env, slog.New(slog.DiscardHandler))
		done <- err
	}()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the preparation never started")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("a cancelled PrepareRuntime = %v, want context.Canceled", err)
		}
	case <-time.After(waitDelay + 10*time.Second):
		t.Fatal("PrepareRuntime still runs after its ctx was cancelled")
	}
	checkNoTemp(t, dir)
	if entries, _ := os.ReadDir(dir); len(entries) > 2 { // locks, and logs on Windows
		t.Errorf("a cancelled preparation left %v", entries)
	}
}

// The first run of opengrep, which unpacks its runtime, runs alone: once
// within a process, and once between processes.
func TestRunFirstAlone(t *testing.T) {
	t.Parallel()
	t.Run("goroutines", func(t *testing.T) {
		t.Parallel()
		exe, sum, env, runs := unpacker(t, "GOGREP_TEST_DELAY=200ms")
		dir := t.TempDir()
		xdgs := make([]string, 8)
		var wg sync.WaitGroup
		for i := range xdgs {
			wg.Go(func() {
				var err error
				if xdgs[i], err = PrepareRuntime(context.Background(), exe, sum, dir, env, slog.New(slog.DiscardHandler)); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if n, overlap := countRuns(t, runs); n != 1 || overlap {
			t.Errorf("opengrep ran %d times, overlapping %v; want once", n, overlap)
		}
		for _, xdg := range xdgs {
			checkPrepared(t, dir, sum, xdg)
		}
	})

	t.Run("processes", func(t *testing.T) {
		t.Parallel()
		exe, sum, env, runs := unpacker(t, "GOGREP_TEST_DELAY=500ms")
		dir := t.TempDir()
		outs := make([][]byte, 2)
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range outs {
			wg.Go(func() {
				cmd := exec.Command(exe, exe, sum, dir)
				cmd.Env = append(slices.Clip(env), "GOGREP_TEST_HELPER=prepare")
				outs[i], errs[i] = cmd.Output()
			})
		}
		wg.Wait()
		if n, overlap := countRuns(t, runs); n != 1 || overlap {
			t.Errorf("opengrep ran %d times, overlapping %v; want once", n, overlap)
		}
		want := filepath.Join(dir, "runtime-"+sum[:16]) + " <nil>\n"
		if runtime.GOOS == "windows" {
			want = " <nil>\n"
		}
		for i := range outs {
			if errs[i] != nil || string(outs[i]) != want {
				t.Errorf("process %d printed %q, %v; want %q", i, outs[i], errs[i], want)
			}
		}
		checkPrepared(t, dir, sum, strings.TrimSuffix(string(outs[0]), " <nil>\n"))
	})
}

func TestLock(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "locks", "x.lock")
	unlock, err := lock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("lock file %s: %v, %v; want mode 0600", path, fi.Mode(), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*lockPoll)
	defer cancel()
	if _, err := lock(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("lock of a locked file = %v, want to wait until ctx is done", err)
	}
	done := make(chan error, 1)
	go func() {
		unlock, err := lock(context.Background(), path)
		if err == nil {
			unlock()
		}
		done <- err
	}()
	time.Sleep(2 * lockPoll)
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("lock after unlock = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("lock still waits after unlock")
	}
}
