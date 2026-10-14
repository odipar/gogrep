package opengrep

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
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
// $XDG_CACHE_HOME/opengrep/v1.30.2 if that is set, prints its version
// unless $GOGREP_TEST_SILENT=1, and exits with $GOGREP_TEST_EXIT.
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
	if os.Getenv("GOGREP_TEST_SILENT") != "1" {
		fmt.Println("1.30.2")
	}
	code, _ := strconv.Atoi(os.Getenv("GOGREP_TEST_EXIT"))
	return code
}

// unpacker returns the test binary as the opengrep that unpackHelper stands
// in for: its path, its SHA-256 and an environment that has it record its
// runs in the directory runs, with env added. Its own XDG_CACHE_HOME is a
// new directory, where a runtime kept in place is unpacked.
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
	return exe, sum, append(append(os.Environ(), "GOGREP_TEST_HELPER=unpack", "GOGREP_TEST_RUNS="+runs, "XDG_CACHE_HOME="+t.TempDir()), env...), runs
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

// checkPrepared checks that dir holds the runtime prepared for sum in env
// and, apart from locks, nothing else. A runtime kept in place is unpacked
// in env's XDG_CACHE_HOME, and marked in dir.
func checkPrepared(t *testing.T, dir, sum, xdg string, env []string) {
	t.Helper()
	ready := filepath.Join(dir, "runtime-"+sum[:16])
	if staysInPlace(runtime.GOOS, dir) {
		if xdg != "" {
			t.Errorf("PrepareRuntime = %q, want \"\" for a runtime kept in place", xdg)
		}
		if fi, err := os.Stat(ready + ".ready"); err != nil || !fi.Mode().IsRegular() || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
			t.Errorf("no marker %s.ready of mode 0600: %v", ready, err)
		}
		own := filepath.Join(lookup(env, "XDG_CACHE_HOME"), "opengrep", "v1.30.2")
		want := string(inPlaceMark(runtime.GOOS, env))
		if runtime.GOOS != "windows" {
			want += "RUNTIME=" + own + "\n"
		}
		if data, err := os.ReadFile(ready + ".ready"); err != nil || string(data) != want {
			t.Errorf("the marker holds %q, %v; want %q", data, err, want)
		}
		place := filepath.Join(own, "Python")
		if data, err := os.ReadFile(place); err != nil || string(data) != "runtime" {
			t.Errorf("the runtime kept in place holds %q, %v; want the unpacked one", data, err)
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
	checkPrepared(t, dir, sum, xdg, env)
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
// it. So does one that exits 0 without printing a version, as opengrep
// 1.30.2 does under a path that is not ASCII.
func TestPrepareRuntimeFails(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct{ env, why string }{
		{"GOGREP_TEST_EXIT=3", "exit status 3"},
		{"GOGREP_TEST_SILENT=1", "exited 0 but printed no version"},
	} {
		for _, name := range []string{"cache", "caché"} { // the runtime kept in place, in caché
			exe, sum, env, runs := unpacker(t, tt.env)
			dir := filepath.Join(t.TempDir(), name)
			var log bytes.Buffer
			for i := 1; i <= 2; i++ {
				xdg, err := PrepareRuntime(context.Background(), exe, sum, dir, env, slog.New(slog.NewTextHandler(&log, nil)))
				if n, _ := countRuns(t, runs); xdg != "" || err != nil || n != i {
					t.Errorf("PrepareRuntime of a failing opengrep (%s) in %s = %q, %v after %d runs; want \"\" after %d", tt.env, name, xdg, err, n, i)
				}
			}
			if !strings.Contains(log.String(), "could not prepare opengrep's runtime") || !strings.Contains(log.String(), tt.why) {
				t.Errorf("PrepareRuntime (%s) in %s logged\n%s\nwant why it failed", tt.env, name, log.String())
			}
			for _, name := range []string{"runtime-" + sum[:16], "runtime-" + sum[:16] + ".ready"} {
				if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
					t.Errorf("a failed preparation (%s) published %s", tt.env, name)
				}
			}
			checkNoTemp(t, dir)
		}
	}
	exe, sum, env, _ := unpacker(t, "GOGREP_TEST_EXIT=3")

	// A cache that cannot be written is the same.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if xdg, err := PrepareRuntime(context.Background(), exe, sum, filepath.Join(file, "cache"), env, slog.New(slog.DiscardHandler)); xdg != "" || err != nil {
		t.Errorf("PrepareRuntime in an impossible cache = %q, %v; want \"\" and no error", xdg, err)
	}
}

// Under a cache directory that is not ASCII, where opengrep 1.30.2 runs no
// command, its runtime stays where opengrep keeps it by itself, as on
// Windows: the first run is serialised and marked in the cache directory,
// for the variables that pick that place, so that a run with other ones
// prepares its own.
func TestPrepareRuntimeNotASCII(t *testing.T) {
	t.Parallel()
	exe, sum, env, runs := unpacker(t, "GOGREP_TEST_DELAY=200ms")
	dir := filepath.Join(t.TempDir(), "caché")
	var log bytes.Buffer
	xdgs := make([]string, 8)
	var wg sync.WaitGroup
	for i := range xdgs {
		wg.Go(func() {
			var err error
			if xdgs[i], err = PrepareRuntime(context.Background(), exe, sum, dir, env, slog.New(slog.NewTextHandler(&log, nil))); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n, overlap := countRuns(t, runs); n != 1 || overlap {
		t.Errorf("opengrep ran %d times, overlapping %v; want once", n, overlap)
	}
	for _, xdg := range xdgs {
		checkPrepared(t, dir, sum, xdg, env)
	}
	if runtime.GOOS != "windows" && !strings.Contains(log.String(), "not ASCII") {
		t.Errorf("PrepareRuntime under %s logged\n%s\nwant why it keeps the runtime in place", dir, log.String())
	}
	if xdg, err := PrepareRuntime(context.Background(), exe, sum, dir, env, slog.New(slog.DiscardHandler)); xdg != "" || err != nil {
		t.Errorf("PrepareRuntime again = %q, %v; want \"\"", xdg, err)
	}
	if n, _ := countRuns(t, runs); n != 1 {
		t.Errorf("opengrep ran %d times after PrepareRuntime of a prepared runtime; want once", n)
	}

	// Another place for opengrep's own runtime is prepared too.
	other := append(slices.Clip(env), "XDG_CACHE_HOME="+t.TempDir())
	if xdg, err := PrepareRuntime(context.Background(), exe, sum, dir, other, slog.New(slog.DiscardHandler)); xdg != "" || err != nil {
		t.Errorf("PrepareRuntime with another XDG_CACHE_HOME = %q, %v; want \"\"", xdg, err)
	}
	want := 2
	if runtime.GOOS == "windows" {
		want = 1 // which no variable moves
	}
	if n, _ := countRuns(t, runs); n != want {
		t.Errorf("opengrep ran %d times after PrepareRuntime with another XDG_CACHE_HOME; want %d", n, want)
	}
	if runtime.GOOS != "windows" {
		checkPrepared(t, dir, sum, "", other)

		// A marker whose runtime was removed since (a cleaned cache) no
		// longer counts, so the next first runs are serialised again.
		if err := os.RemoveAll(filepath.Join(lookup(other, "XDG_CACHE_HOME"), "opengrep")); err != nil {
			t.Fatal(err)
		}
		if xdg, err := PrepareRuntime(context.Background(), exe, sum, dir, other, slog.New(slog.DiscardHandler)); xdg != "" || err != nil {
			t.Errorf("PrepareRuntime after its runtime was removed = %q, %v; want \"\"", xdg, err)
		}
		if n, _ := countRuns(t, runs); n != want+1 {
			t.Errorf("opengrep ran %d times after its runtime kept in place was removed; want %d", n, want+1)
		}
		checkPrepared(t, dir, sum, "", other)
	}
}

// staysInPlace keeps opengrep's runtime where opengrep does on Windows, and
// under a cache directory that is not ASCII.
func TestStaysInPlace(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		goos, dir string
		want      bool
	}{
		{"linux", "/home/u/.cache/gogrep", false},
		{"darwin", "/Users/a b/Library/Caches/gogrep", false},
		{"darwin", "/Users/josé/Library/Caches/gogrep", true},
		{"linux", "/tmp/cache-\u00e9", true},
		{"freebsd", "/tmp/キャッシュ", true},
		{"windows", `C:\Users\u\AppData\Local\gogrep`, true},
		{"windows", `C:\Users\josé\AppData\Local\gogrep`, true},
	} {
		if got := staysInPlace(tt.goos, tt.dir); got != tt.want {
			t.Errorf("staysInPlace(%s, %s) = %v, want %v", tt.goos, tt.dir, got, tt.want)
		}
	}
	env := []string{"HOME=/old", "XDG_CACHE_HOME=", "HOME=/home/u"}
	if got, want := string(inPlaceMark("linux", env)), "XDG_CACHE_HOME=\nHOME=/home/u\n"; got != want {
		t.Errorf("inPlaceMark(linux, %q) = %q, want %q", env, got, want)
	}
	if got := inPlaceMark("windows", env); got != nil {
		t.Errorf("inPlaceMark(windows, %q) = %q, want nothing", env, got)
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
// within a process, and once between processes, also where the runtime is
// kept in place.
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
			checkPrepared(t, dir, sum, xdg, env)
		}
	})

	for _, name := range []string{"cache", "caché"} {
		t.Run("processes in "+name, func(t *testing.T) {
			t.Parallel()
			runProcessesFirstAlone(t, filepath.Join(t.TempDir(), name))
		})
	}
}

// runProcessesFirstAlone checks that the first run of opengrep in the cache
// directory dir runs once when two processes prepare its runtime at once.
func runProcessesFirstAlone(t *testing.T, dir string) {
	exe, sum, env, runs := unpacker(t, "GOGREP_TEST_DELAY=500ms")
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
	if staysInPlace(runtime.GOOS, dir) {
		want = " <nil>\n"
	}
	for i := range outs {
		if errs[i] != nil || string(outs[i]) != want {
			t.Errorf("process %d printed %q, %v; want %q", i, outs[i], errs[i], want)
		}
	}
	checkPrepared(t, dir, sum, strings.TrimSuffix(string(outs[0]), " <nil>\n"), env)
}

// RemoveRuntime keeps a runtime that is being prepared, and leaves nothing
// of one it removes.
func TestRemoveRuntime(t *testing.T) {
	t.Parallel()
	exe, sum, env, _ := unpacker(t)
	dir := t.TempDir()
	if _, err := PrepareRuntime(context.Background(), exe, sum, dir, env, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	name := "runtime-" + sum[:16]
	if runtime.GOOS == "windows" {
		name += ".ready"
	}
	stale := func(fs.FileInfo) bool { return true }
	if removed, err := RemoveRuntime(dir, name, func(fs.FileInfo) bool { return false }); removed || err != nil {
		t.Errorf("RemoveRuntime of a runtime that is not stale = %v, %v; want it kept", removed, err)
	}
	unlock, err := lock(context.Background(), filepath.Join(dir, "locks", "runtime-"+sum[:16]+".lock"))
	if err != nil {
		t.Fatal(err)
	}
	removed, err := RemoveRuntime(dir, name, stale)
	unlock()
	if removed || err != nil {
		t.Errorf("RemoveRuntime while the runtime is being prepared = %v, %v; want it kept", removed, err)
	}
	if removed, err := RemoveRuntime(dir, name, stale); !removed || err != nil {
		t.Errorf("RemoveRuntime = %v, %v; want it removed", removed, err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "locks" && e.Name() != "logs" { // logs on Windows
			t.Errorf("RemoveRuntime left %s", e.Name())
		}
	}
	if removed, err := RemoveRuntime(dir, name, stale); removed || err != nil {
		t.Errorf("RemoveRuntime of a removed runtime = %v, %v; want nothing to do", removed, err)
	}
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
