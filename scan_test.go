package gogrep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// scanned decodes the run that the fake opengrep reported in res.SARIF.
func scanned(t *testing.T, res *Result) (driver string, run fakeRun) {
	t.Helper()
	var log struct {
		Runs []struct {
			Tool       struct{ Driver struct{ Name string } }
			Properties fakeRun
		}
	}
	if err := json.Unmarshal(res.SARIF, &log); err != nil || len(log.Runs) != 1 {
		t.Fatalf("Result.SARIF is not the fake's log (%v): %q", err, res.SARIF)
	}
	return log.Runs[0].Tool.Driver.Name, log.Runs[0].Properties
}

func TestScan(t *testing.T) {
	t.Parallel()
	e := newFakeEngine(t, "SEMGREP_RULES=dropped", "OPENGREP_ENABLE_VERSION_CHECK=1", "LANG=C",
		"GOGREP_TEST_FAKE_ENV=SEMGREP_RULES,OPENGREP_ENABLE_VERSION_CHECK,SEMGREP_LOG_FILE,LC_ALL,XDG_CACHE_HOME", "GOGREP_TEST_FAKE_STDIN=1")
	dir := t.TempDir()
	writeTree(t, dir, shadowing)
	before, _ := os.ReadDir(dir)
	res, err := e.Scan(context.Background(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	driver, run := scanned(t, res)
	wd, _ := os.Stat(run.Dir)
	want, _ := os.Stat(dir)
	if driver != "gogrep" || !os.SameFile(wd, want) || !bytes.HasSuffix(res.SARIF, []byte("}\n")) {
		t.Errorf("the fake ran in %s and Result.SARIF is from %q; want %s and gogrep's log, ending in a newline", run.Dir, driver, dir)
	}
	args := slices.Clone(run.Args)
	if len(args) > 2 {
		if filepath.Dir(args[2]) != filepath.Join(e.cacheDir, "selections") {
			t.Errorf("the selection is %s, want one in the cache", args[2])
		}
		args[2] = "<selection>"
	}
	if want := []string{"scan", "--config", "<selection>", "--no-rewrite-rule-ids", "--disable-version-check", "--exclude=opengrep/gogrep/rules/test", "--sarif", "--", "."}; !slices.Equal(args, want) {
		t.Errorf("the fake ran with %q, want %q", run.Args, want)
	}
	if run.Env["SEMGREP_RULES"] != "" || run.Env["OPENGREP_ENABLE_VERSION_CHECK"] != "" || runtime.GOOS != "windows" && run.Env["LC_ALL"] != "C.UTF-8" {
		t.Errorf("the fake ran with %q; want no SEMGREP_* or OPENGREP_* variable from Config.Env, and the locale fix", run.Env)
	}
	if r := run.Env["XDG_CACHE_HOME"]; runtime.GOOS != "windows" && !strings.HasPrefix(r, filepath.Join(e.cacheDir, "runtime-")) {
		t.Errorf("the fake ran with XDG_CACHE_HOME=%s; want the runtime in %s", r, e.cacheDir)
	}
	log := run.Env["SEMGREP_LOG_FILE"]
	if filepath.Dir(log) != filepath.Join(e.cacheDir, "logs") {
		t.Errorf("the fake ran with SEMGREP_LOG_FILE=%s, want a log of its own in the cache", log)
	} else if _, err := os.Stat(log); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the fake's log file is still there: %v", err)
	}
	if !bytes.Contains(res.Stderr, []byte("stdin \"\"\n")) || !bytes.HasSuffix(res.Stderr, []byte("fake stderr\n")) {
		t.Errorf("Result.Stderr = %q; want an empty stdin reported, and the fake's stderr", res.Stderr)
	}
	if res.Rules != 1 || res.Findings != nil || res.Diagnostics != nil || res.Complete {
		t.Errorf("Result = %d rules, %v, %v, complete %v; want 1 rule and an empty, incomplete log", res.Rules, res.Findings, res.Diagnostics, res.Complete)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != len(before) {
		t.Errorf("Scan wrote into the directory: %v", entries)
	}
}

func TestScanArgs(t *testing.T) {
	t.Parallel()
	e := newFakeEngine(t)
	dir := t.TempDir()
	writeTree(t, dir, shadowing)
	ctx := context.Background()
	tests := []struct {
		opts *ScanOptions
		args []string // after the --config <selection> --no-rewrite-rule-ids --disable-version-check
		n    int
	}{
		{&ScanOptions{Jobs: 2, RuleTimeout: 1500 * time.Millisecond, MaxMemoryMB: 512, MaxTargetBytes: 1 << 20, Targets: []string{"a.go", "sub/b", "-c"}},
			[]string{"--exclude=opengrep/gogrep/rules/test", "--sarif", "-j", "2", "--timeout", "2", "--max-memory", "512", "--max-target-bytes", "1048576", "--", "a.go", "sub/b", "-c"}, 1},
		{&ScanOptions{RuleTimeout: time.Second, Selection: Selection{Suites: []string{"mine"}}},
			[]string{"--exclude=opengrep/gogrep/rules/test", "--sarif", "--timeout", "1", "--", "."}, 2},
		{&ScanOptions{RuleTimeout: -1, NoProjectRules: true, Selection: Selection{Rules: []string{"/^gogrep\\.|^opengrep-rules\\.go\\.lang\\.security\\.audit\\.dangerous-exec-command$/"}}},
			[]string{"--sarif", "--timeout", "0", "--", "."}, 1},
	}
	for _, tt := range tests {
		res, err := e.Scan(ctx, dir, tt.opts)
		if err != nil {
			t.Errorf("Scan(%+v) = %v", tt.opts, err)
			continue
		}
		_, run := scanned(t, res)
		if len(run.Args) < 5 || !slices.Equal(run.Args[5:], tt.args) || res.Rules != tt.n {
			t.Errorf("Scan(%+v) ran the fake with %q and %d rules; want %q after the config, and %d rules", tt.opts, run.Args, res.Rules, tt.args, tt.n)
		}
	}

	for _, tt := range []struct {
		opts *ScanOptions
		err  string
	}{
		{&ScanOptions{Targets: []string{"../x"}}, `scan target "../x" is not a relative path inside the directory`},
		{&ScanOptions{Targets: []string{""}}, `scan target "" is not a relative path inside the directory`},
		{&ScanOptions{Targets: []string{filepath.Join(dir, "a.go")}}, fmt.Sprintf("scan target %q is not a relative path inside the directory", filepath.Join(dir, "a.go"))},
		{&ScanOptions{Jobs: -1}, "ScanOptions.Jobs is negative (-1)"},
		{&ScanOptions{MaxMemoryMB: -1}, "ScanOptions.MaxMemoryMB is negative (-1)"},
		{&ScanOptions{MaxTargetBytes: -1}, "ScanOptions.MaxTargetBytes is negative (-1)"},
		{&ScanOptions{Selection: Selection{Rules: []string{"todo-marker"}}, NoProjectRules: true}, "rule todo-marker matches no rule"},
	} {
		if _, err := e.Scan(ctx, dir, tt.opts); err == nil || err.Error() != tt.err {
			t.Errorf("Scan(%+v) = %v, want %q", tt.opts, err, tt.err)
		}
	}
	if _, err := e.Scan(ctx, "relative", nil); err == nil {
		t.Errorf("Scan of a relative directory = nil error, want one")
	}
	missing := newEngine(t, Config{Opengrep: filepath.Join(t.TempDir(), "opengrep")})
	if _, err := missing.Scan(ctx, dir, nil); !errors.Is(err, ErrNoOpengrep) {
		t.Errorf("Scan without opengrep = %v, want ErrNoOpengrep", err)
	}
}

func TestScanErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tests := []struct {
		env    []string
		code   int  // the *ExitError's code; 0 for an *OutputError
		result bool // the *ExitError has a Result
		text   string
	}{
		{[]string{"GOGREP_TEST_FAKE_NO_SARIF=1"}, 0, false, "opengrep exited 0 but wrote no SARIF: output is not a SARIF log: unexpected end of JSON input"},
		{[]string{"GOGREP_TEST_FAKE_EXIT=2"}, 2, true, "opengrep exited with code 2: fake stderr"},
		{[]string{"GOGREP_TEST_FAKE_EXIT=7", "GOGREP_TEST_FAKE_NO_SARIF=1"}, 7, false, "opengrep exited with code 7: fake stderr"},
	}
	for _, tt := range tests {
		res, err := newFakeEngine(t, tt.env...).Scan(context.Background(), dir, nil)
		var exitErr *ExitError
		var outErr *OutputError
		switch {
		case res != nil || err == nil || err.Error() != tt.text:
			t.Errorf("Scan with %q = %v, %v; want no Result and %q", tt.env, res, err, tt.text)
		case tt.code == 0 && (!errors.As(err, &outErr) || !errors.Is(err, ErrNoSARIF) || !bytes.Equal(outErr.Stderr, []byte("fake stderr\n"))):
			t.Errorf("Scan with %q = %#v, want an *OutputError that is ErrNoSARIF, with the fake's stderr", tt.env, err)
		case tt.code != 0 && (!errors.As(err, &exitErr) || exitErr.Code != tt.code || (exitErr.Result != nil) != tt.result ||
			!bytes.Equal(exitErr.Stderr, []byte("fake stderr\n")) || errors.Is(err, ErrNoSARIF)):
			t.Errorf("Scan with %q = %#v, want an *ExitError with code %d, a Result %v and the fake's stderr", tt.env, err, tt.code, tt.result)
		case tt.result && (exitErr.Result.Rules == 0 || !bytes.Equal(exitErr.Result.Stderr, exitErr.Stderr)):
			t.Errorf("the *ExitError's Result = %+v, want the scan's", exitErr.Result)
		}
	}
}

// Result.Stderr keeps the end of opengrep's stderr, and ScanOptions.Stderr
// gets all of it.
func TestScanStderr(t *testing.T) {
	t.Parallel()
	e := newFakeEngine(t, "GOGREP_TEST_FAKE_STDERR=100000")
	var live bytes.Buffer
	res, err := e.Scan(context.Background(), t.TempDir(), &ScanOptions{Stderr: &live})
	if err != nil {
		t.Fatal(err)
	}
	want := string(bytes.Repeat([]byte("x"), 100000)) + "\nfake stderr\n"
	if live.String() != want || string(res.Stderr) != want[len(want)-64<<10:] {
		t.Errorf("ScanOptions.Stderr got %d bytes and Result.Stderr %d, ending %q; want %d and 65536", live.Len(), len(res.Stderr), res.Stderr[max(len(res.Stderr)-20, 0):], len(want))
	}
}

// Findings are decoded from the log, which is rebranded.
func TestScanFindings(t *testing.T) {
	t.Parallel()
	recorded, err := filepath.Abs(filepath.Join("internal", "sarif", "testdata", "suppressed.json"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := newFakeEngine(t, "GOGREP_TEST_FAKE_SARIF="+recorded).Scan(context.Background(), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	var suppressed []bool
	for _, f := range res.Findings {
		if f.RuleID != "project.go.no-exec-command" || f.Level != "warning" || f.Path != "a.go" || f.Fingerprint == "" || !strings.HasPrefix(f.Snippet, "\texec.Command(") {
			t.Errorf("finding %+v; want project.go.no-exec-command in a.go, a warning", f)
		}
		lines, suppressed = append(lines, f.StartLine), append(suppressed, f.Suppressed)
	}
	if !slices.Equal(lines, []int{6, 7, 8, 9, 11}) || !slices.Equal(suppressed, []bool{false, true, true, false, true}) {
		t.Errorf("findings on lines %v, suppressed %v", lines, suppressed)
	}
	if !res.Complete || len(res.Diagnostics) != 0 || !bytes.Contains(res.SARIF, []byte(`"name":"gogrep"`)) {
		t.Errorf("Result = complete %v, %v; want a complete run without diagnostics, rebranded", res.Complete, res.Diagnostics)
	}
}

// A done ctx kills opengrep and every process it started, and Scan returns
// ctx's error.
func TestScanCancelled(t *testing.T) {
	t.Parallel()
	ready := filepath.Join(t.TempDir(), "ready")
	env := []string{"GOGREP_TEST_FAKE_WAIT=" + ready}
	if canKill {
		env = append(env, "GOGREP_TEST_FAKE_CHILD=1", "PATH="+os.Getenv("PATH")) // the child is sleep
	}
	e := newFakeEngine(t, env...)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		res, err := e.Scan(ctx, t.TempDir(), nil)
		if res != nil {
			err = errors.New("a Result")
		}
		done <- err
	}()
	var pid []byte
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var err error
		if pid, err = os.ReadFile(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fake opengrep never started")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Scan, cancelled = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second): // the runner's WaitDelay, and a second
		t.Fatal("Scan still runs after its ctx was cancelled")
	}
	if canKill {
		checkGone(t, string(pid))
	}
}

// Concurrent scans of different directories each report their own.
func TestScanConcurrently(t *testing.T) {
	t.Parallel()
	e := newFakeEngine(t)
	dirs := make([]string, 8)
	for i := range dirs {
		dirs[i] = t.TempDir()
	}
	var wg sync.WaitGroup
	for _, dir := range dirs {
		wg.Go(func() {
			res, err := e.Scan(context.Background(), dir, nil)
			if err != nil {
				t.Error(err)
				return
			}
			_, run := scanned(t, res)
			wd, _ := os.Stat(run.Dir)
			want, _ := os.Stat(dir)
			if !os.SameFile(wd, want) {
				t.Errorf("a scan of %s ran in %s", dir, run.Dir)
			}
		})
	}
	wg.Wait()
}

// Scan, Command, Cmd.Run and Test leave the process as they found it: its signal
// dispositions, which its later children inherit, its working directory and
// its environment.
func TestNoProcessState(t *testing.T) {
	t.Parallel()
	ignored := func() [2]bool { return [2]bool{signal.Ignored(os.Interrupt), signal.Ignored(syscall.SIGTERM)} }
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probe := func() string {
		cmd := exec.Command(exe)
		cmd.Env = append(os.Environ(), "GOGREP_TEST_SIGPROBE=1")
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	sigs, child, env := ignored(), probe(), os.Environ()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	e := newFakeEngine(t)
	dir := t.TempDir()
	ctx := context.Background()
	if _, err := e.Scan(ctx, dir, nil); err != nil {
		t.Fatal(err)
	}
	for _, foreground := range []bool{false, true} {
		cmd, err := e.Command(ctx, dir, &CommandOptions{Foreground: foreground}, "--version")
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
	}
	project := t.TempDir()
	writeTree(t, project, fixtures)
	if _, err := e.Test(ctx, project, nil); err != nil {
		t.Fatal(err)
	}

	if got := ignored(); got != sigs {
		t.Errorf("SIGINT and SIGTERM ignored: %v, want %v as before", got, sigs)
	}
	if got := probe(); got != child {
		t.Errorf("a child started with SIGINT ignored: %s, want %s as before", got, child)
	}
	if got, _ := os.Getwd(); got != wd {
		t.Errorf("the working directory is %s, want %s", got, wd)
	}
	if got := os.Environ(); !slices.Equal(got, env) {
		t.Errorf("the environment changed")
	}
}
