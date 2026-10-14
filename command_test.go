package gogrep

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/odipar/gogrep/internal/fakeopengrep"
)

// TestMain lets the test binary stand in for opengrep: run with
// GOGREP_TEST_FAKE_OPENGREP=1, it is fakeopengrep.Main. Run with
// GOGREP_TEST_SIGPROBE=1, it prints whether it started with SIGINT ignored.
func TestMain(m *testing.M) {
	if os.Getenv("GOGREP_TEST_SIGPROBE") == "1" {
		fmt.Println(signal.Ignored(os.Interrupt))
		os.Exit(0)
	}
	if os.Getenv("GOGREP_TEST_FAKE_OPENGREP") == "1" {
		os.Exit(fakeopengrep.Main(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// newFakeEngine returns an Engine that runs the fake opengrep, in an
// environment with env and GOGREP_TEST_FAKE_OPENGREP=1.
func newFakeEngine(t *testing.T, env ...string) *Engine {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return newEngine(t, Config{Opengrep: exe, Env: append([]string{"GOGREP_TEST_FAKE_OPENGREP=1"}, env...)})
}

// A fakeRun is what the fake opengrep reported about its run.
type fakeRun struct {
	Args []string
	Dir  string
	Env  map[string]string
}

// runFake runs cmd, which runs the fake opengrep with --sarif, and returns
// what the fake reported.
func runFake(t *testing.T, cmd *Cmd) (fakeRun, error) {
	t.Helper()
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err := cmd.Run()
	var log struct {
		Runs []struct{ Properties fakeRun }
	}
	if jerr := json.Unmarshal(out.Bytes(), &log); jerr != nil || len(log.Runs) != 1 {
		t.Fatalf("the fake opengrep wrote %q, %q (%v)", out.String(), stderr.String(), jerr)
	}
	return log.Runs[0].Properties, err
}

func TestCommand(t *testing.T) {
	t.Parallel()
	e := newFakeEngine(t, "SEMGREP_RULES=kept", "GOGREP_TEST_FAKE_ENV=SEMGREP_RULES,LC_ALL,XDG_CACHE_HOME")
	dir := t.TempDir()
	writeTree(t, dir, shadowing)
	ctx := context.Background()
	exe, _ := os.Executable()

	cmd, err := e.Command(ctx, dir, nil, "scan", "--sarif", ".")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Path != exe || !slices.Equal(cmd.Args, []string{exe, "scan", "--sarif", "."}) || cmd.Dir != dir || cmd.foreground {
		t.Errorf("Command = %+v; want opengrep's args verbatim, in %s", cmd, dir)
	}
	run, err := runFake(t, cmd)
	wd, _ := os.Stat(run.Dir)
	want, _ := os.Stat(dir)
	if err != nil || !slices.Equal(run.Args, []string{"scan", "--sarif", "."}) || !os.SameFile(wd, want) {
		t.Errorf("Run = %v; the fake ran with %q in %s", err, run.Args, run.Dir)
	}
	if run.Env["SEMGREP_RULES"] != "kept" || runtime.GOOS != "windows" && run.Env["LC_ALL"] != "C.UTF-8" {
		t.Errorf("the fake ran with %q; want Config.Env's SEMGREP_RULES and the locale fix", run.Env)
	}
	if r := run.Env["XDG_CACHE_HOME"]; runtime.GOOS != "windows" && !strings.HasPrefix(r, filepath.Join(e.cacheDir, "runtime-")) {
		t.Errorf("the fake ran with XDG_CACHE_HOME=%s; want the runtime in %s", r, e.cacheDir)
	}
	if err := cmd.Run(); err == nil {
		t.Errorf("a second Run = nil, want an error")
	}

	// Fields changed before Run are honoured.
	other := t.TempDir()
	cmd, err = e.Command(ctx, dir, &CommandOptions{Foreground: true}, "scan", "--sarif")
	if err != nil || !cmd.foreground {
		t.Fatalf("Command = %+v, %v; want a foreground Cmd", cmd, err)
	}
	cmd.Args = append(cmd.Args, "extra")
	cmd.Dir = other
	cmd.Env = append(cmd.Env, "GOGREP_TEST_FAKE_EXIT=3")
	run, err = runFake(t, cmd)
	var exitErr *ExitError
	wd, _ = os.Stat(run.Dir)
	want, _ = os.Stat(other)
	if !errors.As(err, &exitErr) || exitErr.Code != 3 || exitErr.Stderr != nil || err.Error() != "opengrep exited with code 3" ||
		!slices.Equal(run.Args, []string{"scan", "--sarif", "extra"}) || !os.SameFile(wd, want) {
		t.Errorf("Run of a changed Cmd = %v; the fake ran with %q in %s", err, run.Args, run.Dir)
	}

	cmd, err = e.Command(ctx, dir, nil, "--version")
	if err != nil {
		t.Fatal(err)
	}
	cmd.Path = filepath.Join(t.TempDir(), "missing")
	if err := cmd.Run(); !errors.Is(err, ErrNoOpengrep) {
		t.Errorf("Run of a missing executable = %v, want ErrNoOpengrep", err)
	}
}

func TestCommandSelection(t *testing.T) {
	t.Parallel()
	e := newFakeEngine(t)
	dir := t.TempDir()
	writeTree(t, dir, shadowing)
	ctx := context.Background()
	inject := func(exclude bool) []string {
		args := []string{"scan", "--config", "<selection>", "--no-rewrite-rule-ids", "--disable-version-check"}
		if exclude {
			args = append(args, "--exclude=opengrep/gogrep/rules/test")
		}
		return append(args, "--sarif", "--", "a.go")
	}
	tests := []struct {
		name string
		opts *CommandOptions
		want []string // the project rules selected
		args []string
	}{
		{"the default suite", &CommandOptions{Selection: &Selection{}}, []string{"project.go.no-exec-command"}, inject(true)},
		{"rules", &CommandOptions{Selection: &Selection{Rules: []string{"todo-marker"}}}, []string{"project.generic.todo-marker"}, inject(true)},
		{"no project rules", &CommandOptions{Selection: &Selection{Suites: []string{"all"}}, NoProjectRules: true}, nil, inject(false)},
	}
	for _, tt := range tests {
		cmd, err := e.Command(ctx, dir, tt.opts, "scan", "--sarif", "--", "a.go")
		if err != nil {
			t.Errorf("%s: Command = %v", tt.name, err)
			continue
		}
		args := slices.Clone(cmd.Args[1:])
		config := args[2]
		args[2] = "<selection>"
		if !slices.Equal(args, tt.args) || filepath.Dir(config) != filepath.Join(e.cacheDir, "selections") {
			t.Errorf("%s: Command args = %q, want %q with a selection in the cache", tt.name, cmd.Args[1:], tt.args)
		}
		data, err := os.ReadFile(config)
		var got []string
		for _, line := range strings.Split(string(data), "\n") {
			if id, ok := strings.CutPrefix(strings.TrimSpace(line), "- id: project."); ok {
				got = append(got, "project."+id)
			}
		}
		if err != nil || !slices.Equal(got, tt.want) {
			t.Errorf("%s: the selection holds project rules %q, %v; want %q", tt.name, got, err, tt.want)
		}
	}

	for _, tt := range []struct {
		opts *CommandOptions
		args []string
		err  string
	}{
		{&CommandOptions{Selection: &Selection{}}, []string{"ci"}, "a command with a Selection must be a scan"},
		{&CommandOptions{Selection: &Selection{}}, nil, "a command with a Selection must be a scan"},
		{&CommandOptions{Selection: &Selection{Rules: []string{"todo-marker"}}, NoProjectRules: true}, []string{"scan"}, "rule todo-marker matches no rule"},
		{&CommandOptions{Selection: &Selection{Suites: []string{"mine"}}, NoProjectRules: true}, []string{"scan"}, `unknown suite "mine"`},
	} {
		if _, err := e.Command(ctx, dir, tt.opts, tt.args...); err == nil || err.Error() != tt.err {
			t.Errorf("Command(%+v, %q) = %v, want %q", tt.opts, tt.args, err, tt.err)
		}
	}
	if _, err := e.Command(ctx, "relative", nil, "scan"); err == nil {
		t.Errorf("Command in a relative directory = nil error, want one")
	}
	missing := newEngine(t, Config{Opengrep: filepath.Join(t.TempDir(), "opengrep")})
	if _, err := missing.Command(ctx, dir, nil, "scan"); !errors.Is(err, ErrNoOpengrep) {
		t.Errorf("Command without opengrep = %v, want ErrNoOpengrep", err)
	}
}

// Each Cmd's Env is its own: changing it, in place or by appending, changes
// no other Cmd's, also when the Engine's environment needs no locale fix and
// there is no runtime to point opengrep at.
func TestCommandEnvIsCopied(t *testing.T) {
	t.Parallel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	notDir := filepath.Join(t.TempDir(), "file")
	writeTree(t, filepath.Dir(notDir), map[string]string{"file": ""})
	env := make([]string, 0, 10) // room to append in place
	env = append(env, "GOGREP_TEST_FAKE_OPENGREP=1", "LANG=en_US.UTF-8", "HOME=/home/real")
	e := newEngine(t, Config{Opengrep: exe, Env: env, CacheDir: notDir}) // so preparing the runtime fails
	ctx, dir := context.Background(), t.TempDir()
	c1, err := e.Command(ctx, dir, nil, "--version")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := e.Command(ctx, dir, nil, "--version")
	if err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(c2.Env)
	c1.Env[len(c1.Env)-1] = "HOME=/tmp/just-for-c1"
	c1.Env = append(c1.Env, "FOR_C1=1")
	c3, err := e.Command(ctx, dir, nil, "--version")
	if err != nil {
		t.Fatal(err)
	}
	c2.Env = append(c2.Env, "FOR_C2=2")
	if !slices.Equal(c3.Env, want) || c1.Env[len(c1.Env)-1] != "FOR_C1=1" {
		t.Errorf("after changing one Cmd's Env, another's is %q and the first ends in %q; want %q and FOR_C1=1", c3.Env, c1.Env[len(c1.Env)-1], want)
	}
}

// A done ctx kills the command, and Run returns ctx's error.
func TestCommandCancelled(t *testing.T) {
	t.Parallel()
	ready := filepath.Join(t.TempDir(), "ready")
	e := newFakeEngine(t, "GOGREP_TEST_FAKE_WAIT="+ready)
	ctx, cancel := context.WithCancel(context.Background())
	cmd, err := e.Command(ctx, t.TempDir(), nil, "scan")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(ready); err == nil {
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
			t.Errorf("Run, cancelled = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run still runs after its ctx was cancelled")
	}
}
