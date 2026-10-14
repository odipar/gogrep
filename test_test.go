package gogrep

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// fixtures is a project with rule test fixtures: a passes when opengrep
// loads its rule and finds nothing, b's expected.txt differs, c's rule.ref
// names no rule, d has no samples, and e has no expected.txt. No fixture
// tests project.generic.todo-marker.
var fixtures = map[string]string{
	"opengrep/gogrep/rules/go/no-exec-command.yaml":  noExecRule,
	"opengrep/gogrep/rules/generic/todo-marker.yaml": rule("todo-marker", "generic"),
	ProjectTestsDir + "/go/a/rule.ref":               "no-exec-command\n",
	ProjectTestsDir + "/go/a/a.go":                   "package a\n",
	ProjectTestsDir + "/go/a/expected.txt":           "",
	ProjectTestsDir + "/go/b/rule.ref":               "no-exec-command\n",
	ProjectTestsDir + "/go/b/b.go":                   "package b\n",
	ProjectTestsDir + "/go/b/expected.txt":           "| b.go:1:1:1:2 | old |\n",
	ProjectTestsDir + "/go/c/rule.ref":               "nope\n",
	ProjectTestsDir + "/go/c/c.go":                   "package c\n",
	ProjectTestsDir + "/go/d/rule.ref":               "no-exec-command\n",
	ProjectTestsDir + "/go/e/rule.ref":               "no-exec-command\n",
	ProjectTestsDir + "/go/e/e.go":                   "package e\n",
}

// newTestEngine returns an Engine whose fake opengrep, run with env, loads
// project.go.no-exec-command and finds nothing.
func newTestEngine(t *testing.T, env ...string) *Engine {
	t.Helper()
	log := filepath.Join(t.TempDir(), "log.json")
	writeTree(t, filepath.Dir(log), map[string]string{"log.json": `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "opengrep", "rules": [{"id": "project.go.no-exec-command"}]}},` +
		`"invocations": [{"executionSuccessful": true, "toolExecutionNotifications": []}], "results": []}]}`})
	return newFakeEngine(t, append(env, "GOGREP_TEST_FAKE_SARIF="+log)...)
}

// describeResults returns how each test went, a line each.
func describeResults(results []*TestResult) string {
	var b strings.Builder
	for _, r := range results {
		fmt.Fprintf(&b, "%s %q %s learned=%v missing=%v diff=%v %q ran=%v\n",
			strings.TrimPrefix(r.Name, ProjectTestsDir+"/"), r.Stage, r.RuleID, r.Learned, r.MissingExpected, r.Diff != "", r.Details, r.Command != nil)
	}
	return b.String()
}

func TestTest(t *testing.T) {
	t.Parallel()
	e := newTestEngine(t)
	dir := t.TempDir()
	writeTree(t, dir, fixtures)
	ctx := context.Background()
	exe, _ := os.Executable()

	var progress []string
	rep, err := e.Test(ctx, dir, &TestOptions{Progress: func(done, total int, r *TestResult) {
		name := "<nil>"
		if r != nil {
			name = filepath.Base(r.Name)
		}
		progress = append(progress, fmt.Sprintf("%d/%d %s", done, total, name))
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := `go/a "" project.go.no-exec-command learned=false missing=false diff=false [] ran=true
go/b "RESULT" project.go.no-exec-command learned=false missing=false diff=true [] ran=true
go/c "RULE"  learned=false missing=false diff=false ["rule reference \"nope\" matches no rule; list candidates with: gogrep rules --rule '/nope/'"] ran=false
go/d "SETUP"  learned=false missing=false diff=false ["no code samples"] ran=false
go/e "RESULT" project.go.no-exec-command learned=false missing=true diff=false [] ran=true
`
	if got := describeResults(rep.Results); got != want {
		t.Errorf("Test =\n%s\nwant\n%s", got, want)
	}
	if want := []string{"0/5 <nil>", "1/5 a", "2/5 b", "3/5 c", "4/5 d", "5/5 e"}; !slices.Equal(progress, want) {
		t.Errorf("Progress was called with %q, want %q", progress, want)
	}
	a := rep.Results[0]
	if a.Dir != filepath.Join(dir, filepath.FromSlash(a.Name)) || len(a.Command) == 0 || a.Command[0] != exe || string(a.Stderr) != "fake stderr\n" {
		t.Errorf("the first result = %+v; want its absolute directory, the command line and the fake's stderr", a)
	}
	failed := []string{ProjectTestsDir + "/go/b", ProjectTestsDir + "/go/c", ProjectTestsDir + "/go/d", ProjectTestsDir + "/go/e"}
	if rep.Passed != 1 || rep.Learned != 0 || !slices.Equal(rep.Failed, failed) || !slices.Equal(rep.Untested, []string{"project.generic.todo-marker"}) {
		t.Errorf("TestReport = %d passed, %d learned, failed %q, untested %q", rep.Passed, rep.Learned, rep.Failed, rep.Untested)
	}
	for _, name := range []string{"b", "e"} {
		if data, err := os.ReadFile(filepath.Join(dir, ProjectTestsDir, "go", name, "actual.txt")); err != nil || len(data) != 0 {
			t.Errorf("%s/actual.txt = %q, %v; want the empty results", name, data, err)
		}
	}

	rep, err = e.Test(ctx, dir, &TestOptions{Learn: true, Jobs: 1})
	if err != nil || rep.Passed != 3 || rep.Learned != 2 || len(rep.Failed) != 2 {
		t.Errorf("Test with Learn = %+v, %v; want 3 passed, 2 of them learned", rep, err)
	}
	for _, name := range []string{"b", "e"} {
		if data, err := os.ReadFile(filepath.Join(dir, ProjectTestsDir, "go", name, "expected.txt")); err != nil || len(data) != 0 {
			t.Errorf("%s/expected.txt = %q, %v; want the empty results", name, data, err)
		}
	}

	// Paths and a Selection run some tests, and leave Untested unset;
	// tests that fail at SETUP or RULE always run.
	for _, opts := range []*TestOptions{
		{Paths: []string{ProjectTestsDir + "/go/a", filepath.Join(dir, ProjectTestsDir, "go", "c", "c.go")}},
		{Selection: Selection{Rules: []string{"todo-marker"}}, Paths: []string{ProjectTestsDir + "/go/a", ProjectTestsDir + "/go/c"}},
	} {
		rep, err = e.Test(ctx, dir, opts)
		var names []string
		for _, r := range rep.Results {
			names = append(names, filepath.Base(r.Name))
		}
		want := []string{"a", "c"}
		if opts.Selection.Rules != nil {
			want = []string{"c"}
		}
		if err != nil || !slices.Equal(names, want) || rep.Untested != nil {
			t.Errorf("Test(%+v) = %q, untested %q, %v; want %q", opts, names, rep.Untested, err, want)
		}
	}
}

func TestTestErrors(t *testing.T) {
	t.Parallel()
	e := newTestEngine(t)
	dir := t.TempDir()
	writeTree(t, dir, fixtures)
	ctx := context.Background()
	tests := []struct {
		dir  string
		opts *TestOptions
		text string
		is   error
	}{
		{t.TempDir(), nil, "no rule test directory: opengrep/gogrep/rules/test", ErrNoTestRoot},
		{dir, &TestOptions{Paths: []string{"opengrep/gogrep/rules/go"}}, "opengrep/gogrep/rules/go is not under opengrep/gogrep/rules/test", nil},
		{dir, &TestOptions{Paths: []string{ProjectTestsDir + "/go/f"}}, "opengrep/gogrep/rules/test/go/f does not exist", nil},
		{dir, &TestOptions{Selection: Selection{Rules: []string{"nope"}}}, "rule nope matches no rule", ErrNoRules},
		{dir, &TestOptions{Selection: Selection{Filters: []Filter{{Field: "id"}}}}, "the selection matches no rules", ErrNoRules},
		{dir, &TestOptions{Selection: Selection{Rules: []string{"todo-marker"}}, Paths: []string{ProjectTestsDir + "/go/a"}}, "no tests match the selection", nil},
		{dir, &TestOptions{ReadOnly: true, Learn: true}, "TestOptions.ReadOnly excludes Learn and KeepSARIF", nil},
		{"relative", nil, `directory "relative" is not an absolute path`, nil},
	}
	for _, tt := range tests {
		rep, err := e.Test(ctx, tt.dir, tt.opts)
		if rep != nil || err == nil || err.Error() != tt.text || tt.is != nil && !errors.Is(err, tt.is) {
			t.Errorf("Test(%+v) = %v, %v; want %q", tt.opts, rep, err, tt.text)
		}
	}

	missing := newEngine(t, Config{Opengrep: filepath.Join(t.TempDir(), "opengrep")})
	if rep, err := missing.Test(ctx, dir, nil); rep != nil || !errors.Is(err, ErrNoOpengrep) {
		t.Errorf("Test without opengrep = %v, %v; want ErrNoOpengrep", rep, err)
	}
	// Tests that fail before opengrep runs need none.
	rep, err := missing.Test(ctx, dir, &TestOptions{Paths: []string{ProjectTestsDir + "/go/c", ProjectTestsDir + "/go/d"}})
	if err != nil || len(rep.Results) != 2 || len(rep.Failed) != 2 {
		t.Errorf("Test of tests that need no opengrep, without one = %+v, %v; want 2 failed tests", rep, err)
	}
}

// treeState returns the names of the files and directories under dir, and
// the modes, sizes and modification times of the files. (Windows updates a
// directory's time lazily.)
func treeState(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		switch {
		case err != nil:
			return err
		case d.IsDir():
			fmt.Fprintf(&b, "%s/\n", p)
		default:
			fmt.Fprintf(&b, "%s %v %d %d\n", p, fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// A ReadOnly Test changes no file in the fixtures.
func TestTestReadOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	stale := map[string]string{
		ProjectTestsDir + "/go/a/actual.txt":   "stale\n",
		ProjectTestsDir + "/go/a/actual.sarif": "{}",
		ProjectTestsDir + "/go/c/actual.txt":   "stale\n",
	}
	writeTree(t, dir, fixtures)
	writeTree(t, dir, stale)
	before := treeState(t, dir)
	rep, err := newTestEngine(t).Test(context.Background(), dir, &TestOptions{ReadOnly: true})
	if err != nil || len(rep.Results) != 5 {
		t.Fatalf("Test = %+v, %v; want 5 results", rep, err)
	}
	if after := treeState(t, dir); after != before {
		t.Errorf("a ReadOnly Test changed the fixtures from\n%s\nto\n%s", before, after)
	}
}

// When ctx is done, Test returns the tests reported so far, and writes no
// files for the others.
func TestTestCancelled(t *testing.T) {
	t.Parallel()
	ready := filepath.Join(t.TempDir(), "ready")
	e := newTestEngine(t, "GOGREP_TEST_FAKE_WAIT="+ready)
	dir := t.TempDir()
	writeTree(t, dir, fixtures)
	writeTree(t, dir, map[string]string{ProjectTestsDir + "/go/b/actual.txt": "stale\n"})
	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		rep *TestReport
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		rep, err := e.Test(ctx, dir, &TestOptions{Paths: []string{ProjectTestsDir + "/go/c", ProjectTestsDir + "/go/b"}})
		done <- outcome{rep, err}
	}()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fake opengrep never started")
		}
	}
	cancel()
	var o outcome
	select {
	case o = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Test still runs after its ctx was cancelled")
	}
	// b runs first, so c, which needs no opengrep, waits for it.
	if !errors.Is(o.err, context.Canceled) || o.rep == nil || len(o.rep.Results) != 0 {
		t.Errorf("Test, cancelled = %+v, %v; want no results and context.Canceled", o.rep, o.err)
	}
	if data, err := os.ReadFile(filepath.Join(dir, ProjectTestsDir, "go", "b", "actual.txt")); string(data) != "stale\n" {
		t.Errorf("b/actual.txt = %q, %v; want it untouched", data, err)
	}
}

func TestAcceptTests(t *testing.T) {
	t.Parallel()
	e := newEngine(t, Config{})
	dir := t.TempDir()
	writeTree(t, dir, fixtures)
	writeTree(t, dir, map[string]string{
		ProjectTestsDir + "/go/b/actual.txt": "new\n",
		ProjectTestsDir + "/go/d/actual.txt": "setup\n",
	})
	if acc, err := e.AcceptTests(dir, []string{ProjectTestsDir + "/go/e"}); err != nil || len(acc) != 0 {
		t.Errorf("AcceptTests of a fixture without actual.txt = %v, %v; want none", acc, err)
	}
	acc, err := e.AcceptTests(dir, nil)
	if want := []Acceptance{{Name: ProjectTestsDir + "/go/b"}}; err != nil || !slices.Equal(acc, want) {
		t.Errorf("AcceptTests = %v, %v; want %v", acc, err, want)
	}
	expected := filepath.Join(dir, ProjectTestsDir, "go", "b", "expected.txt")
	if data, err := os.ReadFile(expected); string(data) != "new\n" {
		t.Errorf("b/expected.txt = %q, %v; want the accepted actual.txt", data, err)
	}
	if fi, err := os.Stat(expected); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("b/expected.txt: %v, %v; want mode 0600", fi.Mode(), err)
	}
	if _, err := e.AcceptTests(t.TempDir(), nil); !errors.Is(err, ErrNoTestRoot) {
		t.Errorf("AcceptTests without a test root = %v, want ErrNoTestRoot", err)
	}
}
