package ruletest

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/odipar/gogrep/internal/rules"
)

const (
	testBin    = "/opt/opengrep/opengrep"
	testConfig = "/cache/gogrep/selections/0123456789abcdef.yaml"
)

// A fake is the opengrep run that fakeExec answers with for one fixture.
type fake struct {
	out    Output
	before func(ctx context.Context) // runs before Exec returns, if set
}

// fakeRunner is a Runner whose Exec answers with the fake of the fixture
// directory it runs in, and records the arguments of each call.
type fakeRunner struct {
	Runner
	fakes map[string]*fake // by fixture directory
	mu    sync.Mutex
	calls map[string][]string // by fixture directory
}

func newFakeRunner() *fakeRunner {
	r := &fakeRunner{fakes: map[string]*fake{}, calls: map[string][]string{}}
	r.Bin = testBin
	r.Exec = func(ctx context.Context, dir string, args []string) ([]byte, []byte, int, error) {
		r.mu.Lock()
		r.calls[dir] = args
		f := r.fakes[dir]
		r.mu.Unlock()
		if f == nil {
			return nil, nil, -1, errors.New("no fake for " + dir)
		}
		if f.before != nil {
			f.before(ctx)
		}
		return f.out.Stdout, f.out.Stderr, f.out.Code, f.out.Err
	}
	return r
}

// run runs tests and returns their verdicts, checking that Run reported
// each of them, in order.
func (r *fakeRunner) run(t *testing.T, tests []*Test) ([]*Verdict, error) {
	t.Helper()
	var reported []*Verdict
	vs, err := r.Run(context.Background(), tests, func(v *Verdict) { reported = append(reported, v) })
	if !slices.Equal(reported, vs) {
		t.Errorf("Run reported %d verdicts, and returned %d others", len(reported), len(vs))
	}
	return vs, err
}

// describe returns verdicts as text: for each, a status line with the
// test's name, "missing expected.txt" when the fixture has none, the diff,
// and the details, indented.
func describe(vs []*Verdict) string {
	var b strings.Builder
	for _, v := range vs {
		status := "PASSED"
		switch {
		case v.Learned:
			status = "LEARNED"
		case v.Stage != "":
			status = "FAILED(" + string(v.Stage) + ")"
		}
		fmt.Fprintf(&b, "%s %s\n", status, v.Name)
		if v.Missing {
			b.WriteString("missing expected.txt\n")
		}
		b.WriteString(v.Diff)
		for _, l := range v.Details {
			fmt.Fprintf(&b, "  %s\n", l)
		}
	}
	return b.String()
}

// fixtureSpec describes a fixture for addTest.
type fixtureSpec struct {
	files  map[string]string // files in the fixture besides a.go
	setup  error
	refErr error
	out    Output // what opengrep reports when the test has a rule
}

// addTest creates the fixture name with a sample a.go under dir and returns
// a test of it, with r faking its opengrep run.
func (r *fakeRunner) addTest(t *testing.T, dir, name string, spec fixtureSpec) *Test {
	t.Helper()
	fdir := filepath.Join(dir, name)
	writeTree(t, fdir, map[string]string{"a.go": "package a\n"})
	writeTree(t, fdir, spec.files)
	test := &Test{
		Fixture: &Fixture{Name: "test/" + name, Dir: fdir, Namespace: "go", Ref: "no-exec-command", Samples: []string{"a.go"}, Setup: spec.setup},
		Err:     spec.refErr,
	}
	if spec.setup == nil && spec.refErr == nil {
		test.Rule, test.Config = &rules.Rule{ID: testRuleID, Set: "project"}, testConfig
		r.fakes[fdir] = &fake{out: spec.out}
	}
	return test
}

// results returns opengrep's output with one result in a.go for each message.
func results(msgs ...string) Output {
	var rs []any
	for _, m := range msgs {
		rs = append(rs, result("a.go", [4]int{1, 1, 1, 2}, m))
	}
	return Output{Stdout: sarifLog(rs, nil)}
}

// addTests adds a fixture for each way a test can go, under a new directory.
func (r *fakeRunner) addTests(t *testing.T) []*Test {
	t.Helper()
	dir := t.TempDir()
	stale := map[string]string{"actual.txt": "stale\n", "actual.sarif": "stale"}
	notFound := recordedOutput(t, "file-not-found")
	notFound.Stderr = []byte("oops\n")
	return []*Test{
		r.addTest(t, dir, "a-pass", fixtureSpec{
			files: map[string]string{"expected.txt": "| a.go:1:1:1:2 | m |\n", "actual.txt": "stale\n", "actual.sarif": "stale"},
			out:   results("m"),
		}),
		r.addTest(t, dir, "b-diff", fixtureSpec{files: map[string]string{"expected.txt": "| a.go:1:1:1:2 | old |\n"}, out: results("new")}),
		r.addTest(t, dir, "c-missing", fixtureSpec{out: results("m")}),
		r.addTest(t, dir, "d-setup", fixtureSpec{files: stale, setup: errors.New("no code samples")}),
		r.addTest(t, dir, "e-rule", fixtureSpec{files: stale, refErr: errors.New(`rule reference "x" matches no rule`)}),
		r.addTest(t, dir, "f-invalid", fixtureSpec{files: stale, out: recordedOutput(t, "invalid-schema")}),
		r.addTest(t, dir, "g-run", fixtureSpec{files: stale, out: notFound}),
		r.addTest(t, dir, "h-empty", fixtureSpec{files: map[string]string{"expected.txt": "\uFEFF\r\n"}, out: results()}),
	}
}

// The verdicts of the tests from addTests.
const testsVerdicts = `PASSED test/a-pass
FAILED(RESULT) test/b-diff
--- expected
+++ actual
@@ -1,1 +1,1 @@
-| a.go:1:1:1:2 | old |
+| a.go:1:1:1:2 | new |
FAILED(RESULT) test/c-missing
missing expected.txt
--- expected
+++ actual
@@ -0,0 +1,1 @@
+| a.go:1:1:1:2 | m |
FAILED(SETUP) test/d-setup
  no code samples
FAILED(RULE) test/e-rule
  rule reference "x" matches no rule
FAILED(RULE) test/f-invalid
  InvalidRuleSchemaError: One of these properties is missing: 'message'
  SemgrepError: invalid configuration file found (1 configs were invalid)
FAILED(RUN) test/g-run
  SemgrepError: File not found: missing.go
  opengrep exited with code 2
  > oops
PASSED test/h-empty
`

// checkVerdicts checks that vs, err are the verdicts of the tests from
// addTests, without file errors.
func checkVerdicts(t *testing.T, vs []*Verdict, err error) {
	t.Helper()
	if got := describe(vs); err != nil || got != testsVerdicts {
		t.Errorf("Run = %v, verdicts\n%s\nwant no error, verdicts\n%s", err, got, testsVerdicts)
	}
	for _, v := range vs {
		if len(v.FileErrors) > 0 {
			t.Errorf("%s: file errors %q", v.Name, v.FileErrors)
		}
	}
}

// checkFile checks that the file name in the fixture of test holds want, and
// that only its owner can read and write it; want "-" means it must not
// exist.
func checkFile(t *testing.T, test *Test, name, want string) {
	t.Helper()
	file := filepath.Join(test.Dir, name)
	data, err := os.ReadFile(file)
	switch {
	case want == "-" && !errors.Is(err, os.ErrNotExist):
		t.Errorf("%s/%s exists (%v), want none", test.Name, name, err)
	case want == "-":
	case err != nil:
		t.Errorf("%s/%s: %v", test.Name, name, err)
	case string(data) != want:
		t.Errorf("%s/%s = %q, want %q", test.Name, name, data, want)
	case runtime.GOOS != "windows":
		if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s/%s has mode %v (%v), want 0600", test.Name, name, fi.Mode().Perm(), err)
		}
	}
}

// checkNoTemp checks that no temporary file is left in the fixtures.
func checkNoTemp(t *testing.T, tests []*Test) {
	t.Helper()
	for _, test := range tests {
		if tmp, _ := filepath.Glob(filepath.Join(test.Dir, ".gogrep-*.tmp")); len(tmp) > 0 {
			t.Errorf("temporary files left: %q", tmp)
		}
	}
}

func TestRun(t *testing.T) {
	t.Parallel()
	r := newFakeRunner()
	tests := r.addTests(t)
	vs, err := r.run(t, tests)
	checkVerdicts(t, vs, err)
	if len(vs) != len(tests) {
		t.Fatalf("Run = %d verdicts, want %d", len(vs), len(tests))
	}

	// Verdicts hold the command line of each test that ran opengrep, and
	// its stderr.
	sep := string(filepath.Separator)
	want := []string{testBin, "scan", "--config", testConfig, "--no-rewrite-rule-ids", "--sarif", "--disable-version-check", "--timeout", "0", "-j", "1", "--", "." + sep + "a.go"}
	for i, test := range tests {
		args, ran := r.calls[test.Dir]
		switch v := vs[i]; {
		case test.Rule == nil && (ran || v.Command != nil || v.Stderr != nil):
			t.Errorf("%s ran opengrep (%v), command %q, stderr %q; want none", test.Name, ran, v.Command, v.Stderr)
		case test.Rule != nil && (!slices.Equal(args, want) || !slices.Equal(v.Command, want)):
			t.Errorf("%s ran opengrep with %q, command %q; want %q", test.Name, args, v.Command, want)
		case test.Rule != nil && string(v.Stderr) != string(r.fakes[test.Dir].out.Stderr):
			t.Errorf("%s: stderr %q, want %q", test.Name, v.Stderr, r.fakes[test.Dir].out.Stderr)
		}
	}

	// The tests that failed at RESULT have an actual.txt; all others lost
	// theirs. Without --keep-sarif, no actual.sarif is left.
	actual := map[string]string{"test/b-diff": "| a.go:1:1:1:2 | new |\n", "test/c-missing": "| a.go:1:1:1:2 | m |\n"}
	for _, test := range tests {
		checkFile(t, test, actualFile, cmp.Or(actual[test.Name], "-"))
		checkFile(t, test, sarifFile, "-")
	}
	checkFile(t, tests[0], expectedFile, "| a.go:1:1:1:2 | m |\n")
	checkNoTemp(t, tests)
}

// The report does not depend on the number of opengrep processes, nor on
// the order in which they finish.
func TestRunOrder(t *testing.T) {
	t.Parallel()
	for _, threads := range []int{1, 3, 8} {
		r := newFakeRunner()
		r.Threads = threads
		tests := r.addTests(t)
		if threads >= len(tests) {
			// Each run waits until every later one has finished.
			var ran []*Test
			for _, test := range tests {
				if test.Rule != nil {
					ran = append(ran, test)
				}
			}
			finished := make([]chan struct{}, len(ran))
			for i := range ran {
				finished[i] = make(chan struct{})
			}
			for i, test := range ran {
				r.fakes[test.Dir].before = func(context.Context) {
					if i+1 < len(ran) {
						<-finished[i+1]
					}
					close(finished[i])
				}
			}
		}
		vs, err := r.run(t, tests)
		checkVerdicts(t, vs, err)
	}
}

func TestRunLearn(t *testing.T) {
	t.Parallel()
	r := newFakeRunner()
	r.Learn = true
	tests := r.addTests(t)[:3]
	writeTree(t, tests[1].Dir, map[string]string{"actual.txt": "stale\n"})
	const want = `PASSED test/a-pass
LEARNED test/b-diff
--- expected
+++ actual
@@ -1,1 +1,1 @@
-| a.go:1:1:1:2 | old |
+| a.go:1:1:1:2 | new |
LEARNED test/c-missing
missing expected.txt
--- expected
+++ actual
@@ -0,0 +1,1 @@
+| a.go:1:1:1:2 | m |
`
	if vs, err := r.run(t, tests); err != nil || describe(vs) != want {
		t.Errorf("Run --learn = %v, verdicts\n%s\nwant no error, verdicts\n%s", err, describe(vs), want)
	}
	checkFile(t, tests[1], expectedFile, "| a.go:1:1:1:2 | new |\n")
	checkFile(t, tests[2], expectedFile, "| a.go:1:1:1:2 | m |\n")
	for _, test := range tests {
		checkFile(t, test, actualFile, "-")
	}
	checkNoTemp(t, tests)

	r.Learn = false
	const again = "PASSED test/a-pass\nPASSED test/b-diff\nPASSED test/c-missing\n"
	if vs, err := r.run(t, tests); err != nil || describe(vs) != again {
		t.Errorf("Run after --learn = %v, verdicts\n%s\nwant no error, verdicts\n%s", err, describe(vs), again)
	}
}

func TestRunKeepSARIF(t *testing.T) {
	t.Parallel()
	r := newFakeRunner()
	r.KeepSARIF = true
	tests := r.addTests(t)
	vs, err := r.run(t, tests)
	checkVerdicts(t, vs, err)
	for _, test := range tests {
		want := "-"
		if test.Rule != nil {
			want = string(r.fakes[test.Dir].out.Stdout)
		}
		checkFile(t, test, sarifFile, want)
	}
	checkNoTemp(t, tests)
}

// A read-only run reports what any run would, and writes and removes no
// file in the fixtures, even when told to learn and keep SARIF.
func TestRunReadOnly(t *testing.T) {
	t.Parallel()
	for _, learn := range []bool{false, true} {
		r := newFakeRunner()
		r.ReadOnly, r.Learn, r.KeepSARIF = true, learn, learn
		tests := r.addTests(t)
		dir := filepath.Dir(tests[0].Dir)
		ageTree(t, dir)
		before := treeState(t, dir)
		vs, err := r.run(t, tests)
		checkVerdicts(t, vs, err)
		if after := treeState(t, dir); !slices.Equal(after, before) {
			t.Errorf("Run with ReadOnly and Learn %v changed the fixtures:\n%s\nwant\n%s", learn, strings.Join(after, "\n"), strings.Join(before, "\n"))
		}
	}
}

// ageTree makes everything under dir an hour old, so that writing or
// removing a file in a directory changes the directory's modification time.
func ageTree(t *testing.T, dir string) {
	t.Helper()
	old := time.Now().Add(-time.Hour)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(p, old, old)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// treeState returns the path, mode, size and modification time of
// everything under dir.
func treeState(t *testing.T, dir string) []string {
	t.Helper()
	var state []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		state = append(state, fmt.Sprintf("%s %v %d %d", p, fi.Mode(), fi.Size(), fi.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// A fixture directory that is a symlink fails at SETUP, and gogrep never
// removes files through it.
func TestRunSymlinkedFixture(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	writeTree(t, target, map[string]string{"actual.txt": "kept\n", "actual.sarif": "kept"})
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks: %v", err)
	}
	r := newFakeRunner()
	test := &Test{Fixture: &Fixture{Name: "test/link", Dir: link, Setup: errors.New("symlinks to directories are not supported in the test root: link")}}
	const want = "FAILED(SETUP) test/link\n  symlinks to directories are not supported in the test root: link\n"
	if vs, err := r.run(t, []*Test{test}); err != nil || describe(vs) != want || len(vs) != 1 || vs[0].FileErrors != nil {
		t.Errorf("Run = %v, verdicts\n%s\nwant no error, verdicts\n%s", err, describe(vs), want)
	}
	for name, want := range map[string]string{"actual.txt": "kept\n", "actual.sarif": "kept"} {
		if data, err := os.ReadFile(filepath.Join(target, name)); string(data) != want {
			t.Errorf("%s = %q, %v; want %q", name, data, err, want)
		}
	}
}

func TestRunInterrupt(t *testing.T) {
	t.Parallel()
	for _, threads := range []int{1, 4} {
		r := newFakeRunner()
		r.Threads = threads
		dir := t.TempDir()
		stale := map[string]string{"actual.txt": "stale\n"}
		tests := []*Test{
			r.addTest(t, dir, "a-pass", fixtureSpec{files: map[string]string{"expected.txt": "| a.go:1:1:1:2 | m |\n"}, out: results("m")}),
			r.addTest(t, dir, "b-diff", fixtureSpec{files: map[string]string{"expected.txt": "", "actual.txt": "stale\n"}, out: results("new")}),
			r.addTest(t, dir, "c-missing", fixtureSpec{out: results("m")}),
			r.addTest(t, dir, "d-later", fixtureSpec{files: stale, out: results("m")}),
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// killed waits until gogrep is interrupted, which kills opengrep.
		killed := func(ctx context.Context, test *Test) {
			<-ctx.Done()
			r.fakes[test.Dir].out = Output{Stdout: []byte(`{"vers`), Err: errors.New("signal: killed"), Code: -1}
		}
		first := make(chan struct{}) // closed once a-pass is reported
		want := "PASSED test/a-pass\n"
		if threads == 1 {
			// a-pass and b-diff finish, then gogrep is interrupted while c-missing runs.
			r.fakes[tests[2].Dir].before = func(ctx context.Context) {
				cancel()
				killed(ctx, tests[2])
			}
			want += "FAILED(RESULT) test/b-diff\n--- expected\n+++ actual\n@@ -0,0 +1,1 @@\n+| a.go:1:1:1:2 | new |\n"
		} else {
			// a-pass is reported, then gogrep is interrupted while b-diff and c-missing run.
			r.fakes[tests[1].Dir].before = func(ctx context.Context) { killed(ctx, tests[1]) }
			r.fakes[tests[2].Dir].before = func(ctx context.Context) {
				<-first
				cancel()
				killed(ctx, tests[2])
			}
		}
		var reported []*Verdict
		vs, err := r.Run(ctx, tests, func(v *Verdict) {
			if reported = append(reported, v); len(reported) == 1 {
				close(first)
			}
		})
		if !errors.Is(err, context.Canceled) || describe(vs) != want || !slices.Equal(reported, vs) {
			t.Errorf("Run with %d threads, interrupted = %v, verdicts\n%s\nwant %v, verdicts\n%s", threads, err, describe(vs), context.Canceled, want)
		}
		if threads == 1 {
			checkFile(t, tests[1], actualFile, "| a.go:1:1:1:2 | new |\n")
			if _, ran := r.calls[tests[3].Dir]; ran {
				t.Errorf("Run with 1 thread started opengrep for %s after the interrupt", tests[3].Name)
			}
		} else {
			checkFile(t, tests[1], actualFile, "stale\n")
		}
		checkFile(t, tests[2], actualFile, "-")
		checkFile(t, tests[3], actualFile, "stale\n")
		checkNoTemp(t, tests)
	}
}

func TestRunWriteError(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory that its owner cannot write to")
	}
	r := newFakeRunner()
	tests := r.addTests(t)
	locked := tests[1].Dir // b-diff, which gets an actual.txt
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o700) })
	vs, err := r.run(t, tests)
	if len(vs) != len(tests) {
		t.Fatalf("Run = %d verdicts, %v; want %d", len(vs), err, len(tests))
	}
	errs := vs[1].FileErrors
	if len(errs) != 1 || !strings.HasPrefix(errs[0].Error(), "writing test/b-diff/actual.txt: ") {
		t.Errorf("file errors of %s = %q, want an error writing test/b-diff/actual.txt", vs[1].Name, errs)
	}
	vs[1].FileErrors = nil
	checkVerdicts(t, vs, err)
	checkFile(t, tests[2], actualFile, "| a.go:1:1:1:2 | m |\n")
}

func TestRunLearnErrors(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs files that their owner cannot read or write")
	}
	r := newFakeRunner()
	r.Learn = true
	dir := t.TempDir()
	// Both have the actual.txt of an earlier run.
	tests := []*Test{
		r.addTest(t, dir, "a", fixtureSpec{files: map[string]string{"expected.txt": "| a.go:1:1:1:2 | old |\n", "actual.txt": "stale\n"}, out: results("new")}),
		r.addTest(t, dir, "b", fixtureSpec{files: map[string]string{"expected.txt": "| a.go:1:1:1:2 | m |\n", "actual.txt": "stale\n"}, out: results("m")}),
	}
	expected := filepath.Join(tests[1].Dir, expectedFile)
	for _, chmod := range []struct {
		path string
		mode os.FileMode
	}{{tests[0].Dir, 0o500}, {expected, 0o000}} {
		if err := os.Chmod(chmod.path, chmod.mode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(chmod.path, 0o700) })
	}
	want := `FAILED(RESULT) test/a
--- expected
+++ actual
@@ -1,1 +1,1 @@
-| a.go:1:1:1:2 | old |
+| a.go:1:1:1:2 | new |
FAILED(RESULT) test/b
  open ` + expected + `: permission denied
`
	vs, err := r.run(t, tests)
	if err != nil || describe(vs) != want {
		t.Fatalf("Run --learn = %v, verdicts\n%s\nwant no error, verdicts\n%s", err, describe(vs), want)
	}
	if errs := vs[0].FileErrors; len(errs) != 2 ||
		!strings.HasPrefix(errs[0].Error(), "writing test/a/expected.txt: ") || !strings.HasPrefix(errs[1].Error(), "writing test/a/actual.txt: ") || vs[1].FileErrors != nil {
		t.Errorf("file errors = %q, %q; want errors writing test/a/expected.txt and actual.txt, then none", errs, vs[1].FileErrors)
	}
	// accept must not make the results of the earlier run expected: b's
	// actual.txt holds this run's.
	checkFile(t, tests[1], actualFile, "| a.go:1:1:1:2 | m |\n")
}

func TestAccept(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := newFakeRunner()
	tests := []*Test{
		r.addTest(t, dir, "a", fixtureSpec{files: map[string]string{"expected.txt": "old\n", "actual.txt": "new\n"}}),
		r.addTest(t, dir, "b", fixtureSpec{files: map[string]string{"expected.txt": "old\n"}}),
		r.addTest(t, dir, "c", fixtureSpec{files: map[string]string{"actual.txt": "new\n"}}),
		r.addTest(t, dir, "d", fixtureSpec{files: map[string]string{"actual.txt": "new\n"}, setup: errors.New("no code samples")}),
	}
	if err := os.Chmod(filepath.Join(tests[0].Dir, actualFile), 0o644); err != nil {
		t.Fatal(err)
	}
	var fixtures []*Fixture
	for _, test := range tests {
		fixtures = append(fixtures, test.Fixture)
	}
	if got := accepted(Accept(fixtures)); !slices.Equal(got, []string{"test/a", "test/c"}) {
		t.Errorf("Accept = %q, want [test/a test/c]", got)
	}
	for _, f := range []struct {
		test             *Test
		expected, actual string
	}{{tests[0], "new\n", "-"}, {tests[1], "old\n", "-"}, {tests[2], "new\n", "-"}, {tests[3], "-", "new\n"}} {
		checkFile(t, f.test, expectedFile, f.expected)
		if f.actual != "-" {
			// Accept leaves its mode alone.
			if data, err := os.ReadFile(filepath.Join(f.test.Dir, actualFile)); string(data) != f.actual {
				t.Errorf("%s/actual.txt = %q, %v; want %q", f.test.Name, data, err, f.actual)
			}
		} else {
			checkFile(t, f.test, actualFile, "-")
		}
	}

	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return
	}
	writeTree(t, tests[1].Dir, map[string]string{"actual.txt": "newer\n"})
	if err := os.Chmod(tests[1].Dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(tests[1].Dir, 0o700) })
	writeTree(t, tests[2].Dir, map[string]string{"actual.txt": "newer\n"})
	if got := accepted(Accept(fixtures)); !slices.Equal(got, []string{"test/b: permission denied", "test/c"}) {
		t.Errorf("Accept with a read-only fixture = %q, want [test/b: permission denied test/c]", got)
	}
}

// accepted returns the names of the fixtures of acceptances, each followed
// by ": permission denied" when it failed for lack of permission, or by its
// error.
func accepted(acceptances []Acceptance) []string {
	var out []string
	for _, a := range acceptances {
		switch {
		case errors.Is(a.Err, fs.ErrPermission):
			out = append(out, a.Name+": permission denied")
		case a.Err != nil:
			out = append(out, a.Name+": "+a.Err.Error())
		default:
			out = append(out, a.Name)
		}
	}
	return out
}

func TestPlan(t *testing.T) {
	t.Parallel()
	all := ruleSet("project", "project.go.no-exec-command", "project.go.other")
	fixtures := []*Fixture{
		{Name: "a", Namespace: "go", Ref: "no-exec-command"},
		{Name: "b", Namespace: "go", Ref: "other"},
		{Name: "c", Namespace: "go", Ref: "nope"},
		{Name: "d", Setup: errors.New("no code samples")},
	}
	describe := func(tests []*Test) []string {
		var out []string
		for _, t := range tests {
			s := t.Name + ":"
			if t.Rule != nil {
				s += t.Rule.ID
			}
			if t.Err != nil {
				s += "error"
			}
			out = append(out, s)
		}
		return out
	}
	if got, want := describe(Plan(fixtures, all, nil)), []string{"a:project.go.no-exec-command", "b:project.go.other", "c:error", "d:"}; !slices.Equal(got, want) {
		t.Errorf("Plan = %q, want %q", got, want)
	}
	keep := func(r *rules.Rule) bool { return r.ID == "project.go.other" }
	if got, want := describe(Plan(fixtures, all, keep)), []string{"b:project.go.other", "c:error", "d:"}; !slices.Equal(got, want) {
		t.Errorf("Plan with a selection = %q, want %q", got, want)
	}
}

func TestUntested(t *testing.T) {
	t.Parallel()
	project := ruleSet("project", "project.go.c", "project.go.a", "project.go.b")
	tested := func(ids ...string) []*Test {
		tests := []*Test{{Fixture: &Fixture{Name: "broken"}}}
		for _, r := range ruleSet("project", ids...) {
			tests = append(tests, &Test{Fixture: &Fixture{}, Rule: r})
		}
		return tests
	}
	tests := []struct {
		tests []*Test
		want  []string
	}{
		{tested("project.go.a", "project.go.b", "project.go.c"), nil},
		{tested("project.go.a", "project.go.c", "gogrep.x"), []string{"project.go.b"}},
		{tested("project.go.a"), []string{"project.go.b", "project.go.c"}},
	}
	for _, tt := range tests {
		if got := Untested(project, tt.tests); !slices.Equal(got, tt.want) {
			t.Errorf("Untested = %q, want %q", got, tt.want)
		}
	}
}

func TestThreads(t *testing.T) {
	t.Parallel()
	cpus := runtime.NumCPU()
	tests := []struct{ threads, n, want int }{
		{0, 1000, cpus},
		{-1, 1000, max(cpus-1, 1)},
		{-1000, 1000, 1},
		{3, 1000, 3},
		{3, 2, 2},
		{3, 0, 1},
		{0, 1, 1},
	}
	for _, tt := range tests {
		if got := (&Runner{Threads: tt.threads}).threads(tt.n); got != tt.want {
			t.Errorf("threads with Threads %d for %d tests = %d, want %d", tt.threads, tt.n, got, tt.want)
		}
	}
}
