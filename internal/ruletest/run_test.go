package ruletest

import (
	"bytes"
	"cmp"
	"context"
	"errors"
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

// run runs tests and returns the exit code and output.
func (r *fakeRunner) run(ctx context.Context, tests []*Test) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = r.Run(ctx, tests, &out, &errb)
	return code, out.String(), errb.String()
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

// The report of the tests from addTests.
const testsReport = `Executing 8 tests.
[1/8] PASSED test/a-pass
[2/8] FAILED(RESULT) test/b-diff
--- expected
+++ actual
@@ -1,1 +1,1 @@
-| a.go:1:1:1:2 | old |
+| a.go:1:1:1:2 | new |
[3/8] FAILED(RESULT) test/c-missing
Cannot find expected.txt.
--- expected
+++ actual
@@ -0,0 +1,1 @@
+| a.go:1:1:1:2 | m |
[4/8] FAILED(SETUP) test/d-setup
  no code samples
[5/8] FAILED(RULE) test/e-rule
  rule reference "x" matches no rule
[6/8] FAILED(RULE) test/f-invalid
  InvalidRuleSchemaError: One of these properties is missing: 'message'
  SemgrepError: invalid configuration file found (1 configs were invalid)
[7/8] FAILED(RUN) test/g-run
  SemgrepError: File not found: missing.go
  opengrep exited with code 2
  > oops
[8/8] PASSED test/h-empty
2 tests passed; 6 tests failed:
  FAILED: test/b-diff
  FAILED: test/c-missing
  FAILED: test/d-setup
  FAILED: test/e-rule
  FAILED: test/f-invalid
  FAILED: test/g-run
`

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
	r := newFakeRunner()
	tests := r.addTests(t)
	code, stdout, stderr := r.run(context.Background(), tests)
	if code != 1 || stdout != testsReport || stderr != "" {
		t.Errorf("Run = %d, stderr %q, stdout\n%s\nwant 1, no stderr, stdout\n%s", code, stderr, stdout, testsReport)
	}

	sep := string(filepath.Separator)
	want := []string{testBin, "scan", "--config", testConfig, "--no-rewrite-rule-ids", "--sarif", "--disable-version-check", "--timeout", "0", "-j", "1", "--", "." + sep + "a.go"}
	for _, test := range tests {
		if args, ran := r.calls[test.Dir]; test.Rule == nil && ran {
			t.Errorf("%s ran opengrep, want not", test.Name)
		} else if test.Rule != nil && !slices.Equal(args, want) {
			t.Errorf("%s ran opengrep with %q, want %q", test.Name, args, want)
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
	for _, threads := range []int{1, 3, 8} {
		r := newFakeRunner()
		r.Threads = threads
		tests := r.addTests(t)
		if threads >= len(tests) {
			// After the first run, which runs alone, each waits until every
			// later one has finished.
			var ran []*Test
			for _, test := range tests[1:] {
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
		code, stdout, stderr := r.run(context.Background(), tests)
		if code != 1 || stdout != testsReport || stderr != "" {
			t.Errorf("Run with %d threads = %d, stderr %q, stdout\n%s\nwant 1, no stderr, stdout\n%s", threads, code, stderr, stdout, testsReport)
		}
	}
}

// The first opengrep run, which may unpack opengrep, runs alone.
func TestRunFirstAlone(t *testing.T) {
	r := newFakeRunner()
	r.Threads = 8
	tests := r.addTests(t)
	var others int
	r.fakes[tests[0].Dir].before = func(context.Context) {
		time.Sleep(50 * time.Millisecond) // time enough for other runs to start
		r.mu.Lock()
		others = len(r.calls) - 1
		r.mu.Unlock()
	}
	if code, stdout, _ := r.run(context.Background(), tests); code != 1 || stdout != testsReport {
		t.Errorf("Run = %d, stdout\n%s\nwant 1, stdout\n%s", code, stdout, testsReport)
	}
	if others != 0 {
		t.Errorf("%d other opengrep runs started during the first", others)
	}
}

func TestRunLearn(t *testing.T) {
	r := newFakeRunner()
	r.Learn = true
	tests := r.addTests(t)[:3]
	writeTree(t, tests[1].Dir, map[string]string{"actual.txt": "stale\n"})
	const want = `Executing 3 tests.
[1/3] PASSED test/a-pass
[2/3] LEARNED test/b-diff
--- expected
+++ actual
@@ -1,1 +1,1 @@
-| a.go:1:1:1:2 | old |
+| a.go:1:1:1:2 | new |
[3/3] LEARNED test/c-missing
--- expected
+++ actual
@@ -0,0 +1,1 @@
+| a.go:1:1:1:2 | m |
All 3 tests passed (2 learned).
`
	if code, stdout, stderr := r.run(context.Background(), tests); code != 0 || stdout != want || stderr != "" {
		t.Errorf("Run --learn = %d, stderr %q, stdout\n%s\nwant 0, no stderr, stdout\n%s", code, stderr, stdout, want)
	}
	checkFile(t, tests[1], expectedFile, "| a.go:1:1:1:2 | new |\n")
	checkFile(t, tests[2], expectedFile, "| a.go:1:1:1:2 | m |\n")
	for _, test := range tests {
		checkFile(t, test, actualFile, "-")
	}
	checkNoTemp(t, tests)

	r.Learn = false
	const again = `Executing 3 tests.
[1/3] PASSED test/a-pass
[2/3] PASSED test/b-diff
[3/3] PASSED test/c-missing
All 3 tests passed.
`
	if code, stdout, stderr := r.run(context.Background(), tests); code != 0 || stdout != again || stderr != "" {
		t.Errorf("Run after --learn = %d, stderr %q, stdout\n%s\nwant 0, no stderr, stdout\n%s", code, stderr, stdout, again)
	}
}

func TestRunKeepSARIF(t *testing.T) {
	r := newFakeRunner()
	r.KeepSARIF = true
	tests := r.addTests(t)
	if code, stdout, _ := r.run(context.Background(), tests); code != 1 || stdout != testsReport {
		t.Errorf("Run --keep-sarif = %d, stdout\n%s\nwant 1, stdout\n%s", code, stdout, testsReport)
	}
	for _, test := range tests {
		want := "-"
		if test.Rule != nil {
			want = string(r.fakes[test.Dir].out.Stdout)
		}
		checkFile(t, test, sarifFile, want)
	}
	checkNoTemp(t, tests)
}

func TestRunShowOutput(t *testing.T) {
	r := newFakeRunner()
	r.Bin, r.ShowOutput = "/opt/open grep/opengrep", true
	dir := t.TempDir()
	out := results("m")
	out.Stderr = []byte("\n  \nScanning 1 file.\n\nRan 1 rule.  \n\n")
	tests := []*Test{
		r.addTest(t, dir, "a", fixtureSpec{files: map[string]string{"expected.txt": "| a.go:1:1:1:2 | m |\n"}, out: out}),
		r.addTest(t, dir, "b", fixtureSpec{setup: errors.New("no code samples")}),
	}
	sample := "." + string(filepath.Separator) + "a.go"
	want := `Executing 2 tests.
[1/2] PASSED test/a
  $ ` + commandLine([]string{r.Bin, "scan", "--config", testConfig, "--no-rewrite-rule-ids", "--sarif", "--disable-version-check", "--timeout", "0", "-j", "1", "--", sample}) + `
  > Scanning 1 file.
  >
  > Ran 1 rule.
[2/2] FAILED(SETUP) test/b
  no code samples
1 tests passed; 1 tests failed:
  FAILED: test/b
`
	if code, stdout, _ := r.run(context.Background(), tests); code != 1 || stdout != want {
		t.Errorf("Run --show-opengrep-output = %d, stdout\n%s\nwant 1, stdout\n%s", code, stdout, want)
	}
}

// A fixture directory that is a symlink fails at SETUP, and gogrep never
// removes files through it.
func TestRunSymlinkedFixture(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	writeTree(t, target, map[string]string{"actual.txt": "kept\n", "actual.sarif": "kept"})
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks: %v", err)
	}
	r := newFakeRunner()
	test := &Test{Fixture: &Fixture{Name: "test/link", Dir: link, Setup: errors.New("symlinks are not supported in the test root: link")}}
	const want = "Executing 1 tests.\n[1/1] FAILED(SETUP) test/link\n  symlinks are not supported in the test root: link\n0 tests passed; 1 tests failed:\n  FAILED: test/link\n"
	if code, stdout, stderr := r.run(context.Background(), []*Test{test}); code != 1 || stdout != want || stderr != "" {
		t.Errorf("Run = %d, stderr %q, stdout\n%s\nwant 1, no stderr, stdout\n%s", code, stderr, stdout, want)
	}
	for name, want := range map[string]string{"actual.txt": "kept\n", "actual.sarif": "kept"} {
		if data, err := os.ReadFile(filepath.Join(target, name)); string(data) != want {
			t.Errorf("%s = %q, %v; want %q", name, data, err, want)
		}
	}
}

func TestCommandLine(t *testing.T) {
	got := commandLine([]string{"/bin/opengrep", "scan", "--config=/a b/c.yaml", "--", "./x-y_z.go", "./it's.go", "", `.\a.go`, "./h€.go"})
	want := `/bin/opengrep scan '--config=/a b/c.yaml' -- ./x-y_z.go './it'\''s.go' '' '.\a.go' './h€.go'`
	if got != want {
		t.Errorf("commandLine = %s, want %s", got, want)
	}
}

// watchWriter is a buffer that is safe for concurrent use and closes seen
// once it holds want.
type watchWriter struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	want string
	seen chan struct{}
	once sync.Once
}

func (w *watchWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buf.Write(p)
	if strings.Contains(w.buf.String(), w.want) {
		w.once.Do(func() { close(w.seen) })
	}
	return n, err
}

func TestRunInterrupt(t *testing.T) {
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
		stdout := &watchWriter{want: "[1/4] PASSED test/a-pass\n", seen: make(chan struct{})}
		want := "Executing 4 tests.\n[1/4] PASSED test/a-pass\n"
		if threads == 1 {
			// a-pass and b-diff finish, then gogrep is interrupted while c-missing runs.
			r.fakes[tests[2].Dir].before = func(ctx context.Context) {
				cancel()
				killed(ctx, tests[2])
			}
			want += "[2/4] FAILED(RESULT) test/b-diff\n--- expected\n+++ actual\n@@ -0,0 +1,1 @@\n+| a.go:1:1:1:2 | new |\n"
		} else {
			// a-pass is reported, then gogrep is interrupted while b-diff and c-missing run.
			r.fakes[tests[1].Dir].before = func(ctx context.Context) { killed(ctx, tests[1]) }
			r.fakes[tests[2].Dir].before = func(ctx context.Context) {
				<-stdout.seen
				cancel()
				killed(ctx, tests[2])
			}
		}
		var stderr bytes.Buffer
		code := r.Run(ctx, tests, stdout, &stderr)
		if code != 130 || stdout.buf.String() != want || stderr.String() != "gogrep: interrupted\n" {
			t.Errorf("Run with %d threads, interrupted = %d, stderr %q, stdout\n%s\nwant 130, stderr %q, stdout\n%s", threads, code, &stderr, &stdout.buf, "gogrep: interrupted\n", want)
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
	code, stdout, stderr := r.run(context.Background(), tests)
	if code != 2 || stdout != testsReport || !strings.HasPrefix(stderr, "gogrep: writing test/b-diff/actual.txt: ") || strings.Count(stderr, "\n") != 1 {
		t.Errorf("Run = %d, stderr %q, stdout\n%s\nwant 2, an error writing test/b-diff/actual.txt, stdout\n%s", code, stderr, stdout, testsReport)
	}
	checkFile(t, tests[2], actualFile, "| a.go:1:1:1:2 | m |\n")
}

func TestRunLearnErrors(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs files that their owner cannot read or write")
	}
	r := newFakeRunner()
	r.Learn = true
	dir := t.TempDir()
	tests := []*Test{
		r.addTest(t, dir, "a", fixtureSpec{files: map[string]string{"expected.txt": "| a.go:1:1:1:2 | old |\n"}, out: results("new")}),
		r.addTest(t, dir, "b", fixtureSpec{files: map[string]string{"expected.txt": "| a.go:1:1:1:2 | m |\n"}, out: results("m")}),
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
	want := `Executing 2 tests.
[1/2] FAILED(RESULT) test/a
--- expected
+++ actual
@@ -1,1 +1,1 @@
-| a.go:1:1:1:2 | old |
+| a.go:1:1:1:2 | new |
[2/2] FAILED(RESULT) test/b
  open ` + expected + `: permission denied
0 tests passed; 2 tests failed:
  FAILED: test/a
  FAILED: test/b
`
	code, stdout, stderr := r.run(context.Background(), tests)
	if code != 2 || stdout != want || !strings.HasPrefix(stderr, "gogrep: writing test/a/expected.txt: ") || strings.Count(stderr, "\n") != 1 {
		t.Errorf("Run --learn = %d, stderr %q, stdout\n%s\nwant 2, an error writing test/a/expected.txt, stdout\n%s", code, stderr, stdout, want)
	}
}

func TestAccept(t *testing.T) {
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
	var stdout, stderr bytes.Buffer
	if code := Accept(fixtures, &stdout, &stderr); code != 0 || stdout.String() != "Accepted test/a\nAccepted test/c\n" || stderr.Len() > 0 {
		t.Errorf("Accept = %d, %q, %q; want 0, %q, no stderr", code, &stdout, &stderr, "Accepted test/a\nAccepted test/c\n")
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
	stdout.Reset()
	stderr.Reset()
	if code := Accept(fixtures, &stdout, &stderr); code != 2 || stdout.String() != "Accepted test/c\n" ||
		!strings.HasPrefix(stderr.String(), "gogrep: accepting test/b/actual.txt: ") {
		t.Errorf("Accept with a read-only fixture = %d, %q, %q; want 2, %q, an error accepting test/b/actual.txt", code, &stdout, &stderr, "Accepted test/c\n")
	}
}

func TestPlan(t *testing.T) {
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

func TestWarnUntested(t *testing.T) {
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
		want  string
	}{
		{tested("project.go.a", "project.go.b", "project.go.c"), ""},
		{tested("project.go.a", "project.go.c", "gogrep.x"), "gogrep: warning: 1 project rule has no test fixture:\n  project.go.b\n"},
		{tested("project.go.a"), "gogrep: warning: 2 project rules have no test fixture:\n  project.go.b\n  project.go.c\n"},
	}
	for _, tt := range tests {
		var w bytes.Buffer
		if WarnUntested(&w, project, tt.tests); w.String() != tt.want {
			t.Errorf("WarnUntested = %q, want %q", &w, tt.want)
		}
	}
}

func TestThreads(t *testing.T) {
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
