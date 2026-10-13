package gogrep

import (
	"bytes"
	"errors"
	"testing"

	"github.com/odipar/gogrep/internal/engine"
)

// verdict returns v as the result of a test of the fixture name.
func verdict(name string, v engine.TestResult) *engine.TestResult {
	v.Name = name
	return &v
}

// printReport reports verdicts, as many as there are tests, and returns the
// exit code and output.
func printReport(verdicts []*engine.TestResult, showOutput bool) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	r := &testReport{stdout: &out, stderr: &errb, total: len(verdicts), showOutput: showOutput}
	r.start()
	for _, v := range verdicts {
		r.add(v)
	}
	code = r.finish()
	return code, out.String(), errb.String()
}

func TestTestReport(t *testing.T) {
	verdicts := []*engine.TestResult{
		verdict("test/a-pass", engine.TestResult{}),
		verdict("test/b-diff", engine.TestResult{Stage: engine.StageResult, Diff: "--- expected\n+++ actual\n@@ -1,1 +1,1 @@\n-| a.go:1:1:1:2 | old |\n+| a.go:1:1:1:2 | new |\n"}),
		verdict("test/c-missing", engine.TestResult{Stage: engine.StageResult, MissingExpected: true, Diff: "--- expected\n+++ actual\n@@ -0,0 +1,1 @@\n+| a.go:1:1:1:2 | m |\n"}),
		verdict("test/d-setup", engine.TestResult{Stage: engine.StageSetup, Details: []string{"no code samples"}}),
		verdict("test/e-rule", engine.TestResult{Stage: engine.StageRule, Details: []string{`rule reference "x" matches no rule`}}),
		verdict("test/f-invalid", engine.TestResult{Stage: engine.StageRule, Details: []string{
			"InvalidRuleSchemaError: One of these properties is missing: 'message'",
			"SemgrepError: invalid configuration file found (1 configs were invalid)",
		}}),
		verdict("test/g-run", engine.TestResult{Stage: engine.StageRun, Details: []string{"SemgrepError: File not found: missing.go", "opengrep exited with code 2", "> oops"}}),
		verdict("test/h-empty", engine.TestResult{}),
	}
	const want = `Executing 8 tests.
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
	if code, stdout, stderr := printReport(verdicts, false); code != 1 || stdout != want || stderr != "" {
		t.Errorf("report = %d, stderr %q, stdout\n%s\nwant 1, no stderr, stdout\n%s", code, stderr, stdout, want)
	}
}

func TestTestReportLearned(t *testing.T) {
	verdicts := []*engine.TestResult{
		verdict("test/a-pass", engine.TestResult{}),
		verdict("test/b-diff", engine.TestResult{Learned: true, Diff: "--- expected\n+++ actual\n@@ -1,1 +1,1 @@\n-| a.go:1:1:1:2 | old |\n+| a.go:1:1:1:2 | new |\n"}),
		verdict("test/c-missing", engine.TestResult{Learned: true, MissingExpected: true, Diff: "--- expected\n+++ actual\n@@ -0,0 +1,1 @@\n+| a.go:1:1:1:2 | m |\n"}),
	}
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
	if code, stdout, stderr := printReport(verdicts, false); code != 0 || stdout != want || stderr != "" {
		t.Errorf("report = %d, stderr %q, stdout\n%s\nwant 0, no stderr, stdout\n%s", code, stderr, stdout, want)
	}
	const passed = "Executing 1 tests.\n[1/1] PASSED test/a-pass\nAll 1 tests passed.\n"
	if code, stdout, stderr := printReport(verdicts[:1], false); code != 0 || stdout != passed || stderr != "" {
		t.Errorf("report = %d, stderr %q, stdout\n%s\nwant 0, no stderr, stdout\n%s", code, stderr, stdout, passed)
	}
}

func TestTestReportShowOutput(t *testing.T) {
	cmd := []string{"/opt/open grep/opengrep", "scan", "--config", "/cache/gogrep/selections/0123456789abcdef.yaml", "--no-rewrite-rule-ids", "--sarif", "--disable-version-check", "--timeout", "0", "-j", "1", "--", "./a.go"}
	verdicts := []*engine.TestResult{
		verdict("test/it's/a", engine.TestResult{Command: cmd, Stderr: []byte("\n  \nScanning 1 file.\r\n\nRan 1 rule.  \n\n")}),
		verdict("test/it's/b", engine.TestResult{Stage: engine.StageSetup, Details: []string{"no code samples"}}),
	}
	const want = `Executing 2 tests.
[1/2] PASSED test/it's/a
  $ (cd 'test/it'\''s/a' && '/opt/open grep/opengrep' scan --config /cache/gogrep/selections/0123456789abcdef.yaml --no-rewrite-rule-ids --sarif --disable-version-check --timeout 0 -j 1 -- ./a.go)
  > Scanning 1 file.
  >
  > Ran 1 rule.
[2/2] FAILED(SETUP) test/it's/b
  no code samples
1 tests passed; 1 tests failed:
  FAILED: test/it's/b
`
	if code, stdout, _ := printReport(verdicts, true); code != 1 || stdout != want {
		t.Errorf("report --show-opengrep-output = %d, stdout\n%s\nwant 1, stdout\n%s", code, stdout, want)
	}
}

// A fixture file that could not be written or removed is reported on
// stderr, before the test, and makes the exit code 2.
func TestTestReportFileErrors(t *testing.T) {
	verdicts := []*engine.TestResult{
		verdict("test/a", engine.TestResult{FileErrors: []error{errors.New("writing test/a/expected.txt: denied"), errors.New("writing test/a/actual.txt: denied")}}),
		verdict("test/b", engine.TestResult{}),
	}
	const want = "gogrep: writing test/a/expected.txt: denied\ngogrep: writing test/a/actual.txt: denied\n"
	if code, stdout, stderr := printReport(verdicts, false); code != 2 || stderr != want || stdout != "Executing 2 tests.\n[1/2] PASSED test/a\n[2/2] PASSED test/b\nAll 2 tests passed.\n" {
		t.Errorf("report = %d, %q, %q; want 2, the passed tests, %q", code, stdout, stderr, want)
	}
}

func TestTestReportInterrupted(t *testing.T) {
	var stdout, stderr bytes.Buffer
	r := &testReport{stdout: &stdout, stderr: &stderr, total: 2}
	r.start()
	r.add(verdict("test/a", engine.TestResult{}))
	if code := r.interrupted(); code != 130 || stdout.String() != "Executing 2 tests.\n[1/2] PASSED test/a\n" || stderr.String() != "gogrep: interrupted\n" {
		t.Errorf("report, interrupted = %d, %q, %q; want 130, the first test, %q", code, &stdout, &stderr, "gogrep: interrupted\n")
	}
}

func TestWarnUntested(t *testing.T) {
	tests := []struct {
		untested []string
		want     string
	}{
		{nil, ""},
		{[]string{"project.go.b"}, "gogrep: warning: 1 project rule has no test fixture:\n  project.go.b\n"},
		{[]string{"project.go.b", "project.go.c"}, "gogrep: warning: 2 project rules have no test fixture:\n  project.go.b\n  project.go.c\n"},
	}
	for _, tt := range tests {
		var w bytes.Buffer
		if warnUntested(&w, tt.untested); w.String() != tt.want {
			t.Errorf("warnUntested(%q) = %q, want %q", tt.untested, &w, tt.want)
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
