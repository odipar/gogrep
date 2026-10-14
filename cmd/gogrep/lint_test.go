package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// bareRule is a rule without metadata, which rule-lint reports twice.
const bareRule = "rules:\n  - id: bare\n    languages: [go]\n    severity: WARNING\n    message: Do not exit\n    pattern: os.Exit(...)\n"

func TestParseLintArgs(t *testing.T) {
	tests := []struct {
		args   []string
		want   lintArgs
		errMsg string
	}{
		{nil, lintArgs{}, ""},
		{[]string{"a", "--sarif", "b"}, lintArgs{sarif: true, paths: []string{"a", "b"}}, ""},
		{[]string{"a", "-h"}, lintArgs{help: true, paths: []string{"a"}}, ""},
		{[]string{"--help"}, lintArgs{help: true}, ""},
		{[]string{"--json"}, lintArgs{}, "unknown flag --json; gogrep lint does not forward flags to opengrep"},
		{[]string{"--sarif=true"}, lintArgs{}, "unknown flag --sarif=true; gogrep lint does not forward flags to opengrep"},
		{[]string{"-"}, lintArgs{}, "unknown flag -; gogrep lint does not forward flags to opengrep"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			got, err := parseLintArgs(tt.args)
			if tt.errMsg != "" {
				if err == nil || err.Error() != tt.errMsg {
					t.Errorf("parseLintArgs(%q) error = %v, want %q", tt.args, err, tt.errMsg)
				}
				return
			}
			if err != nil || fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Errorf("parseLintArgs(%q) = %+v, %v; want %+v", tt.args, got, err, tt.want)
			}
		})
	}
}

// Usage and setup errors exit 2 before opengrep runs, or say why it failed.
func TestLintUsage(t *testing.T) {
	useFakeOpengrep(t, 0)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"opengrep/gogrep/rules/go/bare.yaml": bareRule,
		testRoot + "/go/a/notes.yaml":        bareRule,
	})
	t.Chdir(dir)
	const takesSuite = "gogrep: gogrep lint takes --suite, not --rule or --gogrep-* flags\n"
	const oneSuite = "gogrep: gogrep lint takes one --suite NAME\n"
	tests := []struct {
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{[]string{"lint", "--help"}, 0, lintUsage, ""},
		{[]string{"lint", "nope.yaml", "-h", "--json"}, 2, "", "gogrep: unknown flag --json; gogrep lint does not forward flags to opengrep\n"},
		{[]string{"lint", "-h", "nope.yaml"}, 0, lintUsage, ""},
		{[]string{"lint", "--config", "r.yaml"}, 2, "", "gogrep: unknown flag --config; gogrep lint does not forward flags to opengrep\n"},
		{[]string{"lint", "--rule", "bare"}, 2, "", takesSuite},
		{[]string{"lint", "--gogrep-lang", "yaml"}, 2, "", takesSuite},
		{[]string{"lint", "--suite", "rule-lint,all"}, 2, "", oneSuite},
		{[]string{"lint", "--suite", "rule-lint", "--suite", "all"}, 2, "", oneSuite},
		{[]string{"lint", "--suite="}, 2, "", oneSuite},
		{[]string{"lint", "--suite"}, 2, "", "gogrep: --suite needs a value\n"},
		{[]string{"lint", "--suite", "nope"}, 2, "", "gogrep: unknown suite \"nope\"; list them with: gogrep suites\n"},
		{[]string{"lint", "nope.yaml"}, 2, "", "gogrep: nope.yaml does not exist\n"},
		{[]string{"lint", "opengrep/gogrep/rules", "nope"}, 2, "", "gogrep: nope does not exist\n"},
		{[]string{"lint", "../x"}, 2, "", "gogrep: ../x is not a relative path inside the current directory\n"},
		{[]string{"lint", "opengrep/gogrep/rules", dir}, 2, "", "gogrep: " + dir + " is not a relative path inside the current directory\n"},
		{[]string{"lint", testRoot}, 2, "", "gogrep: opengrep/gogrep/rules/test holds rule test fixtures, which are not linted\n"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			code, stdout, stderr := runGogrep(tt.args...)
			if code != tt.code || stdout != tt.stdout || stderr != tt.stderr {
				t.Errorf("gogrep %q = %d, %q, %q; want %d, %q, %q", tt.args, code, stdout, stderr, tt.code, tt.stdout, tt.stderr)
			}
		})
	}

	t.Run("no rules directory", func(t *testing.T) {
		t.Chdir(t.TempDir())
		code, stdout, stderr := runGogrep("lint")
		if want := "gogrep: no opengrep/gogrep/rules here; name the rules to lint\n"; code != 2 || stdout != "" || stderr != want {
			t.Errorf("gogrep lint = %d, %q, %q; want 2, no stdout, %q", code, stdout, stderr, want)
		}
	})
}

// A lint scans the rule files of opengrep/gogrep/rules by default, or of
// the paths it is given, with the rule-lint suite or the one --suite names.
func TestLintTargets(t *testing.T) {
	useFakeOpengrep(t, 0)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"opengrep/gogrep/rules/go/bare.yaml": bareRule,
		"more/rules.yml":                     bareRule,
		"more/vendor/rules.yaml":             bareRule,
		"more/README.md":                     "Rules\n",
	})
	t.Chdir(dir)
	bare, more, vendored := filepath.FromSlash("opengrep/gogrep/rules/go/bare.yaml"), filepath.FromSlash("more/rules.yml"), filepath.FromSlash("more/vendor/rules.yaml")
	for _, tt := range []struct {
		args    []string
		targets []string
	}{
		{[]string{"lint", "--sarif"}, []string{bare}},
		{[]string{"lint", "--sarif", "opengrep/gogrep/rules/go/bare.yaml", "more"}, []string{more, vendored, bare}},
		{[]string{"lint", "--suite", "code-scanning", "--sarif", "more"}, []string{more, vendored}},
	} {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			code, stdout, stderr := runGogrep(tt.args...)
			if code != 0 || stderr != "" {
				t.Fatalf("gogrep %q = %d, %q; want 0, no stderr", tt.args, code, stderr)
			}
			driver, args := sarifRun(t, stdout)
			if driver != "gogrep" {
				t.Errorf("SARIF driver = %q, want gogrep", driver)
			}
			i := slices.Index(args, "--")
			if i < 0 || !slices.Equal(args[i+1:], tt.targets) {
				t.Errorf("opengrep args = %q, want targets %q after --", args, tt.targets)
			}
		})
	}
}

// gogrep lint counts the rule files that Engine.Lint scans, also those that
// ignore files hide from a scan; without any it prints an empty SARIF log.
// Lint's errors about the files are setup errors.
func TestLintFiles(t *testing.T) {
	useFakeOpengrep(t, 0)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		".semgrepignore":                            "opengrep/\n",
		"opengrep/gogrep/rules/go/a.yaml":           bareRule,
		"opengrep/gogrep/rules/go/tests/b.yaml":     bareRule,
		"opengrep/gogrep/rules/node_modules/c.yaml": bareRule,
		"other/d.yml":                               bareRule,
		"other/private/e.yaml":                      bareRule,
		"code/main.go":                              "package main\n",
	})
	t.Chdir(dir)
	if code, stdout, stderr := runGogrep("lint"); code != 0 || stdout != "" || stderr != "No problems in 3 rule files.\n" {
		t.Errorf("gogrep lint = %d, %q, %q; want 0, no stdout, 3 rule files", code, stdout, stderr)
	}
	code, stdout, stderr := runGogrep("lint", "--sarif", "code")
	if driver, _ := sarifRun(t, stdout); code != 0 || stderr != "" || driver != "gogrep" || strings.Contains(stdout, `"ruleId"`) {
		t.Errorf("gogrep lint --sarif code = %d, %q, %q; want 0, gogrep's log without results, no stderr", code, stdout, stderr)
	}

	t.Run("unreadable directory", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs a directory that its owner cannot read")
		}
		if err := os.Chmod(filepath.Join(dir, "other", "private"), 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(filepath.Join(dir, "other", "private"), 0o700) })
		code, stdout, stderr := runGogrep("lint", "other")
		if want := "gogrep: open other/private: permission denied\n"; code != 2 || stdout != "" || stderr != want {
			t.Errorf("gogrep lint other = %d, %q, %q; want 2, no stdout, %q", code, stdout, stderr, want)
		}
	})

	t.Run("symlink outside", func(t *testing.T) {
		link, outside := filepath.Join(dir, "opengrep", "gogrep", "rules", "go", "out.yaml"), t.TempDir()
		writeTree(t, outside, map[string]string{"out.yaml": bareRule})
		if err := os.Symlink(filepath.Join(outside, "out.yaml"), link); err != nil {
			t.Skipf("cannot create symlinks: %v", err)
		}
		t.Cleanup(func() { os.Remove(link) })
		code, stdout, stderr := runGogrep("lint")
		if want := "gogrep: opengrep/gogrep/rules/go/out.yaml leads outside the directory through a symlink\n"; code != 2 || stdout != "" || stderr != want {
			t.Errorf("gogrep lint = %d, %q, %q; want 2, no stdout, %q", code, stdout, stderr, want)
		}
	})
}

// A fakeResult is a result of the SARIF log that fakeLintLog makes.
type fakeResult struct {
	path               string
	line, col, endLine int
	rule, level, msg   string // level "" sets none
	suppressed         bool
}

// A fakeNote is a notification of the SARIF log that fakeLintLog makes.
type fakeNote struct{ id, msg string }

// fakeLintLog makes the fake opengrep print a SARIF log with results and
// notes as its run's notifications.
func fakeLintLog(t *testing.T, results []fakeResult, notes ...fakeNote) {
	t.Helper()
	rs := []any{}
	for _, r := range results {
		res := map[string]any{
			"ruleId":  r.rule,
			"message": map[string]any{"text": r.msg},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": r.path},
				"region":           map[string]any{"startLine": r.line, "startColumn": r.col, "endLine": r.endLine, "endColumn": 1},
			}}},
		}
		if r.level != "" {
			res["level"] = r.level
		}
		if r.suppressed {
			res["suppressions"] = []any{map[string]any{"kind": "inSource"}}
		}
		rs = append(rs, res)
	}
	ns := []any{}
	for _, n := range notes {
		ns = append(ns, map[string]any{"level": "warning", "descriptor": map[string]any{"id": n.id}, "message": map[string]any{"text": n.msg}})
	}
	data, err := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool":        map[string]any{"driver": map[string]any{"name": "opengrep"}},
		"invocations": []any{map[string]any{"executionSuccessful": true, "toolExecutionNotifications": ns}},
		"results":     rs,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "lint.sarif")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOGREP_TEST_FAKE_SARIF", file)
}

// The problems are printed one per line, sorted by path, line, column and
// rule id, then opengrep's other notifications and the summary on stderr;
// suppressed findings are no problems, a syntax error in a rule file is
// one. --sarif prints the log instead.
func TestLintOutput(t *testing.T) {
	useFakeOpengrep(t, 0)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"opengrep/gogrep/rules/go/a.yaml":  bareRule,
		"opengrep/gogrep/rules/go/b.yaml":  bareRule,
		"opengrep/gogrep/rules/go/c.yml":   bareRule,
		"opengrep/gogrep/rules/README.md":  "Rules\n",
		testRoot + "/go/a/notes.yaml":      bareRule, // a fixture, not a rule file
		"opengrep/gogrep/rules/go/x.yaml~": bareRule,
	})
	t.Chdir(dir)
	const a, b, c = "opengrep/gogrep/rules/go/a.yaml", "opengrep/gogrep/rules/go/b.yaml", "opengrep/gogrep/rules/go/c.yml"
	fakeLintLog(t, []fakeResult{
		{b, 1, 1, 1, "r.z", "", "No level", false},
		{a, 3, 1, 3, "r.w", "error", "Third", false},
		{a, 2, 7, 2, "r.v", "warning", "Second", false},
		{a, 2, 5, 3, "r.y", "note", "First, by rule id", false},
		{a, 2, 5, 9, "r.x", "error", "  Spread\n  over\n\n  lines  ", false},
		{c, 1, 1, 1, "r.x", "error", "Suppressed", true},
	}, fakeNote{"Other syntax error", "Other syntax error at line opengrep/gogrep/rules/go/b.yaml:3:\n bad"},
		fakeNote{"Timeout", "Timeout when running r.v on opengrep/gogrep/rules/go/c.yml:\n  took too long"})

	code, stdout, stderr := runGogrep("lint")
	wantOut := a + ":2:5: r.x (ERROR): Spread over lines\n" +
		a + ":2:5: r.y (INFO): First, by rule id\n" +
		a + ":2:7: r.v (WARNING): Second\n" +
		a + ":3:1: r.w (ERROR): Third\n" +
		b + ":1:1: r.z (WARNING): No level\n" +
		b + ":3:1: syntax-error (ERROR): bad\n"
	wantErr := "gogrep: opengrep: Timeout when running r.v on opengrep/gogrep/rules/go/c.yml: took too long\n" +
		"6 problems in 2 of 3 rule files.\n"
	if code != 1 || stdout != wantOut || stderr != wantErr {
		t.Errorf("gogrep lint = %d, stdout\n%s\nstderr\n%s\nwant 1, stdout\n%s\nstderr\n%s", code, stdout, stderr, wantOut, wantErr)
	}

	code, stdout, stderr = runGogrep("lint", "--sarif")
	if driver, _ := sarifRun(t, stdout); code != 1 || stderr != "" || driver != "gogrep" {
		t.Errorf("gogrep lint --sarif = %d, driver %q, stderr %q; want 1, gogrep, no stderr", code, driver, stderr)
	}
	if !strings.HasSuffix(stdout, "}\n") || strings.Count(stdout, `"ruleId"`) != 6 {
		t.Errorf("gogrep lint --sarif = %q, want the log of all 6 results and a newline", stdout)
	}
}

func TestLintSummary(t *testing.T) {
	useFakeOpengrep(t, 0)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"one/a.yaml":    bareRule,
		"two/a.yaml":    bareRule,
		"two/sub/b.yml": bareRule,
		"code/main.go":  "package main\n",
	})
	t.Chdir(dir)
	for _, tt := range []struct {
		args    []string
		results []fakeResult
		code    int
		stderr  string
	}{
		{[]string{"lint", "one"}, nil, 0, "No problems in 1 rule file.\n"},
		{[]string{"lint", "two"}, nil, 0, "No problems in 2 rule files.\n"},
		{[]string{"lint", "one/a.yaml", "two/sub"}, []fakeResult{{path: "one/a.yaml", line: 2, col: 5, rule: "r"}}, 1, "1 problem in 1 of 2 rule files.\n"},
		{[]string{"lint", "one"}, []fakeResult{{path: "one/a.yaml", line: 2, col: 5, rule: "r"}}, 1, "1 problem in 1 of 1 rule file.\n"},
		{[]string{"lint", "two", "one"}, []fakeResult{{path: "one/a.yaml", rule: "r"}, {path: "two/a.yaml", rule: "r"}}, 1, "2 problems in 2 of 3 rule files.\n"},
		{[]string{"lint", "one"}, []fakeResult{{path: "one/a.yaml", rule: "r", suppressed: true}}, 0, "No problems in 1 rule file.\n"},
		{[]string{"lint", "code"}, nil, 0, "No problems in 0 rule files.\n"},
		// Without rule files opengrep does not run, and finds nothing.
		{[]string{"lint", "--suite", "code-scanning", "code"}, []fakeResult{{path: "code/main.go", rule: "r"}}, 0, "No problems in 0 rule files.\n"},
		// A problem in another file counts that file too.
		{[]string{"lint", "--suite", "code-scanning", "one"}, []fakeResult{{path: "code/main.go", rule: "r"}}, 1, "1 problem in 1 of 2 rule files.\n"},
	} {
		t.Run(fmt.Sprint(tt.args, len(tt.results)), func(t *testing.T) {
			fakeLintLog(t, tt.results)
			if code, _, stderr := runGogrep(tt.args...); code != tt.code || stderr != tt.stderr {
				t.Errorf("gogrep %q = %d, %q; want %d, %q", tt.args, code, stderr, tt.code, tt.stderr)
			}
		})
	}
}

// A notification that opengrep could not parse a rule file is a problem of
// the check syntax-error, at the line it names or line 1, also with --sarif;
// other notifications, and those about other files, are not.
func TestLintSyntaxErrors(t *testing.T) {
	useFakeOpengrep(t, 0)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"one/a.yaml": bareRule, "one/a.yaml.yaml": bareRule, "two/sub/b.yml": bareRule})
	t.Chdir(dir)
	const parser = "(approximate error location; error nearby after) error calling parser: did not find expected ',' or ']' character 0 position 0 returned: 0"
	for _, tt := range []struct {
		note   fakeNote
		code   int
		stdout string
		stderr string
	}{
		{fakeNote{"Other syntax error", "Other syntax error at line one/a.yaml:4:\n " + parser}, 1, "one/a.yaml:4:1: syntax-error (ERROR): " + parser + "\n", "1 problem in 1 of 3 rule files.\n"},
		{fakeNote{"Syntax error", "Syntax error at line two/sub/b.yml:12:\n `x` was unexpected"}, 1, "two/sub/b.yml:12:1: syntax-error (ERROR): `x` was unexpected\n", "1 problem in 1 of 3 rule files.\n"},
		{fakeNote{"Lexical error", "Lexical error at line " + filepath.FromSlash("two/sub/b.yml") + ": bad"}, 1, "two/sub/b.yml:1:1: syntax-error (ERROR): bad\n", "1 problem in 1 of 3 rule files.\n"},
		{fakeNote{"Other syntax error", "Other syntax error at line one/a.yaml.yaml:2:"}, 1, "one/a.yaml.yaml:2:1: syntax-error (ERROR): Other syntax error at line one/a.yaml.yaml:2:\n", "1 problem in 1 of 3 rule files.\n"},
		{fakeNote{"Other syntax error", "Other syntax error at line elsewhere.yaml:3:\n bad"}, 0, "", "gogrep: opengrep: Other syntax error at line elsewhere.yaml:3: bad\nNo problems in 3 rule files.\n"},
		{fakeNote{"Timeout", "Timeout at line one/a.yaml:3:\n slow"}, 0, "", "gogrep: opengrep: Timeout at line one/a.yaml:3: slow\nNo problems in 3 rule files.\n"},
	} {
		t.Run(tt.note.msg, func(t *testing.T) {
			fakeLintLog(t, nil, tt.note)
			if code, stdout, stderr := runGogrep("lint", "one", "two"); code != tt.code || stdout != tt.stdout || stderr != tt.stderr {
				t.Errorf("gogrep lint = %d, %q, %q; want %d, %q, %q", code, stdout, stderr, tt.code, tt.stdout, tt.stderr)
			}
			if code, _, stderr := runGogrep("lint", "--sarif", "one", "two"); code != tt.code || stderr != "" {
				t.Errorf("gogrep lint --sarif = %d, %q; want %d, no stderr", code, stderr, tt.code)
			}
		})
	}
}

// opengrep's failures are setup errors.
func TestLintOpengrepFails(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"opengrep/gogrep/rules/go/bare.yaml": bareRule})
	t.Chdir(dir)

	t.Run("exit code", func(t *testing.T) {
		useFakeOpengrep(t, 7)
		code, stdout, stderr := runGogrep("lint")
		if want := "gogrep: opengrep exited with code 7: fake stderr\n"; code != 2 || stdout != "" || stderr != want {
			t.Errorf("gogrep lint = %d, %q, %q; want 2, no stdout, %q", code, stdout, stderr, want)
		}
	})

	t.Run("no SARIF", func(t *testing.T) {
		useFakeOpengrep(t, 0)
		t.Setenv("GOGREP_TEST_FAKE_NO_SARIF", "1")
		code, stdout, stderr := runGogrep("lint", "--sarif")
		if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "gogrep: opengrep exited 0 but wrote no SARIF: ") {
			t.Errorf("gogrep lint --sarif = %d, %q, %q; want 2, no stdout, a no SARIF error", code, stdout, stderr)
		}
	})

	t.Run("no opengrep", func(t *testing.T) {
		useFakeOpengrep(t, 0)
		t.Setenv("OPENGREP_BIN", filepath.Join(dir, "missing-opengrep"))
		if code, _, stderr := runGogrep("lint"); code != 2 || !strings.HasPrefix(stderr, "gogrep: ") {
			t.Errorf("gogrep lint = %d, %q; want 2 and a gogrep: error", code, stderr)
		}
	})
}

// With the real opengrep: a rule without metadata has two problems, the
// example rules none, and YAML in the rule test fixtures is not linted, also
// where a .semgrepignore replaces opengrep's default ignores.
func TestLintRules(t *testing.T) {
	requireOpengrep(t)
	testProject(t, map[string]string{
		".semgrepignore":                     "*.md\n",
		"opengrep/gogrep/rules/go/bare.yaml": bareRule,
		testRoot + "/go/bare/rules.yaml":     bareRule,
	})
	code, stdout, stderr := runGogrep("lint")
	// The problems, without their messages, which are opengrep-rules'.
	want := []string{
		"opengrep/gogrep/rules/go/bare.yaml:2:5: opengrep-rules.yaml.semgrep.metadata-category (INFO): ",
		"opengrep/gogrep/rules/go/bare.yaml:2:5: opengrep-rules.yaml.semgrep.metadata-technology (INFO): ",
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	ok := len(lines) == len(want)
	for i := 0; ok && i < len(lines); i++ {
		ok = strings.HasPrefix(lines[i], want[i]) && len(lines[i]) > len(want[i])
	}
	if code != 1 || !ok || stderr != "2 problems in 1 of 4 rule files.\n" {
		t.Errorf("gogrep lint = %d, stdout\n%s\nstderr %q; want 1, problems %q with messages, stderr %q", code, stdout, stderr, want, "2 problems in 1 of 4 rule files.\n")
	}

	code, stdout, stderr = runGogrep("lint", "opengrep/gogrep/rules/go/no-exec-command.yaml", "opengrep/gogrep/rules/generic")
	if code != 0 || stdout != "" || stderr != "No problems in 2 rule files.\n" {
		t.Errorf("gogrep lint of the example rules = %d, %q, %q; want 0, no stdout, %q", code, stdout, stderr, "No problems in 2 rule files.\n")
	}

	// A rule file that opengrep cannot parse is a problem.
	writeTree(t, ".", map[string]string{"other/broken.yaml": "rules:\n  - id: broken\n    pattern: [unclosed\n"})
	code, stdout, stderr = runGogrep("lint", "other")
	if want := "other/broken.yaml:3:1: syntax-error (ERROR): "; code != 1 || !strings.HasPrefix(stdout, want) || strings.Count(stdout, "\n") != 1 || stderr != "1 problem in 1 of 1 rule file.\n" {
		t.Errorf("gogrep lint of a broken rule file = %d, %q, %q; want 1, a problem %q..., %q", code, stdout, stderr, want, "1 problem in 1 of 1 rule file.\n")
	}
}
