package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
		{[]string{"lint", "../x"}, 2, "", "gogrep: scan target \"../x\" is not a relative path inside the directory\n"},
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

// A lint scans opengrep/gogrep/rules by default, or the paths it is given,
// with the rule-lint suite or the one --suite names.
func TestLintTargets(t *testing.T) {
	useFakeOpengrep(t, 0)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"opengrep/gogrep/rules/go/bare.yaml": bareRule,
		"more/rules.yml":                     bareRule,
	})
	t.Chdir(dir)
	for _, tt := range []struct {
		args    []string
		targets []string
	}{
		{[]string{"lint", "--sarif"}, []string{filepath.FromSlash("opengrep/gogrep/rules")}},
		{[]string{"lint", "--sarif", "more", "opengrep/gogrep/rules/go/bare.yaml"}, []string{"more", "opengrep/gogrep/rules/go/bare.yaml"}},
		{[]string{"lint", "--suite", "code-scanning", "--sarif", "more"}, []string{"more"}},
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

// A fakeResult is a result of the SARIF log that fakeLintLog makes.
type fakeResult struct {
	path               string
	line, col, endLine int
	rule, level, msg   string // level "" sets none
	suppressed         bool
}

// fakeLintLog makes the fake opengrep print a SARIF log with results and
// with notes as the messages of its run's notifications.
func fakeLintLog(t *testing.T, results []fakeResult, notes ...string) {
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
		ns = append(ns, map[string]any{"level": "warning", "descriptor": map[string]any{"id": "Other syntax error"}, "message": map[string]any{"text": n}})
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
// rule id, then the summary and opengrep's notifications on stderr;
// suppressed findings are no problems. --sarif prints the log instead.
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
	}, "Syntax error at line opengrep/gogrep/rules/go/b.yaml:3:\n bad")

	code, stdout, stderr := runGogrep("lint")
	wantOut := a + ":2:5: r.x (ERROR): Spread over lines\n" +
		a + ":2:5: r.y (INFO): First, by rule id\n" +
		a + ":2:7: r.v (WARNING): Second\n" +
		a + ":3:1: r.w (ERROR): Third\n" +
		b + ":1:1: r.z (WARNING): No level\n"
	wantErr := "gogrep: opengrep: Syntax error at line opengrep/gogrep/rules/go/b.yaml:3: bad\n" +
		"5 problems in 2 of 3 rule files.\n"
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
		// Another suite can find problems in other files, which count too.
		{[]string{"lint", "--suite", "code-scanning", "code"}, []fakeResult{{path: "code/main.go", rule: "r"}}, 1, "1 problem in 1 of 1 rule file.\n"},
	} {
		t.Run(fmt.Sprint(tt.args, len(tt.results)), func(t *testing.T) {
			fakeLintLog(t, tt.results)
			if code, _, stderr := runGogrep(tt.args...); code != tt.code || stderr != tt.stderr {
				t.Errorf("gogrep %q = %d, %q; want %d, %q", tt.args, code, stderr, tt.code, tt.stderr)
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
}
