package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/odipar/gogrep/internal/ruletest"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/golden")

// repoDir is the repository root, the package directory; the tests change
// the working directory.
var repoDir, _ = os.Getwd()

// testRoot is the test root of a project, as gogrep prints it.
const testRoot = "opengrep/gogrep/rules/test"

func TestParseTestArgs(t *testing.T) {
	tests := []struct {
		args   []string
		want   testArgs
		errMsg string
	}{
		{nil, testArgs{}, ""},
		{[]string{"run"}, testArgs{}, ""},
		{[]string{"-j", "0"}, testArgs{}, ""},
		{[]string{"-j", "-2"}, testArgs{threads: -2}, ""},
		{[]string{"-j=4", "a"}, testArgs{threads: 4, paths: []string{"a"}}, ""},
		{[]string{"--threads=3"}, testArgs{threads: 3}, ""},
		{[]string{"run", "a", "--threads", "8", "b", "--learn", "--keep-sarif", "--show-opengrep-output"},
			testArgs{threads: 8, paths: []string{"a", "b"}, learn: true, keepSARIF: true, showOutput: true}, ""},
		{[]string{"a", "--help"}, testArgs{help: true, paths: []string{"a"}}, ""},
		{[]string{"accept", "a", "b"}, testArgs{accept: true, paths: []string{"a", "b"}}, ""},
		{[]string{"accept", "-h"}, testArgs{accept: true, help: true}, ""},
		{[]string{"a", "run"}, testArgs{paths: []string{"a", "run"}}, ""},
		{[]string{"-j"}, testArgs{}, "-j needs a value"},
		{[]string{"--threads", "many"}, testArgs{}, `--threads needs a number, not "many"`},
		{[]string{"--sarif"}, testArgs{}, "unknown flag --sarif; gogrep test does not forward flags to opengrep"},
		{[]string{"--learn=true"}, testArgs{}, "unknown flag --learn=true; gogrep test does not forward flags to opengrep"},
		{[]string{"accept", "--learn"}, testArgs{}, "gogrep test accept takes only paths, not --learn"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			got, err := parseTestArgs(tt.args)
			if tt.errMsg != "" {
				if err == nil || err.Error() != tt.errMsg {
					t.Errorf("parseTestArgs(%q) error = %v, want %q", tt.args, err, tt.errMsg)
				}
				return
			}
			if err != nil || fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Errorf("parseTestArgs(%q) = %+v, %v; want %+v", tt.args, got, err, tt.want)
			}
		})
	}
}

// testProject copies testdata/project, without the output of earlier runs
// (which git ignores), into a temporary directory, adds files (keyed by slash
// path) and makes it the working directory.
func testProject(t *testing.T, files map[string]string) {
	t.Helper()
	dir, src := t.TempDir(), filepath.Join(repoDir, "testdata", "project")
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return os.MkdirAll(filepath.Join(dir, rel), 0o700)
		case d.Name() == "actual.txt" || d.Name() == "actual.sarif":
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, rel), data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	writeTree(t, dir, files)
	t.Chdir(dir)
}

var (
	pinOnce sync.Once
	pinSkip string // why tests that run opengrep are skipped
)

// requireOpengrep skips the test under -short, and when gogrep finds no
// opengrep or not the version that opengrep.json pins, which made the golden
// files.
func requireOpengrep(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("runs opengrep")
	}
	pinOnce.Do(func() {
		var pin struct{ Version string }
		data, err := os.ReadFile(filepath.Join(repoDir, "opengrep.json"))
		if err == nil {
			err = json.Unmarshal(data, &pin)
		}
		if err != nil {
			pinSkip = "reading opengrep.json: " + err.Error()
			return
		}
		bin, err := opengrepBin()
		if err != nil {
			pinSkip = "no opengrep: " + err.Error()
			return
		}
		out, err := exec.Command(bin, "--version").Output()
		if v := strings.TrimSpace(string(out)); err != nil || "v"+v != pin.Version {
			pinSkip = fmt.Sprintf("%s --version = %q, %v; the golden files need opengrep %s", bin, v, err, pin.Version)
		}
	})
	if pinSkip != "" {
		t.Skip(pinSkip)
	}
}

// checkGolden compares output with the golden file testdata/golden/name, or
// rewrites the file with -update. The golden files hold the output of a
// bundled build; other builds add a hint to unresolved rule references.
func checkGolden(t *testing.T, name, output string) {
	t.Helper()
	output = strings.ReplaceAll(output, "; this gogrep build has no bundled rule sets", "")
	file := filepath.Join(repoDir, "testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(output), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if output != string(want) {
		diff := ruletest.Diff(ruletest.Normalize(want), ruletest.Normalize([]byte(output)))
		if diff == "" {
			diff = fmt.Sprintf("%q", output)
		}
		t.Errorf("output differs from testdata/golden/%s (go test -update rewrites it):\n%s", name, diff)
	}
}

// checkFile checks that the file at the slash path name holds want and,
// except on Windows, that only its owner can read and write it.
func checkFile(t *testing.T, name, want string) {
	t.Helper()
	p := filepath.FromSlash(name)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Error(err)
		return
	}
	if string(data) != want {
		t.Errorf("%s = %q, want %q", name, data, want)
	}
	if fi, err := os.Stat(p); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("%s has mode %v, want 0600", name, fi.Mode().Perm())
	}
}

func checkNoFile(t *testing.T, name string) {
	t.Helper()
	if _, err := os.Lstat(filepath.FromSlash(name)); err == nil {
		t.Errorf("%s exists, want it removed", name)
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestTestUsage(t *testing.T) {
	testProject(t, nil)
	tests := []struct {
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{[]string{"test", "--help"}, 0, testUsage, ""},
		{[]string{"test", "accept", "-h"}, 0, testUsage, ""},
		{[]string{"test", "accept"}, 0, "", ""},
		{[]string{"test", "--sarif"}, 2, "", "gogrep: unknown flag --sarif; gogrep test does not forward flags to opengrep\n"},
		{[]string{"test", "-j"}, 2, "", "gogrep: -j needs a value\n"},
		{[]string{"test", "accept", "--rule", "no-exec-command"}, 2, "", "gogrep: gogrep test accept takes only paths, not --rule, --suite or --gogrep-* flags\n"},
		{[]string{"test", "opengrep/gogrep/rules/go"}, 2, "", "gogrep: opengrep/gogrep/rules/go is not under opengrep/gogrep/rules/test\n"},
		{[]string{"test", testRoot + "/go/nope"}, 2, "", "gogrep: opengrep/gogrep/rules/test/go/nope does not exist\n"},
		{[]string{"test", "--rule", "nope"}, 2, "", "gogrep: --rule nope matches no rule; list them with: gogrep rules --suite all\n"},
		{[]string{"test", "--rule", "todo-marker", testRoot + "/go"}, 2, "", "gogrep: no tests match the selection\n"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			code, stdout, stderr := runGogrep(tt.args...)
			if code != tt.code || stdout != tt.stdout || stderr != tt.stderr {
				t.Errorf("gogrep %q = %d, %q, %q; want %d, %q, %q", tt.args, code, stdout, stderr, tt.code, tt.stdout, tt.stderr)
			}
		})
	}

	t.Run("no test root", func(t *testing.T) {
		t.Chdir(t.TempDir())
		code, _, stderr := runGogrep("test")
		if want := "gogrep: no opengrep/gogrep/rules/test directory here; run gogrep test from the project root\n"; code != 2 || stderr != want {
			t.Errorf("gogrep test = %d, %q; want 2, %q", code, stderr, want)
		}
	})
}

// gogrep test runs each opengrep process in its fixture's directory, so it
// resolves $OPENGREP_BIN first, and a missing binary is a setup error.
func TestTestOpengrepBin(t *testing.T) {
	useFakeOpengrep(t, 0)
	testProject(t, brokenFiles)
	exe := os.Getenv("OPENGREP_BIN")
	fixture := testRoot + "/go/exec-command"

	t.Run("relative", func(t *testing.T) {
		wd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(wd, exe)
		if err != nil {
			t.Skipf("no relative path to %s: %v", exe, err)
		}
		t.Setenv("OPENGREP_BIN", rel)
		// The fake opengrep loads no rule, so the test fails at RULE.
		code, stdout, stderr := runGogrep("test", "--show-opengrep-output", fixture)
		_, cmd, _ := strings.Cut(stdout, "  $ ")
		bin, _, _ := strings.Cut(strings.TrimPrefix(cmd, "'"), " scan ")
		if code != 1 || stderr != "" || !strings.Contains(stdout, "FAILED(RULE)") || !filepath.IsAbs(strings.TrimSuffix(bin, "'")) {
			t.Errorf("gogrep test with OPENGREP_BIN=%s = %d, %q, stdout\n%s\nwant 1, no stderr, a RULE failure and an absolute opengrep", rel, code, stderr, stdout)
		}
	})

	t.Run("missing", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "opengrep")
		t.Setenv("OPENGREP_BIN", missing)
		code, stdout, stderr := runGogrep("test", fixture)
		if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "gogrep: exec: ") {
			t.Errorf("gogrep test with a missing OPENGREP_BIN = %d, %q, %q; want 2, no stdout, a gogrep: exec: error", code, stdout, stderr)
		}
		// Tests that fail before opengrep runs need no binary.
		code, stdout, stderr = runGogrep("test", testRoot+"/broken/unknown")
		if code != 1 || stderr != "" || !strings.Contains(stdout, "FAILED(RULE)") {
			t.Errorf("gogrep test of an unresolved reference with a missing OPENGREP_BIN = %d, %q, stdout\n%s\nwant 1, no stderr, a RULE failure", code, stderr, stdout)
		}
	})

	t.Run("directory", func(t *testing.T) {
		t.Setenv("OPENGREP_BIN", ".")
		if code, stdout, stderr := runGogrep("test", fixture); code != 2 || stdout != "" || !strings.HasPrefix(stderr, "gogrep: ") {
			t.Errorf("gogrep test with OPENGREP_BIN=. = %d, %q, %q; want 2, no stdout, a gogrep: error", code, stdout, stderr)
		}
	})
}

func TestRulesSkipsFixtures(t *testing.T) {
	testProject(t, nil)
	code, stdout, stderr := runGogrep("rules", "--suite", "all")
	if code != 0 {
		t.Fatalf("gogrep rules --suite all = %d, %q", code, stderr)
	}
	var project []string
	for _, line := range strings.Split(stdout, "\n") {
		if id, _, _ := strings.Cut(line, " "); strings.HasPrefix(id, "project.") {
			project = append(project, id)
		}
	}
	if want := []string{"project.generic.todo-marker", "project.go.no-exec-command", "project.go.no-exec-command-in-prod"}; !slices.Equal(project, want) {
		t.Errorf("project rules = %q, want %q", project, want)
	}
}

func TestTestCommitted(t *testing.T) {
	requireOpengrep(t)
	testProject(t, nil)
	code, stdout, stderr := runGogrep("test")
	if code != 0 || stderr != "" {
		t.Errorf("gogrep test = %d, stderr %q; want 0 and no stderr", code, stderr)
	}
	checkGolden(t, "pass.txt", stdout)
}

func TestTestMissingExpected(t *testing.T) {
	requireOpengrep(t)
	testProject(t, nil)
	fixture := testRoot + "/go/exec-command"
	expected, actual := fixture+"/expected.txt", fixture+"/actual.txt"
	table := readFile(t, expected)
	if err := os.Remove(filepath.FromSlash(expected)); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ := runGogrep("test", fixture)
	if code != 1 {
		t.Errorf("gogrep test without expected.txt = %d, want 1", code)
	}
	checkGolden(t, "exec-command-missing.txt", stdout)
	checkFile(t, actual, table)

	code, stdout, stderr := runGogrep("test", "accept")
	if want := "Accepted " + fixture + "\n"; code != 0 || stdout != want || stderr != "" {
		t.Errorf("gogrep test accept = %d, %q, %q; want 0, %q, no stderr", code, stdout, stderr, want)
	}
	checkFile(t, expected, table)
	checkNoFile(t, actual)

	writeTree(t, ".", map[string]string{actual: "stale\n"})
	code, stdout, _ = runGogrep("test", fixture)
	if code != 0 {
		t.Errorf("gogrep test after accept = %d, want 0", code)
	}
	checkGolden(t, "exec-command-pass.txt", stdout)
	checkNoFile(t, actual)
}

func TestTestRegression(t *testing.T) {
	requireOpengrep(t)
	testProject(t, nil)
	rule := "opengrep/gogrep/rules/go/no-exec-command.yaml"
	narrowed := strings.Replace(readFile(t, rule), "exec.Command($CMD, ...)", "exec.Command($CMD)", 1)
	writeTree(t, ".", map[string]string{rule: narrowed})
	fixture := testRoot + "/go/exec-command"
	table := "| sample.go:7:6:7:24 | Avoid running \"ls\" with exec.Command |\n"

	code, stdout, _ := runGogrep("test", fixture)
	if code != 1 {
		t.Errorf("gogrep test = %d, want 1", code)
	}
	checkGolden(t, "exec-command-regression.txt", stdout)
	checkFile(t, fixture+"/actual.txt", table)

	code, stdout, _ = runGogrep("test", "--learn", fixture)
	if code != 0 {
		t.Errorf("gogrep test --learn = %d, want 0", code)
	}
	checkGolden(t, "exec-command-learn.txt", stdout)
	checkFile(t, fixture+"/expected.txt", table)
	checkNoFile(t, fixture+"/actual.txt")

	code, stdout, _ = runGogrep("test", fixture)
	if code != 0 {
		t.Errorf("gogrep test after --learn = %d, want 0", code)
	}
	checkGolden(t, "exec-command-pass.txt", stdout)
}

const goSample = "package a\n\nimport \"os/exec\"\n\nfunc A() { exec.Command(\"a\") }\n"

// brokenFiles add fixtures to testdata/project that fail at SETUP or RULE,
// and the rules they refer to.
var brokenFiles = map[string]string{
	// opengrep rejects these rules: the first has no message (exit 7), the
	// second an invalid pattern (exit 2).
	"opengrep/gogrep/rules/broken/no-message.yaml": "rules:\n  - id: no-message\n    languages: [go]\n    severity: WARNING\n    pattern: exec.Command(...)\n",
	"opengrep/gogrep/rules/broken/unclosed.yaml":   "rules:\n  - id: unclosed\n    languages: [go]\n    severity: WARNING\n    message: Unclosed\n    pattern: exec.Command($CMD, ...\n",
	// A second go.no-exec-command, relative to the broken namespace.
	"opengrep/gogrep/rules/broken/go/no-exec-command.yaml": "rules:\n  - id: no-exec-command\n    languages: [go]\n    severity: WARNING\n    message: m\n    pattern: exec.Command(...)\n",

	testRoot + "/broken/schema/rule.ref":      "no-message\n",
	testRoot + "/broken/schema/a.go":          goSample,
	testRoot + "/broken/pattern/rule.ref":     "unclosed\n",
	testRoot + "/broken/pattern/a.go":         goSample,
	testRoot + "/broken/unknown/rule.ref":     "no-such-rule\n",
	testRoot + "/broken/unknown/a.go":         goSample,
	testRoot + "/broken/ambiguous/rule.ref":   "go.no-exec-command\n",
	testRoot + "/broken/ambiguous/a.go":       goSample,
	testRoot + "/broken/empty/rule.ref":       "no-exec-command\n",
	testRoot + "/broken/outer/rule.ref":       "no-exec-command\n",
	testRoot + "/broken/outer/a.go":           goSample,
	testRoot + "/broken/outer/inner/rule.ref": "no-exec-command\n",
	testRoot + "/broken/outer/inner/a.go":     goSample,
	testRoot + "/broken/typo/rule.ref":        "no-exec-command\n",
	testRoot + "/broken/typo/a.go":            goSample,
	testRoot + "/broken/typo/expected.text":   "",
	testRoot + "/broken/orphan/expected.txt":  "",
}

func TestTestBroken(t *testing.T) {
	requireOpengrep(t)
	testProject(t, brokenFiles)
	var outputs []string
	for _, j := range []string{"1", "8"} {
		code, stdout, stderr := runGogrep("test", "-j", j)
		if want := "gogrep: warning: 1 project rule has no test fixture:\n  project.broken.go.no-exec-command\n"; code != 1 || stderr != want {
			t.Errorf("gogrep test -j %s = %d, %q; want 1, %q", j, code, stderr, want)
		}
		checkGolden(t, "broken.txt", stdout)
		outputs = append(outputs, stdout)
	}
	if outputs[0] != outputs[1] {
		t.Errorf("gogrep test -j 1 and -j 8 print different reports")
	}
}

func TestTestSelection(t *testing.T) {
	requireOpengrep(t)
	testProject(t, brokenFiles)
	code, stdout, stderr := runGogrep("test", "--rule", "no-exec-command")
	if code != 1 || stderr != "" {
		t.Errorf("gogrep test --rule no-exec-command = %d, %q; want 1 and no stderr", code, stderr)
	}
	checkGolden(t, "selection.txt", stdout)
}

func TestScanSkipsFixtures(t *testing.T) {
	requireOpengrep(t)
	testProject(t, map[string]string{
		".semgrepignore": "# Replaces opengrep's default ignores, test/ among them.\n*.md\n",
		"main.go":        goSample,
	})
	code, stdout, stderr := runGogrep("scan", "--rule", "no-exec-command", "--sarif", ".")
	if code != 0 {
		t.Fatalf("gogrep scan = %d, %q", code, stderr)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }
					}
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(stdout), &log); err != nil || len(log.Runs) != 1 {
		t.Fatalf("stdout is not a SARIF log with one run (%v): %q", err, stdout)
	}
	var uris []string
	for _, r := range log.Runs[0].Results {
		for _, l := range r.Locations {
			uris = append(uris, l.PhysicalLocation.ArtifactLocation.URI)
		}
	}
	if want := []string{"main.go"}; !slices.Equal(uris, want) {
		t.Errorf("gogrep scan reports %q, want %q", uris, want)
	}
}

func TestOpengrepVersion(t *testing.T) {
	requireOpengrep(t)
	data, err := os.ReadFile(filepath.Join(repoDir, "opengrep.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pin struct{ Version string }
	if err := json.Unmarshal(data, &pin); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := runGogrep("opengrep", "--version")
	// opengrep ends its lines with CRLF on Windows, and gogrep passes them on.
	stdout = strings.ReplaceAll(stdout, "\r\n", "\n")
	if want := strings.TrimPrefix(pin.Version, "v") + "\n"; code != 0 || stdout != want {
		t.Errorf("gogrep opengrep --version = %d, %q; want 0, %q", code, stdout, want)
	}
}
