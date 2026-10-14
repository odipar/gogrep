package gogrep

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
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
)

// lintPrefix starts the id of every rule of LintSuite.
const lintPrefix = "opengrep-rules.yaml.semgrep."

// twoChecks is a project suite that overrides LintSuite with two of its rules.
const twoChecks = "- description: Two checks\n- rules: bundled\n- include:\n    id: [" +
	lintPrefix + "metadata-category, " + lintPrefix + "metadata-technology]\n"

// securityRule is a security rule without subcategory, confidence,
// likelihood or impact.
const securityRule = `rules:
  - id: insecure
    languages: [go]
    severity: WARNING
    message: m
    pattern: f()
    metadata:
      category: security
      technology: [go]
`

// scannedTargets returns what the fake opengrep scanned in res: its arguments
// after "--".
func scannedTargets(t *testing.T, res *LintResult) []string {
	t.Helper()
	_, run := scanned(t, res.Result)
	i := slices.Index(run.Args, "--")
	if i < 0 {
		t.Fatalf("the fake ran with %q, without --", run.Args)
	}
	return run.Args[i+1:]
}

// osPaths returns the slash paths ps as OS paths.
func osPaths(ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = filepath.FromSlash(p)
	}
	return out
}

// checkFiles checks that the lint res listed and scanned the rule files
// want, slash paths.
func checkFiles(t *testing.T, res *LintResult, want []string) {
	t.Helper()
	if got := scannedTargets(t, res); !slices.Equal(res.Files, want) || !slices.Equal(got, osPaths(want)) {
		t.Errorf("Lint listed %q and scanned %q; want %q", res.Files, got, want)
	}
}

// The zero LintOptions lint the rule files of ProjectRulesDir with
// LintSuite: exactly a Scan of them with that suite.
func TestLint(t *testing.T) {
	t.Parallel()
	e := newFakeEngine(t)
	dir := t.TempDir()
	writeTree(t, dir, shadowing)
	ctx := context.Background()

	rs, err := e.Rules(dir, &RulesOptions{Selection: Selection{Suites: []string{LintSuite}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if !strings.HasPrefix(r.ID, lintPrefix) {
			t.Errorf("%s selects %s", LintSuite, r.ID)
		}
	}
	if len(rs) != 45 {
		t.Errorf("%s selects %d rules, want the 45 of %s*", LintSuite, len(rs), lintPrefix)
	}
	files := []string{ProjectRulesDir + "/generic/todo-marker.yaml", ProjectRulesDir + "/go/no-exec-command.yaml"}
	scan, err := e.Scan(ctx, dir, &ScanOptions{Selection: Selection{Suites: []string{LintSuite}}, Targets: osPaths(files)})
	if err != nil {
		t.Fatal(err)
	}
	_, want := scanned(t, scan)

	for _, opts := range []*LintOptions{nil, {}, {Suite: LintSuite, Paths: []string{}}} {
		res, err := e.Lint(ctx, dir, opts)
		if err != nil {
			t.Errorf("Lint(%+v) = %v", opts, err)
			continue
		}
		if _, run := scanned(t, res.Result); !slices.Equal(run.Args, want.Args) || res.Rules != len(rs) || !slices.Equal(res.Files, files) {
			t.Errorf("Lint(%+v) ran the fake with %q and %d rules, and lists %q; want %q, as Scan, %d rules and %q", opts, run.Args, res.Rules, res.Files, want.Args, len(rs), files)
		}
	}

	var live bytes.Buffer
	if _, err := e.Lint(ctx, dir, &LintOptions{Stderr: &live}); err != nil || live.String() != "fake stderr\n" {
		t.Errorf("Lint with a Stderr = %v, and the Stderr got %q; want the fake's stderr", err, live.String())
	}
}

// Without paths, a directory without ProjectRulesDir is a plain error that
// names it, before opengrep is looked for; with paths, it is linted.
func TestLintNoRulesDir(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	empty := t.TempDir()
	notDir := t.TempDir() // its ProjectRulesDir is a file
	writeTree(t, notDir, map[string]string{ProjectRulesDir: rule("a", "go"), "rules/a.yaml": rule("a", "go")})
	missing := newEngine(t, Config{Opengrep: filepath.Join(t.TempDir(), "opengrep")})
	for _, dir := range []string{empty, notDir} {
		for _, opts := range []*LintOptions{nil, {Suite: "all"}} {
			res, err := missing.Lint(ctx, dir, opts)
			want := dir + " has no opengrep/gogrep/rules; name the rules to lint"
			if res != nil || err == nil || err.Error() != want || errors.Unwrap(err) != nil {
				t.Errorf("Lint(%s, %+v) = %v, %v; want no Result and the plain error %q", dir, opts, res, err, want)
			}
		}
	}

	res, err := newFakeEngine(t).Lint(ctx, notDir, &LintOptions{Paths: []string{"rules"}})
	if err != nil {
		t.Fatal(err)
	}
	checkFiles(t, res, []string{"rules/a.yaml"})
}

// Paths inside the fixtures, in any letter case and spelling, are refused
// before opengrep is looked for; others, even next to them, are linted,
// without the fixtures below them, in any letter case.
func TestLintFixtures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	writeTree(t, dir, fixtures)
	writeTree(t, dir, map[string]string{
		ProjectTestsDir + "/go/a/notes.yaml":              rule("notes", "go"),
		"opengrep/gogrep/rules/Test/go/b/notes.yml":       rule("notes", "go"), // the fixtures on a case-insensitive file system
		"opengrep/gogrep/rules/testing/t.yaml":            rule("t", "go"),
		"opengrep/gogrep/rules/test.yaml":                 rule("t", "go"),
		"opengrep/gogrep/rules/go/test/not-fixtures.yaml": rule("t", "go"),
		"test/top.yml":                                      rule("t", "go"),
		"opengrep/gogrep/suites/mine.yaml":                  "- import: rule-lint\n",
		"opengrep/gogrep/rules/generic/todo-marker.yaml.md": "Not a rule file\n",
	})
	missing := newEngine(t, Config{Opengrep: filepath.Join(t.TempDir(), "opengrep")})
	for _, p := range []string{
		ProjectTestsDir,
		ProjectTestsDir + "/",
		"./" + ProjectTestsDir,
		"./" + ProjectTestsDir + "/go/a/",
		ProjectTestsDir + "/go/a/notes.yaml",
		"Opengrep/GoGrep/Rules/TEST",
		"opengrep/gogrep/rules/Test/go/",
		"opengrep//gogrep/./rules/test",
		"opengrep/gogrep/rules/go/../test/go",
		filepath.FromSlash(ProjectTestsDir + "/go/a"),
	} {
		for _, paths := range [][]string{{p}, {"opengrep/gogrep/rules/go", p}} {
			res, err := missing.Lint(ctx, dir, &LintOptions{Paths: paths})
			want := p + " holds rule test fixtures, which are not linted"
			if res != nil || err == nil || err.Error() != want {
				t.Errorf("Lint of %q = %v, %v; want no Result and %q", paths, res, err, want)
			}
		}
	}

	paths := []string{
		"opengrep/gogrep/rules/go",
		"opengrep/gogrep/rules/testing",
		"opengrep/gogrep/rules/test.yaml",
		"opengrep/gogrep/rules/test/../go",
		"opengrep/gogrep",
		"test",
		".",
	}
	res, err := newFakeEngine(t).Lint(ctx, dir, &LintOptions{Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	checkFiles(t, res, []string{
		"opengrep/gogrep/rules/generic/todo-marker.yaml",
		"opengrep/gogrep/rules/go/no-exec-command.yaml",
		"opengrep/gogrep/rules/go/test/not-fixtures.yaml",
		"opengrep/gogrep/rules/test.yaml",
		"opengrep/gogrep/rules/testing/t.yaml",
		"opengrep/gogrep/suites/mine.yaml",
		"test/top.yml",
	})
}

// Lint lints every rule file below its paths, also those that .gitignore,
// .semgrepignore or opengrep's default ignores (tests/, vendor/,
// node_modules/, build/, hidden directories) hide from a scan, and only
// those: not the fixtures, in any letter case, nor other files.
func TestLintFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := rule("r", "go")
	writeTree(t, dir, map[string]string{
		".gitignore":                              ProjectRulesDir + "/gen/\n",
		".semgrepignore":                          ProjectRulesDir + "/semi/\n",
		ProjectRulesDir + "/.gitignore":           "*.yml\n",
		ProjectRulesDir + "/go/a.yaml":            r,
		ProjectRulesDir + "/go/b.yml":             r,
		ProjectRulesDir + "/go/tests/c.yaml":      r,
		ProjectRulesDir + "/vendor/d.yaml":        r,
		ProjectRulesDir + "/node_modules/e.yaml":  r,
		ProjectRulesDir + "/gen/f.yaml":           r,
		ProjectRulesDir + "/semi/g.yaml":          r,
		ProjectRulesDir + "/build/h.yaml":         r,
		ProjectRulesDir + "/.hidden/i.yaml":       r,
		ProjectRulesDir + "/README.md":            "Rules\n",
		ProjectRulesDir + "/go/x.yaml~":           r,
		ProjectRulesDir + "/go/x.json":            "{}\n",
		ProjectTestsDir + "/go/a/sample.yaml":     r,
		ProjectRulesDir + "/Test/go/b/sample.yml": r,
	})
	res, err := newFakeEngine(t).Lint(context.Background(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, f := range []string{".hidden/i.yaml", "build/h.yaml", "gen/f.yaml", "go/a.yaml", "go/b.yml", "go/tests/c.yaml", "node_modules/e.yaml", "semi/g.yaml", "vendor/d.yaml"} {
		want = append(want, ProjectRulesDir+"/"+f)
	}
	checkFiles(t, res, want)
}

// symlink makes link a symlink to target, both slash paths, link relative
// to dir, or skips the test where that cannot be done.
func symlink(t *testing.T, dir, target, link string) {
	t.Helper()
	name := filepath.Join(dir, filepath.FromSlash(link))
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.FromSlash(target), name); err != nil {
		t.Skipf("cannot create symlinks: %v", err)
	}
}

// A symlinked rule file, a symlinked rules directory and a path that leads
// through one are linted by the files they lead to, inside the directory;
// the fixtures they lead to are not, and neither is a symlinked directory
// below a path. A symlink that leads outside the directory, nowhere, or to
// a file that is not a rule file is an error that names it.
func TestLintSymlinks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newFakeEngine(t)
	r := rule("r", "go")

	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"real/go/a.yaml":             r,
		"real/test/go/x/sample.yaml": r,
		"real/Test/go/y/sample.yaml": r,
		"shared/linked.yaml":         r,
		"shared/sub/hidden.yaml":     r,
		"shared/chained.yml":         r,
		"other/rules/b.yaml":         r,
		"other/rules/test/c.yaml":    r, // not the fixtures of the rules directory
	})
	symlink(t, dir, "../../real", ProjectRulesDir)
	symlink(t, dir, "../../shared/linked.yaml", "real/go/link.yaml")
	symlink(t, dir, "../../shared/sub", "real/go/sub")                 // a directory, not entered
	symlink(t, dir, "../../shared/sub/hidden.yaml", "real/go/sub.txt") // not a rule file by name
	symlink(t, dir, "chained.yml", "shared/chain.yml")
	symlink(t, dir, "../../shared/chain.yml", "real/go/chain.yaml")
	symlink(t, dir, "other/rules", "rules")
	symlink(t, dir, "real/test", "fixtures")

	for _, tt := range []struct {
		paths []string
		want  []string
	}{
		{nil, []string{"real/go/a.yaml", "shared/chained.yml", "shared/linked.yaml"}},
		{[]string{"real"}, []string{"real/go/a.yaml", "shared/chained.yml", "shared/linked.yaml"}},
		{[]string{ProjectRulesDir + "/go/link.yaml"}, []string{"shared/linked.yaml"}},
		{[]string{ProjectRulesDir + "/go", "shared"}, []string{"real/go/a.yaml", "shared/chained.yml", "shared/linked.yaml", "shared/sub/hidden.yaml"}},
		{[]string{"rules"}, []string{"other/rules/b.yaml", "other/rules/test/c.yaml"}},
	} {
		res, err := e.Lint(ctx, dir, &LintOptions{Paths: tt.paths})
		if err != nil {
			t.Errorf("Lint of %q: %v", tt.paths, err)
			continue
		}
		checkFiles(t, res, tt.want)
	}
	for _, p := range []string{"fixtures", "fixtures/go", "real/test", "real/TEST/go"} {
		if _, err := e.Lint(ctx, dir, &LintOptions{Paths: []string{p}}); err == nil || err.Error() != p+" holds rule test fixtures, which are not linted" {
			t.Errorf("Lint of %s = %v, want it refused as the fixtures", p, err)
		}
	}

	outside := t.TempDir()
	writeTree(t, outside, map[string]string{"x.yaml": r, "x.txt": r})
	tests := []struct {
		target, link string
		paths        []string
		want         string // the error
	}{
		{outside + "/x.yaml", ProjectRulesDir + "/go/out.yaml", nil, ProjectRulesDir + "/go/out.yaml leads outside the directory through a symlink"},
		{outside, ProjectRulesDir, nil, filepath.FromSlash(ProjectRulesDir) + " leads outside the directory through a symlink"},
		{outside, "linked", []string{"linked"}, "linked leads outside the directory through a symlink"},
		{"../x.txt", ProjectRulesDir + "/go/txt.yaml", nil, ProjectRulesDir + "/go/txt.yaml leads to " + ProjectRulesDir + "/x.txt, which is not a .yaml or .yml file"},
		{"x.txt", "txt.yaml", []string{"txt.yaml"}, "txt.yaml leads to x.txt, which is not a .yaml or .yml file"},
		{"nowhere.yaml", ProjectRulesDir + "/go/gone.yaml", nil, "stat " + ProjectRulesDir + "/go/gone.yaml: "},
	}
	for _, tt := range tests {
		dir := t.TempDir()
		writeTree(t, dir, map[string]string{ProjectRulesDir + "/go/a.yaml": r, ProjectRulesDir + "/x.txt": r, "x.txt": r})
		if tt.link == ProjectRulesDir {
			os.RemoveAll(filepath.Join(dir, filepath.FromSlash(ProjectRulesDir)))
		}
		symlink(t, dir, tt.target, tt.link)
		res, err := e.Lint(ctx, dir, &LintOptions{Paths: tt.paths})
		if res != nil || err == nil || !strings.HasPrefix(err.Error(), tt.want) || strings.HasSuffix(tt.want, ": ") != errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Lint of %q with a symlink %s to %s = %v, %v; want no Result and %q", tt.paths, tt.link, tt.target, res, err, tt.want)
		}
	}
}

// A directory below a path that cannot be read is an error that names it.
func TestLintUnreadableDir(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory that its owner cannot read")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"other/a.yaml": rule("a", "go"), "other/private/b.yaml": rule("b", "go")})
	private := filepath.Join(dir, "other", "private")
	if err := os.Chmod(private, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(private, 0o700) })
	res, err := newFakeEngine(t).Lint(context.Background(), dir, &LintOptions{Paths: []string{"other"}})
	if want := "open other/private: "; res != nil || !errors.Is(err, fs.ErrPermission) || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("Lint with an unreadable directory = %v, %v; want no Result and an error %q...", res, err, want)
	}
}

// The rule file arguments may take 30,000 bytes, which keeps opengrep's
// command line within Windows' limit; more are an error.
func TestLintTooManyFiles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	// Arguments (path and a separator) of 120 bytes each: 250 fill the
	// 30,000 bytes allowed exactly.
	files := map[string]string{"z.yaml": ""}
	var many []string
	for i := range 250 {
		name := fmt.Sprintf("many/%s%03d.yaml", strings.Repeat("x", 106), i)
		files[name] = ""
		many = append(many, name)
		files[fmt.Sprintf("more/%s%03d.yaml", strings.Repeat("x", 107), i)] = ""
	}
	writeTree(t, dir, files)
	e := newFakeEngine(t)
	res, err := e.Lint(ctx, dir, &LintOptions{Paths: []string{"many", many[0]}})
	if err != nil {
		t.Fatal(err)
	}
	checkFiles(t, res, many)
	for _, paths := range [][]string{{"more"}, {"many", "z.yaml"}} {
		res, err := e.Lint(ctx, dir, &LintOptions{Paths: paths})
		want := fmt.Sprintf("too many rule files (%d); lint fewer paths at once", 250+len(paths)-1)
		if res != nil || err == nil || err.Error() != want {
			t.Errorf("Lint of %q = %v, %v; want no Result and %q", paths, res, err, want)
		}
	}
}

// Without rule files, Lint neither runs opengrep nor looks for it, and
// returns a complete Result without findings, for the suite it resolves.
func TestLintNoFiles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"code/main.go":                       "package main\n",
		ProjectRulesDir + "/README.md":       "Rules\n",
		ProjectTestsDir + "/go/a/notes.yaml": rule("a", "go"),
		ProjectSuitesDir + "/rule-lint.yaml": twoChecks,
	})
	failing := newFakeEngine(t, "GOGREP_TEST_FAKE_EXIT=7") // a scan fails
	missing := newEngine(t, Config{Opengrep: filepath.Join(t.TempDir(), "opengrep")})
	for _, e := range []*Engine{failing, missing} {
		for _, opts := range []*LintOptions{nil, {Paths: []string{"code"}}, {Paths: []string{"code", ProjectRulesDir}}} {
			res, err := e.Lint(ctx, dir, opts)
			if err != nil {
				t.Errorf("Lint(%+v) without rule files = %v", opts, err)
				continue
			}
			var log struct {
				Version string
				Runs    []struct {
					Tool    struct{ Driver struct{ Name string } }
					Results []any
				}
			}
			if err := json.Unmarshal(res.SARIF, &log); err != nil || log.Version != "2.1.0" || len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "gogrep" || len(log.Runs[0].Results) != 0 {
				t.Errorf("Lint(%+v) without rule files has the SARIF log %s (%v); want one run of gogrep without results", opts, res.SARIF, err)
			}
			if res.Files != nil || res.Findings != nil || res.Diagnostics != nil || !res.Complete || res.Rules != 2 || res.Stderr != nil {
				t.Errorf("Lint(%+v) without rule files = %+v; want a complete Result of 2 rules, without files, findings, diagnostics or stderr", opts, res)
			}
		}
		_, err := e.Lint(ctx, dir, &LintOptions{Paths: []string{"code"}, Suite: "nope"})
		if !errors.Is(err, ErrUnknownSuite) {
			t.Errorf("Lint without rule files with an unknown suite = %v, want ErrUnknownSuite", err)
		}
	}
}

// The directory is checked as Scan checks it; a path that is not relative
// and inside it, does not exist or is a file but not a rule file is
// refused, before opengrep is looked for.
func TestLintArguments(t *testing.T) {
	t.Parallel()
	e := newFakeEngine(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"main.go": "package main\n", "opengrep/gogrep/rules/go/a.yaml": rule("a", "go"), "a.yaml.txt": rule("a", "go")})

	if _, err := e.Lint(ctx, "relative", nil); err == nil || err.Error() != `directory "relative" is not an absolute path` {
		t.Errorf("Lint of a relative directory = %v, want an error", err)
	}
	for _, bad := range []string{filepath.Join(dir, "missing"), filepath.Join(dir, "main.go")} {
		for _, opts := range []*LintOptions{nil, {Paths: []string{"a.yaml"}}} {
			_, err := e.Lint(ctx, bad, opts)
			if err == nil || !strings.HasPrefix(err.Error(), fmt.Sprintf("directory %q: ", bad)) || errors.Is(err, ErrNoOpengrep) {
				t.Errorf("Lint(%s, %+v) = %v; want an error that names the directory, not ErrNoOpengrep", bad, opts, err)
			}
			if filepath.Base(bad) == "missing" && !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("Lint(%s, %+v) = %v; want fs.ErrNotExist", bad, opts, err)
			}
		}
	}

	missing := newEngine(t, Config{Opengrep: filepath.Join(t.TempDir(), "opengrep")})
	for _, p := range []string{"../x", "", "go/../../x", filepath.Join(dir, "main.go"), filepath.Join(dir, filepath.FromSlash(ProjectTestsDir))} {
		for _, paths := range [][]string{{p}, {"opengrep/gogrep/rules", p}} {
			res, err := missing.Lint(ctx, dir, &LintOptions{Paths: paths})
			want := fmt.Sprintf("lint path %q is not a relative path inside the directory", p)
			if res != nil || err == nil || err.Error() != want {
				t.Errorf("Lint of %q = %v, %v; want no Result and %q", paths, res, err, want)
			}
		}
	}

	for _, p := range []string{"missing", "opengrep/gogrep/rules/go/missing.yaml"} {
		res, err := missing.Lint(ctx, dir, &LintOptions{Paths: []string{"opengrep/gogrep/rules", p}})
		if res != nil || !errors.Is(err, fs.ErrNotExist) || !strings.HasPrefix(err.Error(), "stat "+p+": ") {
			t.Errorf("Lint of %s = %v, %v; want no Result and a stat error that names it", p, res, err)
		}
	}
	for _, p := range []string{"main.go", "a.yaml.txt"} {
		res, err := missing.Lint(ctx, dir, &LintOptions{Paths: []string{p, "opengrep/gogrep/rules"}})
		if want := p + " is not a rule file (.yaml or .yml)"; res != nil || err == nil || err.Error() != want {
			t.Errorf("Lint of %s = %v, %v; want no Result and %q", p, res, err, want)
		}
	}
}

// Suite picks another suite, resolved as Scan resolves it, and a project
// suite named LintSuite overrides the built-in one.
func TestLintSuite(t *testing.T) {
	t.Parallel()
	e := newFakeEngine(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"opengrep/gogrep/rules/go/no-exec-command.yaml": noExecRule,
		"metadata.yaml": "- description: The metadata checks\n- rules: bundled\n- include:\n    id: /^opengrep-rules\\.yaml\\.semgrep\\.metadata-/\n",
	})
	overridden := t.TempDir()
	writeTree(t, overridden, map[string]string{
		"opengrep/gogrep/rules/go/no-exec-command.yaml": noExecRule,
		ProjectSuitesDir + "/rule-lint.yaml":            twoChecks,
	})

	tests := []struct {
		dir   string
		suite string
		n     int // the number of rules, or 0 for as many as Rules selects
	}{
		{dir, "", 45},
		{dir, "metadata.yaml", 0},
		{dir, "code-scanning", 0},
		{dir, "all", 0},
		{overridden, "", 2},
		{overridden, LintSuite, 2},
	}
	for _, tt := range tests {
		sel := Selection{Suites: []string{cmp.Or(tt.suite, LintSuite)}}
		rs, err := e.Rules(tt.dir, &RulesOptions{Selection: sel})
		if err != nil {
			t.Fatal(err)
		}
		if tt.n == 0 {
			tt.n = len(rs)
		}
		res, err := e.Lint(ctx, tt.dir, &LintOptions{Suite: tt.suite})
		if err != nil {
			t.Errorf("Lint with suite %q: %v", tt.suite, err)
			continue
		}
		scan, err := e.Scan(ctx, tt.dir, &ScanOptions{Selection: sel, Targets: []string{filepath.FromSlash(ProjectRulesDir + "/go/no-exec-command.yaml")}})
		if err != nil {
			t.Fatal(err)
		}
		_, run := scanned(t, res.Result)
		_, want := scanned(t, scan)
		if res.Rules != tt.n || len(rs) != tt.n || !slices.Equal(run.Args, want.Args) {
			t.Errorf("Lint of %s with suite %q ran the fake with %q and %d rules; want %q, as Scan, and %d rules", tt.dir, tt.suite, run.Args, res.Rules, want.Args, tt.n)
		}
	}

	_, err := e.Lint(ctx, dir, &LintOptions{Suite: "nope"})
	var se *SelectionError
	if !errors.As(err, &se) || !errors.Is(err, ErrUnknownSuite) || err.Error() != `unknown suite "nope"` {
		t.Errorf("Lint with an unknown suite = %#v, want a *SelectionError that is ErrUnknownSuite", err)
	}
}

// Concurrent lints of different directories each lint their own, with their
// own suite.
func TestLintConcurrently(t *testing.T) {
	t.Parallel()
	e := newFakeEngine(t)
	var wg sync.WaitGroup
	for i := range 4 {
		dir := t.TempDir()
		files := map[string]string{ProjectRulesDir + "/go/r.yaml": rule(fmt.Sprintf("r%d", i), "go")}
		n, opts := 45, &LintOptions{}
		if i%2 == 1 {
			files[ProjectSuitesDir+"/rule-lint.yaml"] = twoChecks
			n, opts = 2, &LintOptions{Paths: []string{filepath.FromSlash(ProjectRulesDir + "/go")}}
		}
		writeTree(t, dir, files)
		wg.Go(func() {
			res, err := e.Lint(context.Background(), dir, opts)
			if err != nil {
				t.Error(err)
				return
			}
			_, run := scanned(t, res.Result)
			wd, _ := os.Stat(run.Dir)
			want, _ := os.Stat(dir)
			if !os.SameFile(wd, want) || res.Rules != n {
				t.Errorf("a lint of %s ran in %s with %d rules; want %d", dir, run.Dir, res.Rules, n)
			}
		})
	}
	wg.Wait()
}

// ruleIDs returns the rule ids of the findings of res in the file path,
// sorted.
func ruleIDs(res *Result, path string) []string {
	var out []string
	for _, f := range res.Findings {
		if f.Path == path {
			out = append(out, f.RuleID)
		}
	}
	slices.Sort(out)
	return out
}

func TestLintOpengrep(t *testing.T) {
	e := requireOpengrep(t)
	t.Parallel()
	ctx := context.Background()

	// A rule without metadata, and a security rule without the metadata a
	// security rule needs, get one finding for each missing field: the
	// findings of a Scan with the suite.
	t.Run("missing metadata", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		bare, insecure := ProjectRulesDir+"/go/bare.yaml", ProjectRulesDir+"/go/insecure.yaml"
		writeTree(t, dir, map[string]string{bare: rule("bare", "go"), insecure: securityRule})
		res, err := e.Lint(ctx, dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := ruleIDs(res.Result, bare), []string{lintPrefix + "metadata-category", lintPrefix + "metadata-technology"}; !slices.Equal(got, want) {
			t.Errorf("Lint found %q in a rule without metadata, want %q", got, want)
		}
		want := []string{lintPrefix + "metadata-confidence", lintPrefix + "metadata-impact", lintPrefix + "metadata-likelihood", lintPrefix + "metadata-subcategory"}
		if got := ruleIDs(res.Result, insecure); !slices.Equal(got, want) {
			t.Errorf("Lint found %q in a security rule without subcategory, confidence, likelihood or impact, want %q", got, want)
		}
		if len(res.Findings) != 6 || !res.Complete || res.Rules != 45 {
			t.Errorf("Lint = %d rules, %+v, complete %v; want 45 rules, the 6 findings, and a complete run", res.Rules, res.Findings, res.Complete)
		}
		scan, err := e.Scan(ctx, dir, &ScanOptions{Selection: Selection{Suites: []string{LintSuite}}, Targets: []string{filepath.FromSlash(ProjectRulesDir)}})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(res.Findings, scan.Findings) {
			t.Errorf("Lint found %+v; want Scan's %+v", res.Findings, scan.Findings)
		}
	})

	// The example rules of testdata/project are clean.
	t.Run("example rules", func(t *testing.T) {
		t.Parallel()
		res, err := e.Lint(ctx, copyProject(t, nil), nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != 0 || len(res.Diagnostics) != 0 || !res.Complete {
			t.Errorf("Lint of testdata/project = %+v, %+v, complete %v; want a complete run without findings or diagnostics", res.Findings, res.Diagnostics, res.Complete)
		}
	})

	// The YAML samples of the fixtures are never linted, though a scan
	// without project rules finds them. The .semgrepignore replaces
	// opengrep's default ignores, which skip test/ directories.
	t.Run("fixtures", func(t *testing.T) {
		t.Parallel()
		sample := ProjectTestsDir + "/generic/todo-marker/bare.yaml"
		dir := copyProject(t, map[string]string{".semgrepignore": "*.md\n", sample: rule("bare", "generic")})
		for _, opts := range []*LintOptions{nil, {Paths: []string{filepath.FromSlash("opengrep/gogrep")}}, {Paths: []string{"."}}} {
			res, err := e.Lint(ctx, dir, opts)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range res.Findings {
				if strings.HasPrefix(f.Path, ProjectTestsDir+"/") {
					t.Errorf("Lint(%+v) found %s in %s, in the fixtures", opts, f.RuleID, f.Path)
				}
			}
		}

		res, err := e.Scan(ctx, dir, &ScanOptions{Selection: Selection{Suites: []string{LintSuite}}, NoProjectRules: true, Targets: []string{filepath.FromSlash(ProjectRulesDir)}})
		if err != nil {
			t.Fatal(err)
		}
		if got := ruleIDs(res, sample); !slices.Contains(got, lintPrefix+"metadata-category") {
			t.Errorf("Scan without project rules found %q in %s; want metadata-category", got, sample)
		}
	})

	// Rule files that opengrep's default ignores, .gitignore (in a git
	// repository) or .semgrepignore hide from a scan of their directory are
	// linted, as opengrep scans the files that Lint names.
	t.Run("ignored files", func(t *testing.T) {
		t.Parallel()
		git, gitErr := exec.LookPath("git")
		for _, semgrepignore := range []string{"", ProjectRulesDir + "/\n"} {
			dir := t.TempDir()
			files := map[string]string{".gitignore": ProjectRulesDir + "/gen/\n"}
			if semgrepignore != "" {
				files[".semgrepignore"] = semgrepignore
			}
			var want []string
			for _, f := range []string{"gen/a.yaml", "go/b.yaml", "go/tests/c.yaml", "node_modules/d.yaml", "vendor/e.yaml"} {
				files[ProjectRulesDir+"/"+f] = rule("r", "go")
				want = append(want, ProjectRulesDir+"/"+f)
			}
			writeTree(t, dir, files)
			if gitErr == nil {
				if out, err := exec.Command(git, "-C", dir, "init", "-q").CombinedOutput(); err != nil {
					t.Fatalf("git init: %v: %s", err, out)
				}
			}
			res, err := e.Lint(ctx, dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(res.Files, want) {
				t.Errorf("Lint with .semgrepignore %q listed %q, want %q", semgrepignore, res.Files, want)
			}
			for _, f := range want {
				if got := ruleIDs(res.Result, f); !slices.Contains(got, lintPrefix+"metadata-category") {
					t.Errorf("Lint with .semgrepignore %q found %q in %s; want metadata-category", semgrepignore, got, f)
				}
			}
			scan, err := e.Scan(ctx, dir, &ScanOptions{Selection: Selection{Suites: []string{LintSuite}}, Targets: []string{filepath.FromSlash(ProjectRulesDir)}})
			if err != nil {
				t.Fatal(err)
			}
			if n := len(scan.Findings); n >= len(res.Findings) {
				t.Errorf("a Scan with .semgrepignore %q found %d problems, Lint %d; want the ignores to hide some from the Scan", semgrepignore, n, len(res.Findings))
			}
		}
	})

	// A rule file that opengrep cannot parse has no findings but a
	// diagnostic, a syntax error that names it.
	t.Run("syntax error", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeTree(t, dir, map[string]string{"other/broken.yaml": "rules:\n  - id: broken\n    pattern: [unclosed\n", "other/bare.yaml": rule("bare", "go")})
		res, err := e.Lint(ctx, dir, &LintOptions{Paths: []string{"other"}})
		if err != nil {
			t.Fatal(err)
		}
		ok := len(res.Diagnostics) == 1 && res.Complete && ruleIDs(res.Result, "other/broken.yaml") == nil && len(ruleIDs(res.Result, "other/bare.yaml")) == 2
		for _, d := range res.Diagnostics {
			ok = ok && d.ID == "Other syntax error" && (strings.HasPrefix(d.Message, "Other syntax error at line other/broken.yaml:3:") ||
				strings.HasPrefix(d.Message, `Other syntax error at line other\broken.yaml:3:`))
		}
		if !ok {
			t.Errorf("Lint of a broken rule file = %+v, %+v, complete %v; want the bare rule's findings and one syntax error at line other/broken.yaml:3", res.Findings, res.Diagnostics, res.Complete)
		}
	})

	// A symlinked rules directory and a symlinked rule file are linted by
	// the files they lead to, which the findings name.
	t.Run("symlinks", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeTree(t, dir, map[string]string{"real/go/bare.yaml": rule("bare", "go"), "shared/linked.yaml": rule("linked", "go")})
		symlink(t, dir, "../../real", ProjectRulesDir)
		symlink(t, dir, "../../shared/linked.yaml", "real/go/link.yaml")
		res, err := e.Lint(ctx, dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"real/go/bare.yaml", "shared/linked.yaml"}
		if !slices.Equal(res.Files, want) || len(res.Diagnostics) != 0 || !res.Complete {
			t.Errorf("Lint listed %q, with diagnostics %+v, complete %v; want %q, none, complete", res.Files, res.Diagnostics, res.Complete, want)
		}
		for _, f := range want {
			if got, want := ruleIDs(res.Result, f), []string{lintPrefix + "metadata-category", lintPrefix + "metadata-technology"}; !slices.Equal(got, want) {
				t.Errorf("Lint found %q in %s, want %q", got, f, want)
			}
		}
	})
}
