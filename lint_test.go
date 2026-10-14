package gogrep

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
func scannedTargets(t *testing.T, res *Result) []string {
	t.Helper()
	_, run := scanned(t, res)
	i := slices.Index(run.Args, "--")
	if i < 0 {
		t.Fatalf("the fake ran with %q, without --", run.Args)
	}
	return run.Args[i+1:]
}

// The zero LintOptions lint ProjectRulesDir with LintSuite: exactly a Scan
// of it with that suite, which excludes the fixtures.
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
	scan, err := e.Scan(ctx, dir, &ScanOptions{Selection: Selection{Suites: []string{LintSuite}}, Targets: []string{filepath.FromSlash(ProjectRulesDir)}})
	if err != nil {
		t.Fatal(err)
	}
	_, want := scanned(t, scan)
	if !slices.Contains(want.Args, "--exclude="+ProjectTestsDir) {
		t.Errorf("a scan with project rules ran the fake with %q, without excluding the fixtures", want.Args)
	}

	for _, opts := range []*LintOptions{nil, {}, {Suite: LintSuite, Paths: []string{}}} {
		res, err := e.Lint(ctx, dir, opts)
		if err != nil {
			t.Errorf("Lint(%+v) = %v", opts, err)
			continue
		}
		if _, run := scanned(t, res); !slices.Equal(run.Args, want.Args) || res.Rules != len(rs) {
			t.Errorf("Lint(%+v) ran the fake with %q and %d rules; want %q, as Scan, and %d rules", opts, run.Args, res.Rules, want.Args, len(rs))
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
	if got := scannedTargets(t, res); !slices.Equal(got, []string{"rules"}) {
		t.Errorf("Lint of rules scanned %q", got)
	}
}

// Paths inside the fixtures, in any letter case and spelling, are refused
// before opengrep is looked for; others, even next to them, are scanned as
// given.
func TestLintFixtures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	writeTree(t, dir, fixtures)
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
	if got := scannedTargets(t, res); !slices.Equal(got, paths) {
		t.Errorf("Lint of %q scanned %q", paths, got)
	}
}

// The directory and the paths are checked as Scan checks them.
func TestLintArguments(t *testing.T) {
	t.Parallel()
	e := newFakeEngine(t)
	ctx := context.Background()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"main.go": "package main\n", "opengrep/gogrep/rules/go/a.yaml": rule("a", "go")})

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

	for _, p := range []string{"../x", "", filepath.Join(dir, "main.go"), filepath.Join(dir, filepath.FromSlash(ProjectTestsDir))} {
		_, err := e.Lint(ctx, dir, &LintOptions{Paths: []string{p}})
		_, want := e.Scan(ctx, dir, &ScanOptions{Targets: []string{p}})
		if err == nil || want == nil || err.Error() != want.Error() {
			t.Errorf("Lint of %q = %v, want Scan's %v", p, err, want)
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
		scan, err := e.Scan(ctx, tt.dir, &ScanOptions{Selection: sel, Targets: []string{filepath.FromSlash(ProjectRulesDir)}})
		if err != nil {
			t.Fatal(err)
		}
		_, run := scanned(t, res)
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
			_, run := scanned(t, res)
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
		if got, want := ruleIDs(res, bare), []string{lintPrefix + "metadata-category", lintPrefix + "metadata-technology"}; !slices.Equal(got, want) {
			t.Errorf("Lint found %q in a rule without metadata, want %q", got, want)
		}
		want := []string{lintPrefix + "metadata-confidence", lintPrefix + "metadata-impact", lintPrefix + "metadata-likelihood", lintPrefix + "metadata-subcategory"}
		if got := ruleIDs(res, insecure); !slices.Equal(got, want) {
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
}
