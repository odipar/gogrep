package gogrep

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/odipar/gogrep/internal/bundle"
	"github.com/odipar/gogrep/internal/ruletest"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/golden")

var (
	realOnce   sync.Once
	realEngine *Engine
	realSkip   string // why tests that run opengrep are skipped
)

// requireOpengrep returns an Engine that finds opengrep as the gogrep command
// does, in the user's cache, embedded in a gogrep_bundled build or on PATH.
// It skips the test under -short, and when that opengrep is not the version
// that opengrep.json pins, which made the golden files.
func requireOpengrep(t *testing.T) *Engine {
	t.Helper()
	if testing.Short() {
		t.Skip("runs opengrep")
	}
	realOnce.Do(func() {
		e, err := New(Config{EmbeddedOpengrep: bundle.Binary(), AllowUnpinned: true})
		if err != nil {
			realSkip = err.Error()
			return
		}
		pins, err := e.src.pins()
		if err != nil {
			realSkip = err.Error()
			return
		}
		wd, _ := os.Getwd()
		cmd, err := e.Command(context.Background(), wd, nil, "--version")
		if err != nil {
			realSkip = "no opengrep: " + err.Error()
			return
		}
		var out bytes.Buffer
		cmd.Stdout = &out
		err = cmd.Run()
		if v := strings.TrimSpace(out.String()); err != nil || "v"+v != pins.Version {
			realSkip = fmt.Sprintf("%s --version = %q, %v; the golden files need opengrep %s", cmd.Path, v, err, pins.Version)
			return
		}
		realEngine = e
	})
	if realSkip != "" {
		t.Skip(realSkip)
	}
	return realEngine
}

// copyProject copies testdata/project, without the output of earlier rule
// test runs, into a temporary directory, adds files (keyed by slash path)
// and returns the directory.
func copyProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir, src := t.TempDir(), filepath.Join("testdata", "project")
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
	return dir
}

// checkGolden compares data with the golden file testdata/golden/name, or
// rewrites the file with -update.
func checkGolden(t *testing.T, name string, data []byte) {
	t.Helper()
	file := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Errorf("Scan differs from testdata/golden/%s (go test -update rewrites it):\n%s", name, ruletest.Diff(ruletest.Normalize(want), ruletest.Normalize(data)))
	}
}

// scanFiles add code to testdata/project: main.go has matches of the
// project's rules, one of them suppressed, and of a rule of the default
// suite; a fixture holds a match of that rule too. The .semgrepignore
// replaces opengrep's default ignores, which skip test/ directories.
var scanFiles = map[string]string{
	".semgrepignore": "*.md\n",
	"main.go":        "package main\n\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n\nfunc main() {\n\texec.Command(\"ls\") // TODO: remove\n\texec.Command(\"rm\") // nosemgrep\n\thttp.Get(\"http://example.com/\")\n}\n",
	ProjectTestsDir + "/go/exec-command/sub/get.go": "package sub\n\nimport \"net/http\"\n\nfunc get() { http.Get(\"http://example.com/\") }\n",
}

func TestScanOpengrep(t *testing.T) {
	e := requireOpengrep(t)
	t.Parallel()
	ctx := context.Background()
	inFixture := ProjectTestsDir + "/go/exec-command/sub/get.go"

	t.Run("project rules", func(t *testing.T) {
		t.Parallel()
		res, err := e.Scan(ctx, copyProject(t, scanFiles), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Complete || !bytes.Contains(res.SARIF, []byte(`"name":"gogrep"`)) {
			t.Errorf("Result: complete %v; want a complete run, rebranded", res.Complete)
		}
		for i, f := range res.Findings {
			if f.Fingerprint == "" || i > 0 && f.Fingerprint == res.Findings[i-1].Fingerprint {
				t.Errorf("finding %+v has no fingerprint of its own", f)
			}
			if strings.HasPrefix(f.Path, ProjectTestsDir+"/") {
				t.Errorf("Scan reports %s, in the project's rule test fixtures", f.Path)
			}
			res.Findings[i].Fingerprint = "" // they may depend on the platform
		}
		golden, err := json.MarshalIndent(struct {
			Rules       int
			Findings    []Finding
			Diagnostics []Diagnostic
		}{res.Rules, res.Findings, res.Diagnostics}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		checkGolden(t, "scan-findings.json", append(golden, '\n'))
	})

	// A project suite replaces the built-in one of its name, unless project
	// rules are off; then the fixtures are scanned like any other file.
	t.Run("project suite", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{ProjectSuitesDir + "/code-scanning.yaml": "- description: The project's rules\n- rules: project\n"}
		for name, data := range scanFiles {
			files[name] = data
		}
		dir := copyProject(t, files)
		res, err := e.Scan(ctx, dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Rules != 3 || len(res.Findings) == 0 {
			t.Errorf("Scan with the project's code-scanning suite ran %d rules and found %d; want the 3 project rules, and findings", res.Rules, len(res.Findings))
		}
		for _, f := range res.Findings {
			if !strings.HasPrefix(f.RuleID, "project.") {
				t.Errorf("Scan with the project's code-scanning suite found %s", f.RuleID)
			}
		}

		res, err = e.Scan(ctx, dir, &ScanOptions{NoProjectRules: true})
		if err != nil {
			t.Fatal(err)
		}
		fixture := false
		for _, f := range res.Findings {
			if strings.HasPrefix(f.RuleID, "project.") {
				t.Errorf("Scan without project rules found %s", f.RuleID)
			}
			fixture = fixture || f.Path == inFixture
		}
		if !fixture {
			t.Errorf("Scan without project rules found %+v; want a finding in %s", res.Findings, inFixture)
		}
	})
}

// Concurrent scans of copies of a project each report their own files.
func TestScanOpengrepConcurrently(t *testing.T) {
	e := requireOpengrep(t)
	t.Parallel()
	var wg sync.WaitGroup
	for i := range 8 {
		name := fmt.Sprintf("copy%d.go", i)
		dir := copyProject(t, map[string]string{name: "package main\n\nimport \"os/exec\"\n\nfunc main() { exec.Command(\"ls\") }\n"})
		wg.Go(func() {
			res, err := e.Scan(context.Background(), dir, &ScanOptions{Selection: Selection{Rules: []string{"project.go.no-exec-command"}}, Jobs: 1})
			if err != nil {
				t.Error(err)
				return
			}
			if len(res.Findings) != 1 || res.Findings[0].Path != name {
				t.Errorf("Scan of the copy with %s found %+v; want one finding there", name, res.Findings)
			}
		})
	}
	wg.Wait()
}

// Concurrent first scans with a CacheDir that is not ASCII, where opengrep's
// runtime stays where opengrep keeps it, do not crash: as on Windows, the
// first run there is serialised. HOME is new, which on Linux and macOS
// makes that runtime cold; before, 2 of 4 such scans failed with an
// *ExitError of code -1.
func TestScanOpengrepColdNotASCII(t *testing.T) {
	e := requireOpengrep(t)
	t.Parallel()
	info, err := e.Opengrep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	env := []string{"HOME=" + home}
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); name != "HOME" && name != "XDG_CACHE_HOME" {
			env = append(env, kv)
		}
	}
	cold := newEngine(t, Config{Opengrep: info.Path, AllowUnpinned: true, CacheDir: filepath.Join(t.TempDir(), "cache-é"), Env: env})
	var wg sync.WaitGroup
	for i := range 4 {
		name := fmt.Sprintf("cold%d.go", i)
		dir := copyProject(t, map[string]string{name: "package main\n\nimport \"os/exec\"\n\nfunc main() { exec.Command(\"ls\") }\n"})
		wg.Go(func() {
			res, err := cold.Scan(context.Background(), dir, &ScanOptions{Selection: Selection{Rules: []string{"project.go.no-exec-command"}}, Jobs: 1})
			if err != nil {
				t.Errorf("Scan %d: %v", i, err)
				return
			}
			if len(res.Findings) != 1 || res.Findings[0].Path != name {
				t.Errorf("Scan of the copy with %s found %+v; want one finding there", name, res.Findings)
			}
		})
	}
	wg.Wait()
	if runtime.GOOS != "windows" && info.Version != "" {
		if fi, err := os.Stat(filepath.Join(home, ".cache", "opengrep", info.Version)); err != nil || !fi.IsDir() {
			t.Errorf("opengrep's runtime in the new HOME: %v; want it unpacked there", err)
		}
	}
}

// The fixtures of testdata/project pass.
func TestTestOpengrep(t *testing.T) {
	e := requireOpengrep(t)
	t.Parallel()
	info, err := e.Opengrep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := copyProject(t, nil)
	before := treeState(t, dir)
	rep, err := e.Test(context.Background(), dir, &TestOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) == 0 || rep.Passed != len(rep.Results) || rep.Failed != nil || rep.Untested != nil {
		t.Errorf("Test = %d results, %d passed, failed %q, untested %q; want every test passed", len(rep.Results), rep.Passed, rep.Failed, rep.Untested)
	}
	for _, r := range rep.Results {
		if r.Stage != "" || !strings.HasPrefix(r.RuleID, "project.") || len(r.Command) == 0 || r.Command[0] != info.Path || r.Dir != filepath.Join(dir, filepath.FromSlash(r.Name)) {
			t.Errorf("result %+v; want a passed test of a project rule, run in its fixture", r)
		}
	}
	if treeState(t, dir) != before {
		t.Errorf("a ReadOnly Test changed the project")
	}
}
