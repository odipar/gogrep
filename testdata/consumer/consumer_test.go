package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/odipar/gogrep"
)

// TestMain runs repogrep itself when REPOGREP_TEST_MAIN is 1, so that
// TestScan can run it as a program.
func TestMain(m *testing.M) {
	if os.Getenv("REPOGREP_TEST_MAIN") == "1" {
		main()
	}
	os.Exit(m.Run())
}

// The rule sets travel with the module: listing them needs no opengrep.
func TestRulesAndSuites(t *testing.T) {
	eng, err := gogrep.New(gogrep.Config{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	rules, err := eng.Rules("", &gogrep.RulesOptions{Selection: gogrep.Selection{Suites: []string{"all"}}})
	if err != nil || len(rules) != 2121 {
		t.Errorf("Rules of the suite all = %d rules, %v; want 2121", len(rules), err)
	}
	suites, err := eng.Suites("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if i := slices.IndexFunc(suites, func(s gogrep.Suite) bool { return s.Name == gogrep.DefaultSuite }); i < 0 || !suites[i].Default || suites[i].Rules <= 0 {
		t.Errorf("Suites = %+v; want %s, the default, selecting rules", suites, gogrep.DefaultSuite)
	}
}

// httpRule is the rule that the sample's http.Get matches.
const httpRule = "opengrep-rules.problem-based-packs.insecure-transport.go-stdlib.http-request"

const sample = `package main

import "net/http"

func main() {
	http.Get("http://example.com/")
	http.Get("http://example.com/") // nosemgrep
}
`

// InstallOpengrep installs the release asset in $GOGREP_TEST_ASSET, or with
// GOGREP_TEST_DOWNLOAD=1 downloads the one for the platform it detects, and
// then a Scan, repogrep and PruneCache work with it. $GOGREP_TEST_SHA256,
// if set, is the SHA-256 the installed opengrep must have.
func TestScan(t *testing.T) {
	asset := os.Getenv("GOGREP_TEST_ASSET")
	if asset == "" && os.Getenv("GOGREP_TEST_DOWNLOAD") != "1" {
		t.Skip("set GOGREP_TEST_ASSET to a release asset of the pinned opengrep, or GOGREP_TEST_DOWNLOAD=1")
	}
	// The default cache, which repogrep uses too, in a directory of its own.
	root := t.TempDir()
	for _, name := range []string{"HOME", "XDG_CACHE_HOME", "LOCALAPPDATA"} {
		t.Setenv(name, root)
	}
	ctx := context.Background()
	eng, err := gogrep.New(gogrep.Config{})
	if err != nil {
		t.Fatal(err)
	}
	opts := &gogrep.InstallOptions{}
	if asset != "" {
		if opts.From, err = filepath.Abs(asset); err != nil {
			t.Fatal(err)
		}
	}
	info, err := eng.InstallOpengrep(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Pinned || info.Source != "cache" {
		t.Errorf("InstallOpengrep = %+v; want the pinned opengrep in the cache", info)
	}
	if want := os.Getenv("GOGREP_TEST_SHA256"); want != "" && info.SHA256 != want {
		t.Errorf("InstallOpengrep installed %s, SHA-256 %s; want %s", info.Path, info.SHA256, want)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := eng.Scan(ctx, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, f := range res.Findings {
		if f.RuleID == httpRule && f.Path == "main.go" {
			found++
			if suppressed := f.StartLine == 7; f.Suppressed != suppressed {
				t.Errorf("finding at line %d has Suppressed %v, want %v", f.StartLine, f.Suppressed, suppressed)
			}
		}
	}
	if found != 2 {
		t.Errorf("Scan found %+v; want %s on lines 6 and 7 of main.go", res.Findings, httpRule)
	}

	// repogrep, the worked example, finds the live match: exit status 1.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, dir)
	cmd.Env = append(os.Environ(), "REPOGREP_TEST_MAIN=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	var exitErr *exec.ExitError
	if err := cmd.Run(); !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Errorf("repogrep %s = %v; want exit status 1\n%s", dir, err, stderr.Bytes())
	}
	live := 0
	for sc := bufio.NewScanner(&stdout); sc.Scan(); {
		var r record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("repogrep printed %q: %v", sc.Bytes(), err)
		}
		if r.Rule == httpRule && !r.Suppressed {
			live++
		}
	}
	if live != 1 {
		t.Errorf("repogrep printed %d live %s findings, want 1:\n%s", live, httpRule, stdout.Bytes())
	}

	// The current pin's executable survives pruning.
	if err := eng.PruneCache(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(info.Path); err != nil {
		t.Errorf("PruneCache removed the current opengrep: %v", err)
	}
}
