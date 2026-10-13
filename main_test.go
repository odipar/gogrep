package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestMain lets the test binary stand in for opengrep: run as $OPENGREP_BIN
// with GOGREP_TEST_FAKE_OPENGREP=1, it is fakeOpengrep.
func TestMain(m *testing.M) {
	if os.Getenv("GOGREP_TEST_FAKE_OPENGREP") == "1" {
		os.Exit(fakeOpengrep(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeOpengrep prints its args to stdout, one per line, or with --sarif a
// SARIF log from tool "opengrep" that holds them as properties.args. It
// writes "fake stderr" to stderr and exits with $GOGREP_TEST_FAKE_EXIT. With
// $GOGREP_TEST_FAKE_WAIT set, it first creates that file and waits a minute.
func fakeOpengrep(args []string) int {
	if p := os.Getenv("GOGREP_TEST_FAKE_WAIT"); p != "" {
		os.WriteFile(p, nil, 0o600)
		time.Sleep(time.Minute)
	}
	if slices.Contains(args, "--sarif") {
		json.NewEncoder(os.Stdout).Encode(map[string]any{
			"version": "2.1.0",
			"runs": []any{map[string]any{
				"tool":       map[string]any{"driver": map[string]any{"name": "opengrep"}},
				"properties": map[string]any{"args": args},
			}},
		})
	} else {
		for _, a := range args {
			fmt.Println(a)
		}
	}
	fmt.Fprintln(os.Stderr, "fake stderr")
	code, _ := strconv.Atoi(os.Getenv("GOGREP_TEST_FAKE_EXIT"))
	return code
}

// useFakeOpengrep makes gogrep run fakeOpengrep as opengrep, exiting with code.
func useFakeOpengrep(t *testing.T, code int) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENGREP_BIN", exe)
	t.Setenv("GOGREP_TEST_FAKE_OPENGREP", "1")
	t.Setenv("GOGREP_TEST_FAKE_EXIT", strconv.Itoa(code))
}

// runGogrep calls run with args and returns its exit code and output.
func runGogrep(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// sarifRun decodes the single run of the SARIF log fakeOpengrep printed.
func sarifRun(t *testing.T, stdout string) (driver string, args []string) {
	t.Helper()
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct{ Name string }
			}
			Properties struct{ Args []string }
		}
	}
	if err := json.Unmarshal([]byte(stdout), &log); err != nil || len(log.Runs) != 1 {
		t.Fatalf("stdout is not a SARIF log with one run (%v): %q", err, stdout)
	}
	return log.Runs[0].Tool.Driver.Name, log.Runs[0].Properties.Args
}

func TestRunOpengrepPassesArgsVerbatim(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--version"},
		{"test", "--config", "./rd", "./td"},
		{"scan", "--rule", "no-exec-command", "--suite=all", "--gogrep-lang", "go", "--config", "bundled", "."},
	} {
		full := append([]string{"opengrep"}, args...)
		t.Run(strings.Join(full, " "), func(t *testing.T) {
			useFakeOpengrep(t, 0)
			code, stdout, stderr := runGogrep(full...)
			want := ""
			for _, a := range args {
				want += a + "\n"
			}
			if code != 0 || stdout != want || stderr != "fake stderr\n" {
				t.Errorf("gogrep %q = %d, %q, %q; want 0, %q, %q", full, code, stdout, stderr, want, "fake stderr\n")
			}
		})
	}
}

func TestRunOpengrepKeepsExitCodeAndSARIF(t *testing.T) {
	useFakeOpengrep(t, 3)
	code, stdout, _ := runGogrep("opengrep", "scan", "--sarif", ".")
	if code != 3 {
		t.Errorf("exit code = %d, want 3", code)
	}
	if driver, args := sarifRun(t, stdout); driver != "opengrep" || !slices.Equal(args, []string{"scan", "--sarif", "."}) {
		t.Errorf("SARIF driver, args = %q, %q; want opengrep, [scan --sarif .]", driver, args)
	}
}

func TestRunScan(t *testing.T) {
	isolateCache(t)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"opengrep/gogrep/rules/go/no-exec-command.yaml": noExecRule})
	t.Chdir(dir)
	t.Setenv("SEMGREP_RULES", "")

	t.Run("selected rules, SARIF rebranded", func(t *testing.T) {
		useFakeOpengrep(t, 1)
		code, stdout, stderr := runGogrep("scan", "--rule", "no-exec-command", "--sarif", ".")
		if code != 1 || stderr != "fake stderr\n" {
			t.Errorf("exit code, stderr = %d, %q; want 1, %q", code, stderr, "fake stderr\n")
		}
		driver, args := sarifRun(t, stdout)
		if driver != toolName {
			t.Errorf("SARIF driver = %q, want %q", driver, toolName)
		}
		if len(args) > 2 && filepath.IsAbs(args[2]) {
			args[2] = "<abs config>"
		}
		want := []string{"scan", "--config", "<abs config>", "--no-rewrite-rule-ids", "--exclude=opengrep/gogrep/rules/test", "--sarif", "."}
		if !slices.Equal(args, want) {
			t.Errorf("opengrep args = %q, want %q", args, want)
		}
	})

	t.Run("own config", func(t *testing.T) {
		useFakeOpengrep(t, 0)
		code, stdout, _ := runGogrep("scan", "--config", "my-rules/", ".")
		if want := "scan\n--config\nmy-rules/\n.\n"; code != 0 || stdout != want {
			t.Errorf("gogrep scan = %d, %q; want 0, %q", code, stdout, want)
		}
	})

	t.Run("no opengrep", func(t *testing.T) {
		t.Setenv("OPENGREP_BIN", filepath.Join(dir, "missing-opengrep"))
		if code, _, stderr := runGogrep("scan", "."); code != 1 || !strings.HasPrefix(stderr, "gogrep: ") {
			t.Errorf("gogrep scan = %d, stderr %q; want 1 and a gogrep: error", code, stderr)
		}
	})
}

func TestRunRulesAndSuites(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"opengrep/gogrep/rules/go/no-exec-command.yaml": noExecRule})
	t.Chdir(dir)

	tests := []struct {
		args   []string
		code   int
		stdout string // a substring of stdout; "" means no stdout
		stderr string
	}{
		{[]string{"rules", "--rule", "project.go.no-exec-command"}, 0, "project.go.no-exec-command  WARNING", "1 rule\n"},
		{[]string{"suites"}, 0, "code-scanning (default)", ""},
		{[]string{"rules", "--rule"}, 2, "", "gogrep: --rule needs a value\n"},
		{[]string{"rules", "--rule", "nope"}, 2, "", "gogrep: --rule nope matches no rule; list them with: gogrep rules --suite all\n"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			code, stdout, stderr := runGogrep(tt.args...)
			if code != tt.code || stderr != tt.stderr || !strings.Contains(stdout, tt.stdout) || (tt.stdout == "") != (stdout == "") {
				t.Errorf("gogrep %q = %d, %q, %q; want %d, stdout with %q, stderr %q", tt.args, code, stdout, stderr, tt.code, tt.stdout, tt.stderr)
			}
		})
	}
}
