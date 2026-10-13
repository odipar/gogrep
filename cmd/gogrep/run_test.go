package gogrep

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/odipar/gogrep/internal/fakeopengrep"
)

// TestMain lets the test binary stand in for opengrep: run as $OPENGREP_BIN
// with GOGREP_TEST_FAKE_OPENGREP=1, it is fakeopengrep.Main. Run with
// GOGREP_TEST_SIGPROBE=1, it prints whether it started with SIGINT ignored.
func TestMain(m *testing.M) {
	if os.Getenv("GOGREP_TEST_SIGPROBE") == "1" {
		fmt.Println(signal.Ignored(os.Interrupt))
		os.Exit(0)
	}
	if os.Getenv("GOGREP_TEST_FAKE_OPENGREP") == "1" {
		os.Exit(fakeopengrep.Main(os.Args[1:]))
	}
	pins, err := os.ReadFile(filepath.Join(repoDir, "opengrep.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	testAssets = Assets{
		Rules:  os.DirFS(filepath.Join(repoDir, "rules")),
		Suites: os.DirFS(filepath.Join(repoDir, "suites")),
		Pins:   pins,
	}
	os.Exit(m.Run())
}

// testAssets are the files main.go embeds, read from the repository.
var testAssets Assets

// newTestCLI returns the cli that run would use, which discards its output.
func newTestCLI(t *testing.T) *cli {
	t.Helper()
	c, err := newCLI(testAssets, io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// useFakeOpengrep makes gogrep run fakeopengrep.Main as opengrep, exiting with
// code, with a cache of its own, which keeps the runtime prepared for it.
func useFakeOpengrep(t *testing.T, code int) {
	t.Helper()
	isolateCache(t)
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
	code = run(args, testAssets, &out, &errb)
	return code, out.String(), errb.String()
}

// sarifRun decodes the single run of the SARIF log the fake opengrep printed.
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
		if driver != "gogrep" {
			t.Errorf("SARIF driver = %q, want gogrep", driver)
		}
		if len(args) > 2 && filepath.IsAbs(args[2]) {
			args[2] = "<abs config>"
		}
		want := []string{"scan", "--config", "<abs config>", "--no-rewrite-rule-ids", "--disable-version-check", "--exclude=opengrep/gogrep/rules/test", "--sarif", "."}
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

// gogrep rewrites the SARIF files opengrep writes for owner only, and a
// command that asked for SARIF and exited 0 without it fails.
func TestRunSARIFChecks(t *testing.T) {
	t.Chdir(t.TempDir())

	t.Run("files rebranded, owner only", func(t *testing.T) {
		useFakeOpengrep(t, 0)
		code, stdout, stderr := runGogrep("scan", "--config", "r.yaml", "--sarif", "-o", "out.sarif", "--sarif-output=more.sarif", ".")
		if code != 0 || stdout != "" || stderr != "fake stderr\n" {
			t.Errorf("gogrep scan = %d, %q, %q; want 0, no stdout, %q", code, stdout, stderr, "fake stderr\n")
		}
		for _, f := range []string{"out.sarif", "more.sarif"} {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if driver, _ := sarifRun(t, string(data)); driver != "gogrep" {
				t.Errorf("%s: SARIF driver = %q, want gogrep", f, driver)
			}
			if fi, err := os.Stat(f); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
				t.Errorf("%s has mode %v, %v; want 0600", f, fi.Mode().Perm(), err)
			}
		}
	})

	const noSARIF = "gogrep: opengrep exited 0 but wrote no SARIF\n"
	for _, tt := range []struct {
		args   []string
		exit   int
		code   int
		stderr string
	}{
		{[]string{"scan", "--config", "r.yaml", "--sarif", "."}, 0, 2, "fake stderr\n" + noSARIF},
		{[]string{"scan", "--config", "r.yaml", "--sarif", "-o", "missing.sarif", "."}, 0, 2, "fake stderr\n" + noSARIF},
		{[]string{"ci", "--sarif-output", "missing.sarif"}, 0, 2, "fake stderr\n" + noSARIF},
		{[]string{"scan", "--config", "r.yaml", "--sarif", "."}, 3, 3, "fake stderr\n"},
		{[]string{"scan", "--config", "r.yaml", "--sarif-output=https://example.com/sarif", "."}, 0, 0, "fake stderr\n"},
		{[]string{"scan", "--config", "r.yaml", "."}, 0, 0, "fake stderr\n"},
	} {
		t.Run(fmt.Sprintf("no SARIF, exit %d, %s", tt.exit, strings.Join(tt.args, " ")), func(t *testing.T) {
			useFakeOpengrep(t, tt.exit)
			t.Setenv("GOGREP_TEST_FAKE_NO_SARIF", "1")
			if code, _, stderr := runGogrep(tt.args...); code != tt.code || stderr != tt.stderr {
				t.Errorf("gogrep %q = %d, %q; want %d, %q", tt.args, code, stderr, tt.code, tt.stderr)
			}
		})
	}

	t.Run("not SARIF", func(t *testing.T) {
		useFakeOpengrep(t, 0)
		if err := os.WriteFile("bad.sarif", []byte(`{"version": "2.0.0", "runs": []}`), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("GOGREP_TEST_FAKE_NO_SARIF", "1")
		code, _, stderr := runGogrep("scan", "--config", "r.yaml", "--sarif-output", "bad.sarif", ".")
		if code != 2 || stderr != "fake stderr\n"+noSARIF {
			t.Errorf("gogrep scan = %d, %q; want 2, %q", code, stderr, "fake stderr\n"+noSARIF)
		}
	})
}

// A scan's opengrep, which runs in a background process group, reads
// gogrep's stdin unless that is a terminal or another character device;
// every other command reads gogrep's stdin.
func TestRunStdin(t *testing.T) {
	useFakeOpengrep(t, 0)
	t.Setenv("GOGREP_TEST_FAKE_STDIN", "1")
	dir := t.TempDir()
	t.Chdir(dir)
	file := filepath.Join(dir, "stdin")
	if err := os.WriteFile(file, []byte("file contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		stdin string
		args  []string
		want  string // what opengrep reads
	}{
		{file, []string{"scan", "--config", "r.yaml", "."}, "file"},
		{file, []string{"opengrep", "scan", "."}, "file"},
	}
	if runtime.GOOS != "windows" {
		// A character device that, unlike the null device, has data.
		tests = append(tests, []struct {
			stdin string
			args  []string
			want  string
		}{
			{"/dev/zero", []string{"scan", "--config", "r.yaml", "."}, ""},
			{"/dev/zero", []string{"opengrep", "scan", "."}, "\x00\x00\x00\x00"},
			{"/dev/zero", []string{"--version"}, "\x00\x00\x00\x00"},
		}...)
	}
	saved := os.Stdin
	t.Cleanup(func() { os.Stdin = saved })
	for _, tt := range tests {
		f, err := os.Open(tt.stdin)
		if err != nil {
			t.Fatal(err)
		}
		os.Stdin = f
		code, _, stderr := runGogrep(tt.args...)
		f.Close()
		if want := fmt.Sprintf("stdin %q\nfake stderr\n", tt.want); code != 0 || stderr != want {
			t.Errorf("gogrep %q < %s = %d, %q; want 0, %q", tt.args, tt.stdin, code, stderr, want)
		}
	}
}

// Runs share no state: Main once handed its files to run in a package
// variable.
func TestRunConcurrently(t *testing.T) {
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			if code, _, stderr := runGogrep("rules", "--suite", "all"); code != 0 || stderr != "2121 rules\n" {
				t.Errorf("gogrep rules --suite all = %d, %q; want 0, %q", code, stderr, "2121 rules\n")
			}
		})
	}
	wg.Wait()
}

// Every opengrep that gogrep starts gets the runtime gogrep prepared for it
// (except on Windows, which cannot move it); gogrep test runs opengrep
// without the SEMGREP_* and OPENGREP_* variables, and with a log of its own.
func TestRunEnv(t *testing.T) {
	useFakeOpengrep(t, 0)
	testProject(t, brokenFiles)
	t.Setenv("SEMGREP_RULES", "r.yaml")
	t.Setenv("OPENGREP_X", "x")
	t.Setenv("GOGREP_TEST_FAKE_ENV", "SEMGREP_RULES,OPENGREP_X,SEMGREP_LOG_FILE,XDG_CACHE_HOME")
	exe, err := os.Executable()
	sum := sha256.New()
	if err == nil {
		var data []byte
		data, err = os.ReadFile(exe)
		sum.Write(data)
	}
	cache, err2 := os.UserCacheDir()
	if err != nil || err2 != nil {
		t.Fatal(err, err2)
	}
	cache = filepath.Join(cache, "gogrep")
	xdg := filepath.Join(cache, "runtime-"+hex.EncodeToString(sum.Sum(nil))[:16])
	if runtime.GOOS == "windows" {
		xdg = ""
	}

	_, _, stderr := runGogrep("scan", "--config", "r.yaml", ".")
	if want := "SEMGREP_RULES=r.yaml\nOPENGREP_X=x\nSEMGREP_LOG_FILE=\nXDG_CACHE_HOME=" + xdg + "\nfake stderr\n"; stderr != want {
		t.Errorf("gogrep scan ran opengrep with\n%s\nwant\n%s", stderr, want)
	}

	_, stdout, _ := runGogrep("test", "--show-opengrep-output", testRoot+"/go/exec-command")
	_, report, _ := strings.Cut(stdout, "\n  > ")
	report = "> " + report
	logs := filepath.Join(cache, "logs") + string(filepath.Separator) + "opengrep-"
	if want := "> SEMGREP_RULES=\n  > OPENGREP_X=\n  > SEMGREP_LOG_FILE=" + logs; !strings.HasPrefix(report, want) ||
		!strings.Contains(report, ".log\n  > XDG_CACHE_HOME="+xdg+"\n") {
		t.Errorf("gogrep test ran opengrep with\n%s\nwant SEMGREP_RULES and OPENGREP_X unset, a log in %s, and XDG_CACHE_HOME=%s", report, logs, xdg)
	}
	if entries, err := os.ReadDir(filepath.Join(cache, "logs")); err != nil || len(entries) != 0 {
		t.Errorf("gogrep test left logs %v, %v", entries, err)
	}
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
