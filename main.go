// Command gogrep is a thin wrapper around the opengrep binary.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/odipar/gogrep/internal/bundle"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run runs gogrep with args and returns its exit code. `gogrep opengrep
// <args>` runs opengrep with args verbatim, gogrep's own flags included.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "opengrep" {
		return execOpengrep(args[1:], stdout, stderr)
	}
	args, sel, err := gogrepFlags(args)
	if err != nil {
		fmt.Fprintf(stderr, "gogrep: %v\n", err)
		return 2
	}
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "test":
		return runTest(args[1:], sel, stdout, stderr)
	case "rules":
		err = listRules(stdout, stderr, sel)
	case "suites":
		err = listSuites(stdout)
	default:
		return forward(args, sel, stdout, stderr)
	}
	if err != nil {
		fmt.Fprintf(stderr, "gogrep: %v\n", err)
		return 2
	}
	return 0
}

// forward runs an opengrep command: a scan gets the selected rules (see
// withRules), and the SARIF it writes is rebranded.
func forward(args []string, sel selection, stdout, stderr io.Writer) int {
	args, err := withRules(args, sel)
	if err != nil {
		fmt.Fprintf(stderr, "gogrep: %v\n", err)
		return 2
	}
	sarifFiles, sarifStdout := sarifTargets(args)
	out := stdout
	var sarif bytes.Buffer
	if sarifStdout {
		out = &sarif
	}
	code := execOpengrep(args, out, stderr)

	if sarifStdout {
		data := sarif.Bytes()
		if rebranded, err := rebrand(data); err == nil {
			data = append(rebranded, '\n')
		}
		stdout.Write(data)
	}
	for _, f := range sarifFiles {
		if err := rebrandFile(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "gogrep: rewriting SARIF %s: %v\n", f, err)
		}
	}
	return code
}

// execOpengrep runs opengrep with args, gogrep's stdin and the given stdout
// and stderr, and returns its exit code.
func execOpengrep(args []string, stdout, stderr io.Writer) int {
	bin, err := opengrepBin()
	if err != nil {
		fmt.Fprintf(stderr, "gogrep: %v\n", err)
		return 1
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, stderr
	cmd.Env = utf8Env(os.Environ())

	// The child shares our process group and receives Ctrl-C directly;
	// keep the wrapper alive so it can report the child's exit status.
	signal.Ignore(syscall.SIGINT, syscall.SIGTERM)

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			fmt.Fprintf(stderr, "gogrep: %v\n", err)
			return 1
		}
		return exitErr.ExitCode()
	}
	return 0
}

// utf8Env makes opengrep read rule files as UTF-8: without a UTF-8 locale its
// embedded Python falls back to ASCII and crashes on non-ASCII rules.
func utf8Env(env []string) []string {
	if runtime.GOOS == "windows" {
		return append(env, "PYTHONUTF8=1")
	}
	locale := ""
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := os.Getenv(name); v != "" {
			locale = v
			break
		}
	}
	if l := strings.ToLower(locale); strings.Contains(l, "utf-8") || strings.Contains(l, "utf8") {
		return env
	}
	return append(env, "LC_ALL=C.UTF-8")
}

// opengrepBin resolves the wrapped binary: $OPENGREP_BIN, then the binary
// embedded in bundled builds, then opengrep on $PATH.
func opengrepBin() (string, error) {
	if p := os.Getenv("OPENGREP_BIN"); p != "" {
		return p, nil
	}
	if p, ok, err := bundle.Path(); ok {
		if err != nil {
			return "", fmt.Errorf("extracting embedded opengrep: %w", err)
		}
		return p, nil
	}
	return exec.LookPath("opengrep")
}
