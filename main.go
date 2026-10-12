// Command gogrep is a thin wrapper around the opengrep binary.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/odipar/gogrep/internal/bundle"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	sarifFiles, sarifStdout := sarifTargets(args)

	bin, err := opengrepBin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gogrep: %v\n", err)
		return 1
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	var stdout bytes.Buffer
	if sarifStdout {
		cmd.Stdout = &stdout
	}

	// The child shares our process group and receives Ctrl-C directly;
	// keep the wrapper alive so it can report the child's exit status.
	signal.Ignore(syscall.SIGINT, syscall.SIGTERM)

	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			fmt.Fprintf(os.Stderr, "gogrep: %v\n", err)
			return 1
		}
		code = exitErr.ExitCode()
	}

	if sarifStdout {
		out := stdout.Bytes()
		if rebranded, err := rebrand(out); err == nil {
			out = append(rebranded, '\n')
		}
		os.Stdout.Write(out)
	}
	for _, f := range sarifFiles {
		if err := rebrandFile(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "gogrep: rewriting SARIF %s: %v\n", f, err)
		}
	}
	return code
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
