// Command opengrep-wrapper is a thin wrapper around the opengrep binary.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

const defaultBin = "/Users/rapido/.local/bin/opengrep"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	cmd := exec.Command(opengrepBin(), args...) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	// The child shares our process group and receives Ctrl-C directly;
	// keep the wrapper alive so it can report the child's exit status.
	signal.Ignore(syscall.SIGINT, syscall.SIGTERM)

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "opengrep-wrapper: %v\n", err)
		return 1
	}
	return 0
}

// opengrepBin resolves the wrapped binary: $OPENGREP_BIN, then the default path.
func opengrepBin() string {
	if p := os.Getenv("OPENGREP_BIN"); p != "" {
		return p
	}
	return defaultBin
}
