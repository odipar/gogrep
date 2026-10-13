// Package gogrep implements the gogrep command, a wrapper around the
// opengrep binary; the main package at the module root only calls Main.
package gogrep

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/odipar/gogrep/internal/bundle"
	"github.com/odipar/gogrep/internal/opengrep"
	"github.com/odipar/gogrep/internal/pin"
)

// Assets are the files gogrep embeds from the module root, which go:embed
// cannot reach from this package.
type Assets struct {
	Rules  fs.FS  // the repo's rules/ directory, the "gogrep" rule set
	Suites fs.FS  // the built-in suites, as <name>.yaml files
	Pins   []byte // opengrep.json
}

// assets are the embedded files Main was given.
var assets Assets

// Main runs gogrep with args (without the program name) on the process's
// stdio and returns its exit code.
func Main(args []string, a Assets) int {
	assets = a
	return run(args, os.Stdout, os.Stderr)
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
	if bin := bundle.Binary(); len(bin) > 0 {
		p, err := extractOpengrep(bin)
		if err != nil {
			return "", fmt.Errorf("extracting embedded opengrep: %w", err)
		}
		return p, nil
	}
	return exec.LookPath("opengrep")
}

// extractOpengrep returns the path of bin, the embedded opengrep, in the user
// cache directory, writing it there unless a verified copy is there already.
// bin must be an opengrep that opengrep.json pins for this platform.
func extractOpengrep(bin []byte) (string, error) {
	pins, err := pin.Parse(assets.Pins)
	if err != nil {
		return "", fmt.Errorf("opengrep.json: %w", err)
	}
	var sums []string
	for _, key := range pin.Keys(runtime.GOOS, runtime.GOARCH, false) {
		if a, ok := pins.Assets[key]; ok {
			sums = append(sums, a.SHA256)
		}
	}
	if len(sums) == 0 {
		return "", fmt.Errorf("opengrep.json pins no opengrep for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	path, _, err := opengrep.Extract(filepath.Join(cache, "gogrep"), bin, sums...)
	return path, err
}
