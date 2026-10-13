// Package gogrep implements the gogrep command, a wrapper around the
// opengrep binary; the main package at the module root only calls Main.
package gogrep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"

	"github.com/odipar/gogrep/internal/bundle"
	"github.com/odipar/gogrep/internal/opengrep"
	"github.com/odipar/gogrep/internal/pin"
	"github.com/odipar/gogrep/internal/ruletest"
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
		c := &opengrep.Cmd{Args: args[1:], Stdout: stdout, Stderr: stderr, Foreground: true}
		return execOpengrep(context.Background(), c, stderr)
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
// withRules), and the SARIF it writes is rebranded and checked. A scan runs
// in a process group of its own: the signals a terminal sends its
// foreground group reach gogrep alone, which kills opengrep with every
// process it started, says so and exits 130. Every other command shares
// gogrep's process group and stdin, as gogrep opengrep does.
func forward(args []string, sel selection, stdout, stderr io.Writer) int {
	args, err := withRules(args, sel)
	if err != nil {
		fmt.Fprintf(stderr, "gogrep: %v\n", err)
		return 2
	}
	sarifFiles, sarifStdout := sarifTargets(args)
	c := &opengrep.Cmd{Args: args, Stdout: stdout, Stderr: stderr}
	var sarif bytes.Buffer
	if sarifStdout {
		c.Stdout = &sarif
	}
	var code int
	if len(args) > 0 && args[0] == "scan" {
		ctx, stop := interruptContext()
		defer stop()
		c.Stdin = scanStdin()
		if code = execOpengrep(ctx, c, stderr); ctx.Err() != nil {
			fmt.Fprintln(stderr, "gogrep: interrupted")
			return 130
		}
	} else {
		c.Foreground = true
		code = execOpengrep(context.Background(), c, stderr)
	}

	// A command that asked for SARIF and exited 0 without it failed, as
	// when opengrep's processes were killed behind its launcher's back.
	noSARIF := false
	if sarifStdout {
		data := sarif.Bytes()
		_, err := ruletest.DecodeSARIF(data)
		noSARIF = err != nil
		if rebranded, err := rebrand(data); err == nil {
			data = append(rebranded, '\n')
		}
		stdout.Write(data)
	}
	for _, f := range sarifFiles {
		valid, err := rebrandFile(f)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "gogrep: rewriting SARIF %s: %v\n", f, err)
		}
		noSARIF = noSARIF || !valid
	}
	if code == 0 && noSARIF {
		fmt.Fprintln(stderr, "gogrep: opengrep exited 0 but wrote no SARIF")
		return 2
	}
	return code
}

// execOpengrep runs c with the opengrep that gogrep runs, in its environment,
// and returns opengrep's exit code, or 1 when opengrep cannot run. A
// Foreground c reads gogrep's stdin and shares gogrep's process group, so a
// terminal's Ctrl-C reaches opengrep directly; gogrep then ignores SIGINT and
// SIGTERM, to report opengrep's exit status.
func execOpengrep(ctx context.Context, c *opengrep.Cmd, stderr io.Writer) int {
	bin, err := opengrepBin()
	if err != nil {
		fmt.Fprintf(stderr, "gogrep: %v\n", err)
		return 1
	}
	c.Path, c.Env = bin, opengrep.UTF8Env(os.Environ())
	if c.Foreground {
		c.Stdin = os.Stdin
		signal.Ignore(syscall.SIGINT, syscall.SIGTERM)
	}
	err = c.Run(ctx)
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exitErr):
		return exitErr.ExitCode()
	case ctx.Err() == nil:
		fmt.Fprintf(stderr, "gogrep: %v\n", err)
	}
	return 1
}

// interruptContext returns a context that is done once gogrep receives one
// of its interrupts. A signal gogrep was started with ignored, as nohup
// does SIGHUP, stays ignored; given no signals at all, NotifyContext would
// catch every one.
func interruptContext() (context.Context, context.CancelFunc) {
	if sigs := slices.DeleteFunc(slices.Clone(interrupts), signal.Ignored); len(sigs) > 0 {
		return signal.NotifyContext(context.Background(), sigs...)
	}
	return context.Background(), func() {}
}

// scanStdin returns the stdin of a scan's opengrep: gogrep's, unless that is
// a terminal, or another character device such as the null device. A
// background process group that reads its terminal is stopped (SIGTTIN).
func scanStdin() io.Reader {
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice == 0 {
		return os.Stdin
	}
	return nil
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
