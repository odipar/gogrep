// Package gogrep implements the gogrep command, a wrapper around the
// opengrep binary; the main package at the module root only calls Main.
package gogrep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/odipar/gogrep/internal/bundle"
	"github.com/odipar/gogrep/internal/engine"
	"github.com/odipar/gogrep/internal/opengrep"
	"github.com/odipar/gogrep/internal/sarif"
)

// Assets are the files gogrep embeds from the module root, which go:embed
// cannot reach from this package.
type Assets = engine.Files

// Main runs gogrep with args (without the program name) on the process's
// stdio and returns its exit code.
func Main(args []string, a Assets) int {
	return run(args, a, os.Stdout, os.Stderr)
}

// A cli is one run of gogrep, in the current directory.
type cli struct {
	stdout, stderr io.Writer
	dir            string // the current directory, where gogrep's project is
	eng            *engine.Engine
}

// newCLI returns a cli that writes to stdout and stderr, for the current
// directory.
func newCLI(a Assets, stdout, stderr io.Writer) (*cli, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	bin, err := opengrepBinEnv()
	if err != nil {
		return nil, err
	}
	eng, err := engine.New(engine.Config{
		Opengrep:         bin,
		EmbeddedOpengrep: bundle.Binary(),
		AllowUnpinned:    true, // gogrep has always run any opengrep on $PATH
	}, a)
	if err != nil {
		return nil, err
	}
	return &cli{stdout: stdout, stderr: stderr, dir: dir, eng: eng}, nil
}

// run runs gogrep with args and returns its exit code. `gogrep opengrep
// <args>` runs opengrep with args verbatim, gogrep's own flags included.
func run(args []string, a Assets, stdout, stderr io.Writer) int {
	c, err := newCLI(a, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "gogrep: %v\n", err)
		return 2
	}
	if len(args) > 0 && args[0] == "opengrep" {
		oc := &opengrep.Cmd{Args: args[1:], Stdout: stdout, Stderr: stderr, Foreground: true}
		return c.execOpengrep(context.Background(), oc)
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
		return c.runTest(args[1:], sel)
	case "rules":
		err = c.listRules(sel)
	case "suites":
		err = c.listSuites()
	default:
		return c.forward(args, sel)
	}
	if err != nil {
		fmt.Fprintf(stderr, "gogrep: %v\n", explain(err))
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
func (c *cli) forward(args []string, sel selection) int {
	stdout, stderr := c.stdout, c.stderr
	args, err := c.withRules(args, sel)
	if err != nil {
		fmt.Fprintf(stderr, "gogrep: %v\n", explain(err))
		return 2
	}
	sarifFiles, sarifStdout := sarifTargets(args)
	oc := &opengrep.Cmd{Args: args, Stdout: stdout, Stderr: stderr}
	var out bytes.Buffer
	if sarifStdout {
		oc.Stdout = &out
	}
	var code int
	if len(args) > 0 && args[0] == "scan" {
		ctx, stop := interruptContext()
		defer stop()
		oc.Stdin = scanStdin()
		if code = c.execOpengrep(ctx, oc); ctx.Err() != nil {
			fmt.Fprintln(stderr, "gogrep: interrupted")
			return 130
		}
	} else {
		oc.Foreground = true
		code = c.execOpengrep(context.Background(), oc)
	}

	// A command that asked for SARIF and exited 0 without it failed, as
	// when opengrep's processes were killed behind its launcher's back.
	noSARIF := false
	if sarifStdout {
		data := out.Bytes()
		noSARIF = sarif.Check(data) != nil
		if rebranded, err := sarif.Rebrand(data); err == nil {
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

// execOpengrep runs oc with the opengrep that gogrep runs, in its
// environment, and returns opengrep's exit code, or 1 when opengrep cannot
// run. A Foreground oc reads gogrep's stdin and shares gogrep's process
// group, so a terminal's Ctrl-C reaches opengrep directly; gogrep then
// ignores SIGINT and SIGTERM, to report opengrep's exit status.
func (c *cli) execOpengrep(ctx context.Context, oc *opengrep.Cmd) int {
	info, env, err := c.eng.OpengrepEnv(ctx)
	if err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(c.stderr, "gogrep: %v\n", err)
		}
		return 1
	}
	oc.Path, oc.Env = info.Path, env
	if oc.Foreground {
		oc.Stdin = os.Stdin
		signal.Ignore(syscall.SIGINT, syscall.SIGTERM)
	}
	err = oc.Run(ctx)
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exitErr):
		return exitErr.ExitCode()
	case ctx.Err() == nil:
		fmt.Fprintf(c.stderr, "gogrep: %v\n", err)
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

// opengrepBinEnv returns $OPENGREP_BIN, the opengrep that gogrep runs if
// set, made absolute when it is a path, as opengrep runs elsewhere than in
// the current directory: a name without a path separator is looked up in
// $PATH.
func opengrepBinEnv() (string, error) {
	p := os.Getenv("OPENGREP_BIN")
	if p == "" || !strings.ContainsAny(p, "/"+string(filepath.Separator)) && filepath.VolumeName(p) == "" {
		return p, nil
	}
	return filepath.Abs(p)
}
