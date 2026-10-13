package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/odipar/gogrep"
	"github.com/odipar/gogrep/internal/sarif"
)

// forward runs an opengrep command: a scan gets the selected rules (see
// withRules), and the SARIF it writes is rebranded and checked. A scan runs
// in a process group of its own: the signals a terminal sends its
// foreground group reach gogrep alone, which stops opengrep with every
// process it started, says so and exits 130. Every other command shares
// gogrep's process group and stdin, as gogrep opengrep does.
func (c *cli) forward(args []string, sel selection) int {
	args, inject := withRules(args, sel)
	opts := &gogrep.CommandOptions{}
	if inject {
		if sel.empty() {
			fmt.Fprintf(c.stderr, "gogrep: %v\n", errNoRules)
			return 2
		}
		opts.Selection = &sel.Selection
	}
	ctx, scan := context.Background(), len(args) > 0 && args[0] == "scan"
	var cmd *gogrep.Cmd
	var code int
	if scan {
		var stop context.CancelFunc
		ctx, stop = interruptContext()
		defer stop()
		cmd, code = c.command(ctx, opts, args)
	} else {
		cmd, code = c.foregroundCommand(opts, args)
	}
	if cmd != nil {
		files, toStdout := sarifTargets(cmd.Args[1:])
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = c.stdout, c.stderr
		if toStdout {
			cmd.Stdout = &out
		}
		if scan {
			cmd.Stdin = scanStdin()
		}
		code = c.runCmd(ctx, cmd, !scan)
		if ctx.Err() == nil {
			code = c.checkSARIF(code, out.Bytes(), toStdout, files)
		}
	}
	if ctx.Err() != nil {
		fmt.Fprintln(c.stderr, "gogrep: interrupted")
		return 130
	}
	return code
}

// checkSARIF rebrands the SARIF that a command which exited with code wrote,
// out to stdout if toStdout, and files, and returns gogrep's exit code. A
// command that asked for SARIF and exited 0 without it failed, as when
// opengrep's processes were killed behind its launcher's back.
func (c *cli) checkSARIF(code int, out []byte, toStdout bool, files []string) int {
	noSARIF := false
	if toStdout {
		noSARIF = sarif.Check(out) != nil
		if rebranded, err := sarif.Rebrand(out); err == nil {
			out = append(rebranded, '\n')
		}
		c.stdout.Write(out)
	}
	for _, f := range files {
		valid, err := rebrandFile(f)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(c.stderr, "gogrep: rewriting SARIF %s: %v\n", f, err)
		}
		noSARIF = noSARIF || !valid
	}
	if code == 0 && noSARIF {
		fmt.Fprintln(c.stderr, "gogrep: opengrep exited 0 but wrote no SARIF")
		return 2
	}
	return code
}

// passThrough implements `gogrep opengrep <args>`: opengrep runs with args
// verbatim, on gogrep's streams, and its exit code is gogrep's.
func (c *cli) passThrough(args []string) int {
	cmd, code := c.foregroundCommand(&gogrep.CommandOptions{}, args)
	if cmd == nil {
		return code
	}
	cmd.Stdout, cmd.Stderr = c.stdout, c.stderr
	return c.runCmd(context.Background(), cmd, true)
}

// foregroundCommand prepares opengrep to run args in gogrep's process group,
// as command does. The first run's preparation of opengrep's runtime takes
// some seconds in a process group of its own, which a terminal's Ctrl-C
// does not reach, so gogrep catches its interrupts meanwhile: on one, the
// preparation is stopped and cleans up, and gogrep says so and returns a
// nil Cmd and 130.
func (c *cli) foregroundCommand(opts *gogrep.CommandOptions, args []string) (*gogrep.Cmd, int) {
	opts.Foreground = true
	ctx, stop := catchInterrupts()
	cmd, code := c.command(ctx, opts, args)
	stop()
	if ctx.Err() != nil {
		fmt.Fprintln(c.stderr, "gogrep: interrupted")
		return nil, 130
	}
	return cmd, code
}

// command prepares opengrep to run args in the current directory, as
// Engine.Command does. When it cannot, command says why, unless ctx is
// done, and returns a nil Cmd and the exit code: 1 when there is no usable
// opengrep, and 2 for a selection or setup error.
func (c *cli) command(ctx context.Context, opts *gogrep.CommandOptions, args []string) (*gogrep.Cmd, int) {
	cmd, err := c.eng.Command(ctx, c.dir, opts, args...)
	if err == nil {
		return cmd, 0
	}
	if ctx.Err() == nil {
		fmt.Fprintf(c.stderr, "gogrep: %v\n", explain(err))
	}
	var integrity *gogrep.IntegrityError
	if errors.Is(err, gogrep.ErrNoOpengrep) || errors.As(err, &integrity) {
		return nil, 1
	}
	return nil, 2
}

// runCmd runs cmd and returns opengrep's exit code, or 1 when it cannot run.
// A foreground cmd reads gogrep's stdin and shares gogrep's process group, so
// a terminal's Ctrl-C reaches opengrep directly; gogrep then ignores SIGINT
// and SIGTERM, to report opengrep's exit status.
func (c *cli) runCmd(ctx context.Context, cmd *gogrep.Cmd, foreground bool) int {
	if foreground {
		cmd.Stdin = os.Stdin
		signal.Ignore(syscall.SIGINT, syscall.SIGTERM)
	}
	err := cmd.Run()
	var exitErr *gogrep.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exitErr):
		return exitErr.Code
	case ctx.Err() == nil:
		fmt.Fprintf(c.stderr, "gogrep: %v\n", err)
	}
	return 1
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

// withRules reports whether gogrep gives a scan its selected rules: when the
// scan names no rules itself (no --config, -e/--pattern or $SEMGREP_RULES),
// when it uses --config bundled, or when --suite or --rule is given. It
// returns args without --config bundled. The selection then goes to
// opengrep as one generated config with stable rule ids, the scan makes no
// version check, whatever $OPENGREP_ENABLE_VERSION_CHECK says, and it skips
// the project's rule test fixtures: a project .semgrepignore replaces
// opengrep's default exclusion of test/ directories.
func withRules(args []string, sel selection) ([]string, bool) {
	if len(args) == 0 || args[0] != "scan" {
		return args, false
	}
	var out []string
	explicit, useBundled := os.Getenv("SEMGREP_RULES") != "", sel.explicit
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c" || a == "-f" || a == "--config":
			explicit = true
			if i+1 < len(args) && args[i+1] == bundledConfig {
				useBundled = true
				i++
				continue
			}
		case a == "--config="+bundledConfig:
			explicit, useBundled = true, true
			continue
		case strings.HasPrefix(a, "--config=") || a == "-e" || a == "--pattern" || strings.HasPrefix(a, "--pattern="):
			explicit = true
		}
		out = append(out, a)
	}
	if explicit && !useBundled {
		return args, false
	}
	return out, true
}
