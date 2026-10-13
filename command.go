package gogrep

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"sync"

	"github.com/odipar/gogrep/internal/opengrep"
)

// CommandOptions configure Engine.Command; nil means the zero
// CommandOptions, which run args verbatim in a process group of their own.
//
// Experimental: Command exists for the gogrep command's pass-through of
// every opengrep flag. It may change in any minor release; use Scan.
type CommandOptions struct {
	// Selection, if not nil, gives a "scan" command gogrep's rules: right
	// after "scan", Command inserts
	//
	//	--config <selection file> --no-rewrite-rule-ids --disable-version-check --exclude=opengrep/gogrep/rules/test
	//
	// (the --exclude only without NoProjectRules). The zero Selection
	// selects DefaultSuite. It is an error when args[0] is not "scan". With
	// a nil Selection, args go to opengrep verbatim; gogrep consults none of
	// opengrep's flags or environment variables, such as SEMGREP_RULES, to
	// decide.
	Selection *Selection

	// NoProjectRules is as in ScanOptions.
	NoProjectRules bool

	// Foreground keeps opengrep in the caller's process group, so a
	// terminal's Ctrl-C reaches it directly, and makes a done ctx kill only
	// the process Run started. Otherwise opengrep leads a process group of
	// its own (on Windows, its process tree), which a done ctx stops whole:
	// with SIGINT, as Ctrl-C would, and SIGKILL a second later (on Windows,
	// at once). Such a group is stopped if it reads the terminal, so do not
	// give it a terminal as Stdin.
	Foreground bool
}

// A Cmd is an opengrep command that Command prepared. Its fields may be
// changed before Run, as with exec.Cmd. A Cmd cannot be reused, and is not
// safe for concurrent use, except for Signal.
type Cmd struct {
	Path string   // the opengrep executable, absolute
	Args []string // the command line, starting with Path, gogrep's own arguments included
	Dir  string   // the directory opengrep runs in
	Env  []string // opengrep's environment

	// Stdin, Stdout and Stderr are opengrep's standard streams, as in
	// exec.Cmd; nil means the null device.
	Stdin          io.Reader
	Stdout, Stderr io.Writer

	ctx        context.Context
	foreground bool
	log        *slog.Logger
	ran        bool

	mu   sync.Mutex
	proc *os.Process // the running opengrep, for Signal
}

// Command prepares opengrep to run with args (without the executable) in
// dir, an absolute directory. It finds and prepares opengrep as Opengrep
// does and, with a Selection, writes the selection's rule file, so it fails
// as they do. ctx bounds that and the run. Preparing opengrep's runtime runs
// in a process group of its own also with Foreground, so a host whose
// Ctrl-C should stop it cancels ctx, or first calls Opengrep under a ctx
// that Ctrl-C cancels.
func (e *Engine) Command(ctx context.Context, dir string, opts *CommandOptions, args ...string) (*Cmd, error) {
	if opts == nil {
		opts = &CommandOptions{}
	}
	if err := checkDir(dir, false); err != nil {
		return nil, err
	}
	args = slices.Clone(args)
	if opts.Selection != nil {
		if len(args) == 0 || args[0] != "scan" {
			return nil, errors.New("a command with a Selection must be a scan")
		}
		// Right after "scan": after a "--" they would be targets.
		own, _, err := e.ruleArgs(dir, *opts.Selection, opts.NoProjectRules)
		if err != nil {
			return nil, err
		}
		args = slices.Concat(args[:1], own, args[1:])
	}
	info, xdg, err := e.opengrep(ctx)
	if err != nil {
		return nil, err
	}
	return &Cmd{
		Path:       info.Path,
		Args:       append([]string{info.Path}, args...),
		Dir:        dir,
		Env:        slices.Clone(withRuntime(opengrep.UTF8Env(e.env), xdg)), // the caller's to change, never the Engine's
		ctx:        ctx,
		foreground: opts.Foreground,
		log:        e.log,
	}, nil
}

// Run starts the command and waits for it. It returns nil when opengrep
// exits 0; an *ExitError, with nil Stderr and Result, when it exits
// non-zero; an error naming Dir when opengrep cannot run there, as it is
// missing or not a directory; an error wrapping ErrNoOpengrep when it cannot
// start otherwise; and an error wrapping ctx.Err() when ctx ended it. Run
// reads nothing opengrep writes: interpreting its output, SARIF included, is
// up to the caller.
func (c *Cmd) Run() error {
	if c.ran {
		return errors.New("Cmd.Run called twice")
	}
	c.ran = true
	var args []string
	if len(c.Args) > 0 {
		args = c.Args[1:]
	}
	oc := &opengrep.Cmd{Path: c.Path, Args: args, Dir: c.Dir, Env: c.Env, Stdin: c.Stdin, Stdout: c.Stdout, Stderr: c.Stderr, Foreground: c.foreground,
		Started: func(p *os.Process) {
			c.mu.Lock()
			c.proc = p
			c.mu.Unlock()
		}}
	c.log.Info("running opengrep", "dir", c.Dir, "args", c.Args)
	err := oc.Run(c.ctx)
	var exitErr *exec.ExitError
	var startErr *opengrep.StartError
	switch {
	case err == nil || c.ctx.Err() != nil:
		return err
	case errors.As(err, &exitErr):
		return &ExitError{Code: exitErr.ExitCode()}
	case errors.As(err, &startErr):
		return startError(c.Dir, err)
	}
	return err
}

// Signal sends sig to the opengrep that Run started, while Run runs it: to
// opengrep's whole process group, or with Foreground to opengrep alone. On
// Windows, only os.Kill is supported, and it reaches opengrep alone. Signal
// may be called from another goroutine while Run runs; it returns an error
// when no opengrep runs. The gogrep command uses it to stop and continue a
// scan with Ctrl-Z.
func (c *Cmd) Signal(sig os.Signal) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.proc == nil:
		return errors.New("opengrep is not running")
	case c.foreground:
		return c.proc.Signal(sig)
	}
	return opengrep.SignalGroup(c.proc, sig)
}

// startError returns the error for an opengrep that could not start in dir
// ("" for the current directory): os/exec reports a directory it cannot
// enter as a failure to run the executable, so that leaves the Engine without
// an opengrep only when dir is fine.
func startError(dir string, err error) error {
	if dir != "" {
		if derr := enterable(dir); derr != nil {
			return derr
		}
	}
	return &noOpengrep{err}
}
