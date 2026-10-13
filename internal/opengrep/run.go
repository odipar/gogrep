package opengrep

import (
	"context"
	"io"
	"os/exec"
	"time"
)

// waitDelay is how long Run waits, once ctx is done or the process has
// exited, for the process to exit and for its output to be read: a
// grandchild that holds a pipe open cannot keep Run from returning.
const waitDelay = time.Second

// Starting a just-written executable can fail with ETXTBSY while another
// goroutine forks (golang.org/issue/22315), so Run retries the start up to
// startRetries times, waiting firstBackoff and then twice as long each time.
const (
	startRetries = 5
	firstBackoff = 20 * time.Millisecond
)

// A Cmd is an opengrep process to run. Unlike an exec.Cmd, it kills the
// processes opengrep starts along with it, and retries a start that failed
// with ETXTBSY.
type Cmd struct {
	Path string   // the executable
	Args []string // its arguments, without the executable
	Dir  string   // the directory it runs in; "" means the current one
	Env  []string // its environment, as in exec.Cmd

	// Stdin, Stdout and Stderr are its standard streams, as in exec.Cmd;
	// nil means the null device.
	Stdin          io.Reader
	Stdout, Stderr io.Writer

	// Foreground keeps the process in the caller's process group, so that a
	// terminal's Ctrl-C reaches it, and makes a done ctx kill it alone.
	// Otherwise it leads a process group of its own, which a done ctx
	// interrupts whole, as a terminal's Ctrl-C would, and kills killGrace
	// later (on Windows, a done ctx kills its process tree): opengrep's
	// launcher does not pass a kill on to opengrep-cli and opengrep-core,
	// which would scan on.
	Foreground bool

	start func(*exec.Cmd) error // starts each attempt; nil means (*exec.Cmd).Start
}

// Run starts c and waits for it. It returns nil when the process exits 0, an
// *exec.ExitError when it exits non-zero, a *StartError when it cannot
// start, and ctx.Err() when ctx is done before Run returns: a process killed
// on Windows exits with code 1, and an interrupted opengrep may exit 0, so
// once ctx is done no exit status is trusted. When ctx is done, Run stops
// the process as Foreground describes and returns within about a second,
// once every process of its group is gone. A Cmd may be run again.
func (c *Cmd) Run(ctx context.Context) error {
	start := c.start
	if start == nil {
		start = (*exec.Cmd).Start
	}
	backoff := firstBackoff
	for retry := 0; ; retry++ {
		// An exec.Cmd cannot be started twice. Nothing has read Stdin yet:
		// Start copies it only once the process exists.
		cmd, reap := c.command(ctx)
		err := start(cmd)
		if err == nil {
			err = cmd.Wait()
			if ctx.Err() != nil {
				reap()
				return ctx.Err()
			}
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if retry == startRetries || !textBusy(err) {
			return &StartError{err}
		}
		t := time.NewTimer(backoff)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
		backoff *= 2
	}
}

// command returns an exec.Cmd that runs c under ctx, and what to call once
// it was cancelled and Wait returned (see killTree).
func (c *Cmd) command(ctx context.Context) (cmd *exec.Cmd, reap func()) {
	cmd = exec.CommandContext(ctx, c.Path, c.Args...)
	cmd.Dir, cmd.Env = c.Dir, c.Env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	cmd.WaitDelay = waitDelay
	if c.Foreground {
		return cmd, func() {}
	}
	return cmd, killTree(cmd)
}

// A StartError reports that a Cmd's process could not start.
type StartError struct{ Err error }

func (e *StartError) Error() string { return e.Err.Error() }
func (e *StartError) Unwrap() error { return e.Err }
