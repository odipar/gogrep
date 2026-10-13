package gogrep

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/odipar/gogrep/internal/opengrep"
	"github.com/odipar/gogrep/internal/sarif"
)

// stderrTail is how much of opengrep's stderr a Result and the errors of
// Scan keep: its end.
const stderrTail = 64 << 10

// ScanOptions configure Engine.Scan; nil means the zero ScanOptions, which
// scans the whole directory with DefaultSuite, project rules included.
type ScanOptions struct {
	// Selection picks the rules; its zero value selects DefaultSuite.
	Selection

	// NoProjectRules ignores what the directory keeps under opengrep/gogrep:
	// its rules do not load (the "project" set is empty), its suites
	// neither resolve nor shadow built-in ones, and its rule test fixtures
	// are scanned like any other file. Set it for repositories you do not
	// trust; see "Untrusted repositories" in the package documentation.
	NoProjectRules bool

	// Targets are the files and directories to scan, relative to the
	// directory and inside it (filepath.IsLocal). They are passed after
	// "--". Empty means ".".
	Targets []string

	// Jobs is opengrep's -j, the number of files it analyses at once. Zero
	// keeps opengrep's default of one per CPU; lower it when several scans
	// run at once.
	Jobs int

	// RuleTimeout limits each rule on each file (--timeout, rounded up to
	// whole seconds); a negative value means no limit (--timeout 0).
	// MaxMemoryMB limits the memory for analysing one file (--max-memory,
	// MiB). MaxTargetBytes skips larger files (--max-target-bytes). Zero
	// keeps opengrep's default for each; a negative Jobs, MaxMemoryMB or
	// MaxTargetBytes is an error.
	RuleTimeout    time.Duration
	MaxMemoryMB    int
	MaxTargetBytes int64

	// Stderr, if not nil, receives a live copy of opengrep's stderr, written
	// from another goroutine. Once a write to it fails, it gets no more, and
	// the scan goes on as if it were nil. Result.Stderr and the errors keep
	// the last 64 KiB of opengrep's stderr either way.
	Stderr io.Writer
}

// A Result is what one scan found.
type Result struct {
	// SARIF is opengrep's SARIF 2.1.0 log with runs[].tool.driver.name set
	// to "gogrep", encoded as `gogrep scan --sarif` prints it (sorted keys;
	// <, > and & escaped) and otherwise unchanged. Its result URIs are
	// relative to the scanned directory, and driver.rules lists the whole
	// selection.
	SARIF []byte

	// Findings are the log's results, suppressed ones included, sorted by
	// Path, StartLine, StartColumn, EndLine, EndColumn, RuleID and
	// Fingerprint.
	Findings []Finding

	// Diagnostics are the problems opengrep reported about its run and
	// survived (SARIF's toolExecutionNotifications), such as a file it could
	// not parse or a rule that timed out on a file.
	Diagnostics []Diagnostic

	Complete bool   // the log's invocations[0].executionSuccessful
	Rules    int    // the number of rules selected
	Stderr   []byte // the last 64 KiB of opengrep's stderr
}

// A Finding is one match of a rule.
type Finding struct {
	RuleID string // stable qualified id <set>.<dir>.<id>

	// Level is "error", "warning" or "note": the result's level, else its
	// rule's defaultConfiguration.level in the log, else SARIF's default
	// "warning". (opengrep 1.30.2 sets no level on results.)
	Level string

	Message string // the rule's message, metavariables filled in

	// Path is the file, a slash path relative to the scanned directory: the
	// result's URI exactly as opengrep wrote it, with a leading "./"
	// removed and, on Windows, backslashes turned into slashes. It is never
	// percent-decoded: opengrep writes "b c%41.go" raw.
	Path string

	// The match's region: 1-based lines and byte columns, as opengrep
	// reports them; EndColumn is exclusive. A result without a location
	// has an empty Path and a zero region.
	StartLine, StartColumn, EndLine, EndColumn int

	Snippet     string // the source lines of the match, as opengrep includes them
	Fingerprint string // fingerprints["matchBasedId/v1"]

	// Suppressed reports that a nosemgrep comment in the code suppresses
	// the match (SARIF suppressions of kind inSource). opengrep keeps such
	// results in its log; whether they count is the caller's choice.
	Suppressed bool
}

// A Diagnostic is something opengrep reported about its run rather than
// about the code.
type Diagnostic struct {
	Level   string // "error", "warning", "note" or "none"; SARIF's default is "warning"
	ID      string // the notification descriptor's id, such as "SemgrepError"
	Message string
}

// Scan runs the rules opts selects on dir, an absolute directory, and returns
// what opengrep found. opengrep runs in dir on "." (or opts.Targets), so
// .semgrepignore, git's file list and result paths behave exactly as
// `gogrep scan .` run there. Its stdin is the null device, it gets --sarif
// and --disable-version-check, and its environment is described under
// Config.Env. Scan writes nothing into dir.
//
// Findings are data, not errors: Scan returns a nil error whenever opengrep
// exits 0 with a valid SARIF log, whatever it found. Otherwise it returns a
// nil *Result and one of: a *SelectionError or ErrNoRules for a bad
// selection; an error wrapping ErrNoOpengrep, or an *IntegrityError, when no
// usable opengrep is found or it cannot be started; an *ExitError when
// opengrep exits non-zero; an *OutputError, which is ErrNoSARIF, when it
// exits 0 without a valid log; an error wrapping ctx.Err(); or a plain error
// for an invalid argument, such as a dir that is missing or not a directory,
// which names dir, or for a CacheDir it cannot write.
func (e *Engine) Scan(ctx context.Context, dir string, opts *ScanOptions) (*Result, error) {
	if opts == nil {
		opts = &ScanOptions{}
	}
	if err := checkDir(dir, false); err != nil {
		return nil, err
	}
	limits, err := opts.limits()
	if err != nil {
		return nil, err
	}
	targets := opts.Targets
	if len(targets) == 0 {
		targets = []string{"."}
	}
	for _, t := range targets {
		if !filepath.IsLocal(t) {
			return nil, fmt.Errorf("scan target %q is not a relative path inside the directory", t)
		}
	}
	own, n, err := e.ruleArgs(dir, opts.Selection, opts.NoProjectRules)
	if err != nil {
		return nil, err
	}
	info, xdg, err := e.opengrep(ctx)
	if err != nil {
		return nil, err
	}
	args := slices.Concat([]string{"scan"}, own, []string{"--sarif"}, limits, []string{"--"}, targets)

	var stdout bytes.Buffer
	tail := &tailWriter{max: stderrTail}
	var stderr io.Writer = tail
	if opts.Stderr != nil {
		live := &liveCopy{w: opts.Stderr}
		stderr = io.MultiWriter(tail, live)
		defer func() {
			if live.err != nil {
				e.log.Info("ScanOptions.Stderr failed, and got no more of opengrep's stderr", "err", live.err)
			}
		}()
	}
	err = e.runHermetic(ctx, info.Path, xdg, dir, args, &stdout, stderr)
	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case errors.As(err, &exitErr):
		res, _ := result(stdout.Bytes(), n, tail.buf)
		return nil, &ExitError{Code: exitErr.ExitCode(), Stderr: tail.buf, Result: res}
	case errors.As(err, new(*opengrep.StartError)):
		return nil, startError(dir, err)
	case err != nil:
		return nil, err
	}
	res, err := result(stdout.Bytes(), n, tail.buf)
	if err != nil {
		return nil, &OutputError{Err: err, Stderr: tail.buf}
	}
	return res, nil
}

// limits returns opengrep's flags for the job count and resource limits
// of opts.
func (opts *ScanOptions) limits() ([]string, error) {
	var args []string
	add := func(field, flag string, n int64) error {
		if n < 0 {
			return fmt.Errorf("ScanOptions.%s is negative (%d)", field, n)
		}
		if n > 0 {
			args = append(args, flag, strconv.FormatInt(n, 10))
		}
		return nil
	}
	if err := add("Jobs", "-j", int64(opts.Jobs)); err != nil {
		return nil, err
	}
	switch t := opts.RuleTimeout; {
	case t < 0:
		args = append(args, "--timeout", "0")
	case t > 0:
		args = append(args, "--timeout", strconv.FormatInt(int64((t+time.Second-1)/time.Second), 10))
	}
	if err := add("MaxMemoryMB", "--max-memory", int64(opts.MaxMemoryMB)); err != nil {
		return nil, err
	}
	if err := add("MaxTargetBytes", "--max-target-bytes", opts.MaxTargetBytes); err != nil {
		return nil, err
	}
	return args, nil
}

// ruleArgs returns the arguments that give a scan in dir the rules sel
// selects, right after "scan", and the number of those rules.
func (e *Engine) ruleArgs(dir string, sel Selection, noProject bool) ([]string, int, error) {
	env, err := e.loadEnv(dir, noProject)
	if err != nil {
		return nil, 0, err
	}
	selected, err := sel.resolve(env)
	if err != nil {
		return nil, 0, err
	}
	file, err := e.writeRules(selected)
	if err != nil {
		return nil, 0, fmt.Errorf("writing selected rules: %w", err)
	}
	args := []string{"--config", file, "--no-rewrite-rule-ids", "--disable-version-check"}
	if !noProject {
		args = append(args, "--exclude="+ProjectTestsDir)
	}
	return args, len(selected), nil
}

// runHermetic runs the opengrep exe with args in dir as Scan and Test run
// it: in a process group of its own, which a done ctx kills, with the null
// device as stdin, and in Config.Env without the SEMGREP_* and OPENGREP_*
// variables, with the locale fix, the runtime xdg (see withRuntime) and a
// log file of its own, which is removed afterwards.
func (e *Engine) runHermetic(ctx context.Context, exe, xdg, dir string, args []string, stdout, stderr io.Writer) error {
	if e.cacheErr != nil {
		return e.cacheErr
	}
	log, err := opengrep.LogFile(e.cacheDir)
	if err != nil {
		return err
	}
	defer os.Remove(log)
	env := append(withRuntime(opengrep.UTF8Env(opengrep.HermeticEnv(e.env)), xdg), "SEMGREP_LOG_FILE="+log)
	c := &opengrep.Cmd{Path: exe, Args: args, Dir: dir, Env: env, Stdout: stdout, Stderr: stderr}
	e.log.Info("running opengrep", "dir", dir, "args", append([]string{exe}, args...))
	return c.Run(ctx)
}

// result returns the Result of a scan of n rules whose stdout was out and
// whose stderr ended with stderr, or why out is not a SARIF 2.1.0 log of one
// run.
func result(out []byte, n int, stderr []byte) (*Result, error) {
	log, err := sarif.Decode(out)
	if err != nil {
		return nil, err
	}
	rebranded, err := sarif.Rebrand(out)
	if err != nil {
		return nil, fmt.Errorf("output is not a SARIF log: %w", err)
	}
	res := &Result{SARIF: append(rebranded, '\n'), Complete: log.Complete(), Rules: n, Stderr: stderr}
	for _, f := range log.Findings() {
		res.Findings = append(res.Findings, Finding(f))
	}
	for _, d := range log.Diagnostics() {
		res.Diagnostics = append(res.Diagnostics, Diagnostic(d))
	}
	return res, nil
}

// A liveCopy passes what is written to it on to w until a write to w fails,
// and never fails itself: os/exec would stop copying opengrep's stderr, and
// opengrep would fail on the broken pipe or Wait return w's error.
type liveCopy struct {
	w   io.Writer
	err error // why w gets no more
}

func (l *liveCopy) Write(p []byte) (int, error) {
	if l.err == nil {
		if n, err := l.w.Write(p); err != nil || n != len(p) {
			l.err = cmp.Or(err, io.ErrShortWrite)
		}
	}
	return len(p), nil
}

// A tailWriter keeps the last max bytes written to it, in buf.
type tailWriter struct {
	max int
	buf []byte
}

func (w *tailWriter) Write(p []byte) (int, error) {
	if len(p) >= w.max {
		w.buf = append(w.buf[:0], p[len(p)-w.max:]...)
		return len(p), nil
	}
	if over := len(w.buf) + len(p) - w.max; over > 0 {
		w.buf = append(w.buf[:0], w.buf[over:]...)
	}
	w.buf = append(w.buf, p...)
	return len(p), nil
}
