package gogrep

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrNoOpengrep is wrapped by every error that leaves an Engine without
	// an opengrep to run: none was found, the one configured is not a
	// regular file, it could not be extracted, or it could not be started.
	// InstallOpengrep fixes the first case. For Config.Opengrep the error's
	// text is exec.LookPath's or os.Stat's, unchanged ("exec: …").
	ErrNoOpengrep = errors.New("no usable opengrep")

	// ErrNoRules reports a selection that picks no rules. A
	// *SelectionError wraps it for a Rules entry that matches no rule.
	ErrNoRules = errors.New("the selection matches no rules")

	// ErrUnknownSuite is wrapped by the *SelectionError for a suite name
	// that is neither a project suite nor a built-in one, also when a suite
	// imports it.
	ErrUnknownSuite = errors.New("unknown suite")

	// ErrNoSARIF is what every *OutputError is: opengrep exited 0 without
	// the valid SARIF 2.1.0 log of one run asked of it, as when its
	// processes are killed behind its launcher's back.
	ErrNoSARIF = errors.New("opengrep exited 0 but wrote no SARIF")

	// ErrNoTestRoot is wrapped by Test and AcceptTests when the project has
	// no ProjectTestsDir.
	ErrNoTestRoot = errors.New("no rule test directory")
)

// A SelectionError reports a Selection entry that is malformed, names an
// unknown suite, cannot be read, names a suite that cannot select rules, or
// matches no rule.
type SelectionError struct {
	Kind  string // "suite", "rule" or "filter"
	Value string // the suite name or file, the rule entry, or the filter's Field, as given
	Err   error  // ErrUnknownSuite, ErrNoRules, a regexp error, a suite file's read or parse error, or a suite's unknown rule set or import cycle
}

func (e *SelectionError) Error() string {
	switch {
	case e.Kind == "suite" && e.Err == ErrUnknownSuite:
		return fmt.Sprintf("unknown suite %q", e.Value)
	case e.Kind == "suite":
		return e.Err.Error()
	case e.Kind == "rule" && e.Err == ErrNoRules:
		return "rule " + e.Value + " matches no rule"
	case e.Value == "":
		return e.Kind + ": " + e.Err.Error()
	}
	return e.Kind + " " + e.Value + ": " + e.Err.Error()
}

func (e *SelectionError) Unwrap() error { return e.Err }

// An ExitError reports that opengrep exited with a non-zero code. gogrep
// never passes --error, so findings alone never cause one. opengrep's codes
// include 2 (fatal error), 4 (invalid pattern), 5 (invalid YAML), 7 (invalid
// rule or missing config) and 8 (unknown language).
type ExitError struct {
	Code   int     // -1 when a signal ended opengrep
	Stderr []byte  // the last 64 KiB of opengrep's stderr; nil from Cmd.Run
	Result *Result // what opengrep wrote, when it is a valid SARIF log; nil from Cmd.Run
}

// Error returns "opengrep exited with code 7" and, if any, ": " and
// Stderr's last non-empty line.
func (e *ExitError) Error() string {
	msg := fmt.Sprintf("opengrep exited with code %d", e.Code)
	lines := strings.Split(strings.TrimSpace(string(e.Stderr)), "\n")
	if line := strings.TrimSpace(lines[len(lines)-1]); line != "" {
		msg += ": " + line
	}
	return msg
}

// ExitCode returns e.Code.
func (e *ExitError) ExitCode() int { return e.Code }

// An OutputError reports that opengrep exited 0 without a usable SARIF log.
type OutputError struct {
	Err    error  // why the output is not a SARIF 2.1.0 log of one run
	Stderr []byte // the last 64 KiB of opengrep's stderr
}

// Error returns ErrNoSARIF's text, ": " and Err's.
func (e *OutputError) Error() string { return ErrNoSARIF.Error() + ": " + e.Err.Error() }

// Unwrap returns e.Err.
func (e *OutputError) Unwrap() error { return e.Err }

// Is reports whether target is ErrNoSARIF.
func (e *OutputError) Is(target error) bool { return target == ErrNoSARIF }

// An IntegrityError reports an opengrep executable whose SHA-256 is not the
// pinned one where gogrep requires it to be: Config.EmbeddedOpengrep, a
// downloaded asset, or InstallOptions.From. A cached executable that fails
// verification is treated as absent, never run, and replaced by the next
// InstallOpengrep.
type IntegrityError struct {
	Path string // the file or URL concerned; "embedded" for Config.EmbeddedOpengrep
	Want string // the pinned SHA-256, hex
	Got  string // the SHA-256 of the bytes, hex
}

func (e *IntegrityError) Error() string {
	return fmt.Sprintf("%s: SHA-256 %s, want the pinned %s", e.Path, e.Got, e.Want)
}

// noOpengrep is an error, worded as err, that leaves an Engine without an
// opengrep to run.
type noOpengrep struct{ err error }

func (e *noOpengrep) Error() string   { return e.err.Error() }
func (e *noOpengrep) Unwrap() []error { return []error{ErrNoOpengrep, e.err} }
