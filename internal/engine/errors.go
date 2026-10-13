package engine

import (
	"errors"
	"fmt"
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
)

// A SelectionError reports a Selection entry that is malformed, names an
// unknown suite, cannot be read, or matches no rule.
type SelectionError struct {
	Kind  string // "suite", "rule" or "filter"
	Value string // the suite name or file, the rule entry, or the filter's Field, as given
	Err   error  // ErrUnknownSuite, ErrNoRules, a regexp error, or a suite file's read or parse error
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
