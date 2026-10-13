package engine

import (
	"errors"
	"fmt"
)

var (
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
