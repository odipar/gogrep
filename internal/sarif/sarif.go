// Package sarif reads the SARIF logs that opengrep writes with --sarif, the
// only opengrep output gogrep reads: it decodes the subset of SARIF 2.1.0
// that gogrep uses, turns a log's results into findings, and rebrands a log
// as gogrep's.
package sarif

import (
	"encoding/json"
	"fmt"
)

// A Log holds the parts of an opengrep SARIF log that gogrep reads. Fields
// are matched to SARIF properties by name, ignoring case.
type Log struct {
	Version string
	Runs    []Run
}

// A Run is the run of opengrep that a Log reports.
type Run struct {
	Tool struct {
		Driver struct {
			Rules []Rule // the rules opengrep loaded
		}
	}
	Invocations []Invocation
	Results     []Result
}

// A Rule is a rule that opengrep loaded.
type Rule struct {
	ID                   string
	DefaultConfiguration struct {
		Level string // the level of the rule's results: opengrep maps its severity to error, warning or note
	}
}

// An Invocation is how opengrep's run went.
type Invocation struct {
	ExecutionSuccessful        bool
	ToolExecutionNotifications []Notification
}

// A Notification is something opengrep reports about its run rather than
// about the code: a rule error, a missing target, a syntax error in a file.
type Notification struct {
	Level      string // error, warning, note or none; SARIF's default is warning
	Descriptor struct{ ID string }
	Message    struct{ Text string }
}

// A Result is one match of a rule.
type Result struct {
	RuleID       string
	Level        string // opengrep sets none; see Rule
	Message      struct{ Text string }
	Locations    []Location
	Fingerprints map[string]string
	Suppressions []Suppression
}

// A Location is where a result is.
type Location struct {
	PhysicalLocation struct {
		ArtifactLocation struct{ URI string }
		Region           Region
	}
}

// A Region is where in its file a result is: 1-based lines and byte columns,
// with an exclusive end column. Opengrep sets every field; 0 means missing.
type Region struct {
	StartLine, StartColumn, EndLine, EndColumn int
	Snippet                                    struct{ Text string } // the source lines of the match
}

// A Suppression says that a result is suppressed, and how: opengrep reports
// a nosemgrep comment as one of kind inSource.
type Suppression struct {
	Kind   string
	Status string // accepted, underReview or rejected; opengrep sets none
}

// Decode decodes the SARIF log that opengrep writes with --sarif. It is an
// error unless data is a SARIF 2.1.0 log with exactly one run.
func Decode(data []byte) (*Log, error) {
	var log Log
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("output is not a SARIF log: %w", err)
	}
	if log.Version != "2.1.0" {
		return nil, fmt.Errorf("output is not a SARIF 2.1.0 log (version %q)", log.Version)
	}
	if len(log.Runs) != 1 {
		return nil, fmt.Errorf("SARIF log has %d runs, want 1", len(log.Runs))
	}
	return &log, nil
}

// Check reports why data is not the SARIF log of one run that gogrep asks
// opengrep for, as Decode does, or nil when it is.
func Check(data []byte) error {
	_, err := Decode(data)
	return err
}
