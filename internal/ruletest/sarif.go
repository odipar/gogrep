package ruletest

import (
	"encoding/json"
	"fmt"
)

// A Log holds the parts of an opengrep SARIF log that rule tests read.
// Fields are matched to SARIF properties by name, ignoring case.
type Log struct {
	Version string
	Runs    []Run
}

// A Run is the run of opengrep that a Log reports.
type Run struct {
	Tool struct {
		Driver struct {
			Rules []struct{ ID string } // the rules opengrep loaded
		}
	}
	Invocations []struct {
		ToolExecutionNotifications []Notification
	}
	Results []Result
}

// A Notification is something opengrep reports about its run rather than
// about the code: a rule error, a missing target, a syntax error in a sample.
type Notification struct {
	Level      string // error, warning, note or none; SARIF's default is warning
	Descriptor struct{ ID string }
	Message    struct{ Text string }
}

// A Result is one match of a rule.
type Result struct {
	RuleID    string
	Message   struct{ Text string }
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct{ URI string }
			Region           Region
		}
	}
}

// A Region is where a result is: 1-based lines and byte columns, with an
// exclusive end column. Opengrep sets every field; 0 means missing.
type Region struct {
	StartLine, StartColumn, EndLine, EndColumn int
}

// DecodeSARIF decodes the SARIF log that opengrep writes to stdout with
// --sarif. It is an error unless data is a SARIF 2.1.0 log with exactly one
// run.
func DecodeSARIF(data []byte) (*Log, error) {
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
