package ruletest

import (
	"fmt"
	"strings"

	"github.com/odipar/gogrep/internal/sarif"
)

// A Stage is where a test failed.
type Stage string

const (
	StageSetup  Stage = "SETUP"  // the fixture is malformed
	StageRule   Stage = "RULE"   // the rule reference does not resolve, or opengrep rejects the rule
	StageRun    Stage = "RUN"    // opengrep failed, or its output cannot be trusted
	StageResult Stage = "RESULT" // expected.txt is missing or differs
)

// stderrTail is the number of opengrep's last stderr lines a failure shows.
const stderrTail = 20

// An Output is what one opengrep run produced.
type Output struct {
	Stdout, Stderr []byte
	Code           int   // the exit code
	Err            error // opengrep could not start or did not exit normally
}

// Classify decides whether opengrep's run of the rule ruleID on a fixture's
// samples can be trusted, by rows 1 to 4 of the design's §6.3: whether it
// ran, whether its output is a SARIF log whose results lie in the samples,
// whether it loaded the rule, whether it reported an error, and whether
// every result is the rule's. If the run can be trusted, Classify returns its
// table (see Render). Otherwise it returns the stage at which the test fails
// and lines that say why.
func Classify(out Output, ruleID string, samples []string) (table []byte, stage Stage, desc []string) {
	exit := fmt.Sprintf("opengrep exited with code %d", out.Code)
	if out.Err != nil {
		return nil, StageRun, append([]string{"running opengrep: " + out.Err.Error()}, tail(out.Stderr)...)
	}
	log, err := sarif.Decode(out.Stdout)
	if err == nil {
		table, err = Render(log, samples)
	}
	if err != nil {
		return nil, StageRun, append([]string{err.Error(), exit}, tail(out.Stderr)...)
	}

	run := log.Runs[0]
	var errs, notes []string // error-level notifications, and all of them
	missingTarget := false
	for _, inv := range run.Invocations {
		for _, n := range inv.ToolExecutionNotifications {
			lines := splitLines(n.Descriptor.ID + ": " + n.Message.Text)
			notes = append(notes, lines...)
			if n.Level == "error" {
				errs = append(errs, lines...)
				// opengrep loads no rule when a target is missing, and says so
				// in a SemgrepError. A rule that opengrep-core rejects is a
				// SemgrepError too, with another message.
				missingTarget = missingTarget || n.Descriptor.ID == "SemgrepError" && strings.HasPrefix(n.Message.Text, "File not found:")
			}
		}
	}
	loaded := false
	for _, r := range run.Tool.Driver.Rules {
		loaded = loaded || r.ID == ruleID
	}
	switch {
	case out.Code == 7 || out.Code == 8 || !loaded && !missingTarget:
		if len(errs) == 0 {
			notes = append(append([]string{"opengrep did not load rule " + ruleID}, notes...), tail(out.Stderr)...)
		}
		return nil, StageRule, notes
	case out.Code != 0 || len(errs) > 0:
		return nil, StageRun, append(append(errs, exit), tail(out.Stderr)...)
	}
	for _, r := range run.Results {
		if r.RuleID != ruleID {
			return nil, StageRun, []string{"unexpected rule id " + r.RuleID}
		}
	}
	return table, "", nil
}

// tail returns the last lines of opengrep's stderr, each prefixed with "> ".
func tail(stderr []byte) []string {
	ls := quoted(stderr)
	return ls[max(len(ls)-stderrTail, 0):]
}

// quoted returns the lines of output, each prefixed with "> ", without
// trailing blanks and without blank lines at the start or end.
func quoted(output []byte) []string {
	ls := splitLines(string(output))
	for i, l := range ls {
		ls[i] = strings.TrimRight("> "+l, " \t")
	}
	for len(ls) > 0 && ls[0] == ">" {
		ls = ls[1:]
	}
	for len(ls) > 0 && ls[len(ls)-1] == ">" {
		ls = ls[:len(ls)-1]
	}
	return ls
}

// splitLines splits s into lines, reading CRLF as LF and ignoring line ends
// at the end.
func splitLines(s string) []string {
	s = strings.TrimRight(crlfToLF(s), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
