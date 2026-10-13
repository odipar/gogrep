package sarif

import (
	"cmp"
	"path/filepath"
	"slices"
	"strings"
)

// A Finding is one match of a rule. Its fields are those of gogrep.Finding,
// in the same order, so that one converts to the other.
type Finding struct {
	RuleID  string
	Level   string // "error", "warning" or "note"
	Message string
	Path    string // a slash path relative to the scanned directory (see findingPath)

	// 1-based lines and byte columns; EndColumn is exclusive. They are 0 for
	// a result without a location.
	StartLine, StartColumn, EndLine, EndColumn int

	Snippet     string // the source lines of the match
	Fingerprint string // fingerprints["matchBasedId/v1"]
	Suppressed  bool   // a nosemgrep comment suppresses the match
}

// A Diagnostic is something opengrep reported about its run rather than
// about the code. Its fields are those of gogrep.Diagnostic, in the same
// order.
type Diagnostic struct {
	Level   string // "error", "warning", "note" or "none"; SARIF's default is "warning"
	ID      string
	Message string
}

// fingerprintKey names the fingerprint that opengrep gives every result.
const fingerprintKey = "matchBasedId/v1"

// Findings returns the log's results as findings, suppressed ones included,
// sorted by Path, StartLine, StartColumn, EndLine, EndColumn, RuleID and
// Fingerprint. A finding's Level is the result's level, else its rule's
// default level, else SARIF's default, "warning".
func (l *Log) Findings() []Finding {
	var found []Finding
	for _, run := range l.Runs {
		levels := map[string]string{}
		for _, r := range run.Tool.Driver.Rules {
			if _, ok := levels[r.ID]; !ok {
				levels[r.ID] = r.DefaultConfiguration.Level
			}
		}
		for _, res := range run.Results {
			f := Finding{
				RuleID:      res.RuleID,
				Level:       cmp.Or(res.Level, levels[res.RuleID], "warning"),
				Message:     res.Message.Text,
				Fingerprint: res.Fingerprints[fingerprintKey],
				Suppressed:  suppressed(res.Suppressions),
			}
			if len(res.Locations) > 0 {
				loc := res.Locations[0].PhysicalLocation
				reg := loc.Region
				f.Path = findingPath(loc.ArtifactLocation.URI, filepath.Separator)
				f.StartLine, f.StartColumn, f.EndLine, f.EndColumn = reg.StartLine, reg.StartColumn, reg.EndLine, reg.EndColumn
				f.Snippet = reg.Snippet.Text
			}
			found = append(found, f)
		}
	}
	slices.SortStableFunc(found, func(a, b Finding) int {
		return cmp.Or(
			strings.Compare(a.Path, b.Path),
			cmp.Compare(a.StartLine, b.StartLine),
			cmp.Compare(a.StartColumn, b.StartColumn),
			cmp.Compare(a.EndLine, b.EndLine),
			cmp.Compare(a.EndColumn, b.EndColumn),
			strings.Compare(a.RuleID, b.RuleID),
			strings.Compare(a.Fingerprint, b.Fingerprint),
		)
	})
	return found
}

// findingPath returns a result's uri as a finding's Path: with a leading "./"
// removed and, when sep, the separator of the system opengrep ran on, is a
// backslash, backslashes turned into slashes. opengrep writes uris raw, so
// they are never percent-decoded.
func findingPath(uri string, sep byte) string {
	if sep == '\\' {
		uri = strings.ReplaceAll(uri, `\`, "/")
	}
	return strings.TrimPrefix(uri, "./")
}

// suppressed reports whether a result with the suppressions ss is
// suppressed in the source, by a nosemgrep comment.
func suppressed(ss []Suppression) bool {
	return slices.ContainsFunc(ss, func(s Suppression) bool {
		return s.Kind == "inSource" && (s.Status == "" || s.Status == "accepted")
	})
}

// Diagnostics returns the notifications of the log's invocations, in order.
func (l *Log) Diagnostics() []Diagnostic {
	var ds []Diagnostic
	for _, run := range l.Runs {
		for _, inv := range run.Invocations {
			for _, n := range inv.ToolExecutionNotifications {
				ds = append(ds, Diagnostic{Level: cmp.Or(n.Level, "warning"), ID: n.Descriptor.ID, Message: n.Message.Text})
			}
		}
	}
	return ds
}

// Complete reports whether opengrep says that its run succeeded: the first
// invocation's executionSuccessful.
func (l *Log) Complete() bool {
	return len(l.Runs) > 0 && len(l.Runs[0].Invocations) > 0 && l.Runs[0].Invocations[0].ExecutionSuccessful
}
