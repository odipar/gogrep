package ruletest

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/odipar/gogrep/internal/rules"
)

// judge decides how a test went from opengrep's output for it and, unless
// r.ReadOnly is set, writes or removes the fixture's actual.txt,
// expected.txt and actual.sarif to match, as the design's §6.4 describes.
func (r *Runner) judge(t *Test, out Output) *Verdict {
	v := &Verdict{Test: t}
	fail := func(err error) { v.FileErrors = append(v.FileErrors, err) }
	var table []byte
	switch {
	case t.Setup != nil:
		v.Stage, v.Details = StageSetup, splitLines(t.Setup.Error())
	case t.Err != nil:
		v.Stage, v.Details = StageRule, splitLines(t.Err.Error())
	default:
		v.Command, v.Stderr = r.args(t), out.Stderr
		table, v.Stage, v.Details = Classify(out, t.Rule.ID, t.Samples)
	}
	if v.Stage == "" {
		expected, err := os.ReadFile(filepath.Join(t.Dir, expectedFile))
		v.Missing = errors.Is(err, fs.ErrNotExist)
		if err != nil && !v.Missing {
			v.Stage, v.Details = StageResult, []string{err.Error()}
		} else if v.Diff = Diff(Normalize(expected), Normalize(table)); v.Missing || v.Diff != "" {
			v.Stage = StageResult
			if r.Learn && !r.ReadOnly {
				if err := writeFile(t.Fixture, expectedFile, table); err != nil {
					fail(err)
				} else {
					v.Stage, v.Learned = "", true
				}
			}
		}
	}
	if r.ReadOnly {
		return v
	}

	// A test that fails at RESULT, also under --learn when expected.txt
	// cannot be read or written, leaves its results for accept; any other
	// test removes those of an earlier run.
	if v.Stage == StageResult {
		if err := writeFile(t.Fixture, actualFile, table); err != nil {
			fail(err)
		}
	} else if err := removeFile(t.Fixture, actualFile); err != nil {
		fail(err)
	}
	if r.KeepSARIF && len(out.Stdout) > 0 {
		if err := writeFile(t.Fixture, sarifFile, out.Stdout); err != nil {
			fail(err)
		}
	} else if err := removeFile(t.Fixture, sarifFile); err != nil {
		fail(err)
	}
	return v
}

// Untested returns the ids of the rules in project that no test's rule.ref
// names, sorted.
func Untested(project []*rules.Rule, tests []*Test) []string {
	tested := map[string]bool{}
	for _, t := range tests {
		if t.Rule != nil {
			tested[t.Rule.ID] = true
		}
	}
	var ids []string
	for _, r := range project {
		if !tested[r.ID] {
			ids = append(ids, r.ID)
		}
	}
	slices.Sort(ids)
	return ids
}
