package ruletest

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/odipar/gogrep/internal/rules"
)

// A verdict is how a test went.
type verdict struct {
	stage   Stage    // where the test failed, or "" when it passed
	learned bool     // the results differed and became expected.txt
	missing bool     // there is no expected.txt
	diff    string   // the diff from expected.txt to the results
	desc    []string // why the test failed, if not for its results
	ioErr   bool     // a file in the fixture could not be written or removed
}

// judge decides how a test went from opengrep's output for it, and writes or
// removes the fixture's actual.txt, expected.txt and actual.sarif to match,
// as the design's §6.4 describes. It reports the files it cannot write or
// remove on stderr.
func (r *Runner) judge(t *Test, out Output, stderr io.Writer) verdict {
	var v verdict
	fail := func(err error) {
		fmt.Fprintf(stderr, "gogrep: %v\n", err)
		v.ioErr = true
	}
	var table []byte
	switch {
	case t.Setup != nil:
		v.stage, v.desc = StageSetup, splitLines(t.Setup.Error())
	case t.Err != nil:
		v.stage, v.desc = StageRule, splitLines(t.Err.Error())
	default:
		table, v.stage, v.desc = Classify(out, t.Rule.ID, t.Samples)
	}
	if v.stage == "" {
		expected, err := os.ReadFile(filepath.Join(t.Dir, expectedFile))
		v.missing = errors.Is(err, fs.ErrNotExist)
		if err != nil && !v.missing {
			v.stage, v.desc = StageResult, []string{err.Error()}
		} else if v.diff = Diff(Normalize(expected), Normalize(table)); v.missing || v.diff != "" {
			v.stage = StageResult
			if r.Learn {
				if err := writeFile(t.Fixture, expectedFile, table); err != nil {
					fail(err)
				} else {
					v.stage, v.learned = "", true
				}
			}
		}
	}

	// A test that fails at RESULT, also under --learn when expected.txt
	// cannot be read or written, leaves its results for accept; any other
	// test removes those of an earlier run.
	if v.stage == StageResult {
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

// print reports the i-th of n tests: a status line, then the diff of a test
// whose results differ from expected.txt, or why it failed, indented.
func (v verdict) print(w io.Writer, i, n int, t *Test) {
	status := "PASSED"
	switch {
	case v.learned:
		status = "LEARNED"
	case v.stage != "":
		status = "FAILED(" + string(v.stage) + ")"
	}
	fmt.Fprintf(w, "[%d/%d] %s %s\n", i, n, status, t.Name)
	if v.missing && !v.learned {
		fmt.Fprintf(w, "Cannot find %s.\n", expectedFile)
	}
	io.WriteString(w, v.diff)
	for _, l := range v.desc {
		fmt.Fprintf(w, "  %s\n", l)
	}
}

// A tally counts the tests that Run reported.
type tally struct {
	passed, learned int
	failed          []string // the names of the tests that failed
	ioErr           bool
}

func (s *tally) add(t *Test, v verdict) {
	switch {
	case v.stage != "":
		s.failed = append(s.failed, t.Name)
	case v.learned:
		s.passed++
		s.learned++
	default:
		s.passed++
	}
	s.ioErr = s.ioErr || v.ioErr
}

// print writes the summary line, and the names of the tests that failed.
func (s *tally) print(w io.Writer) {
	switch {
	case len(s.failed) > 0:
		fmt.Fprintf(w, "%d tests passed; %d tests failed:\n", s.passed, len(s.failed))
		slices.Sort(s.failed)
		for _, name := range s.failed {
			fmt.Fprintf(w, "  FAILED: %s\n", name)
		}
	case s.learned > 0:
		fmt.Fprintf(w, "All %d tests passed (%d learned).\n", s.passed, s.learned)
	default:
		fmt.Fprintf(w, "All %d tests passed.\n", s.passed)
	}
}

// code returns gogrep's exit code for the tests.
func (s *tally) code() int {
	switch {
	case s.ioErr:
		return 2
	case len(s.failed) > 0:
		return 1
	}
	return 0
}

// WarnUntested warns on w about the rules in project that no test's
// rule.ref names. gogrep warns after a full run: of every fixture, with no
// selection flags, and not interrupted.
func WarnUntested(w io.Writer, project []*rules.Rule, tests []*Test) {
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
	switch len(ids) {
	case 0:
		return
	case 1:
		fmt.Fprintln(w, "gogrep: warning: 1 project rule has no test fixture:")
	default:
		fmt.Fprintf(w, "gogrep: warning: %d project rules have no test fixture:\n", len(ids))
	}
	slices.Sort(ids)
	for _, id := range ids {
		fmt.Fprintf(w, "  %s\n", id)
	}
}

// commandLine returns args as a POSIX shell command line.
func commandLine(args []string) string {
	words := make([]string, len(args))
	for i, a := range args {
		words[i] = a
		if a == "" || strings.ContainsFunc(a, needsQuote) {
			words[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
	}
	return strings.Join(words, " ")
}

// needsQuote reports whether a shell word that contains r must be quoted.
func needsQuote(r rune) bool {
	return !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || strings.ContainsRune("-_./:=@%+,", r))
}
