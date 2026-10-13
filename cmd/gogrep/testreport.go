package gogrep

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/odipar/gogrep/internal/engine"
)

// A testReport prints the report of gogrep test: how many tests run, then
// each test as soon as it and every test before it are done, then a summary.
type testReport struct {
	stdout, stderr io.Writer
	total          int  // the number of tests
	showOutput     bool // print each test's opengrep command line and stderr

	reported   int
	passed     int // learned tests included
	learned    int
	failed     []string // the names of the tests that failed
	fileErrors bool     // a file in a fixture could not be written or removed
}

// start reports that the tests run.
func (p *testReport) start() {
	fmt.Fprintf(p.stdout, "Executing %d tests.\n", p.total)
}

// add reports the next test: the files of its fixture that could not be
// written or removed on stderr, then a status line, then the diff of a test
// whose results differ from expected.txt, or why it failed, indented, and
// with showOutput the opengrep command line and stderr.
func (p *testReport) add(v *engine.TestResult) {
	p.reported++
	for _, err := range v.FileErrors {
		fmt.Fprintf(p.stderr, "gogrep: %v\n", err)
		p.fileErrors = true
	}
	status := "PASSED"
	switch {
	case v.Learned:
		status = "LEARNED"
	case v.Stage != "":
		status = "FAILED(" + string(v.Stage) + ")"
	}
	fmt.Fprintf(p.stdout, "[%d/%d] %s %s\n", p.reported, p.total, status, v.Name)
	if v.MissingExpected && !v.Learned {
		fmt.Fprintln(p.stdout, "Cannot find expected.txt.")
	}
	io.WriteString(p.stdout, v.Diff)
	for _, l := range v.Details {
		fmt.Fprintf(p.stdout, "  %s\n", l)
	}
	if p.showOutput && v.Command != nil {
		// opengrep ran in the fixture, on sample paths relative to it.
		fmt.Fprintf(p.stdout, "  $ (cd %s && %s)\n", commandLine([]string{v.Name}), commandLine(v.Command))
		for _, l := range quoted(v.Stderr) {
			fmt.Fprintf(p.stdout, "  %s\n", l)
		}
	}

	switch {
	case v.Stage != "":
		p.failed = append(p.failed, v.Name)
	case v.Learned:
		p.passed++
		p.learned++
	default:
		p.passed++
	}
}

// interrupted reports that gogrep was interrupted before every test was
// reported, and returns gogrep's exit code.
func (p *testReport) interrupted() int {
	fmt.Fprintln(p.stderr, "gogrep: interrupted")
	return 130
}

// finish writes the summary line, and the names of the tests that failed,
// and returns gogrep's exit code: 0 when every test passed, 1 when a test
// failed, and 2 when a file in a fixture could not be written or removed.
func (p *testReport) finish() int {
	switch {
	case len(p.failed) > 0:
		fmt.Fprintf(p.stdout, "%d tests passed; %d tests failed:\n", p.passed, len(p.failed))
		slices.Sort(p.failed)
		for _, name := range p.failed {
			fmt.Fprintf(p.stdout, "  FAILED: %s\n", name)
		}
	case p.learned > 0:
		fmt.Fprintf(p.stdout, "All %d tests passed (%d learned).\n", p.passed, p.learned)
	default:
		fmt.Fprintf(p.stdout, "All %d tests passed.\n", p.passed)
	}
	switch {
	case p.fileErrors:
		return 2
	case len(p.failed) > 0:
		return 1
	}
	return 0
}

// warnUntested warns on w about the project rules with the ids untested,
// which no test's rule.ref names. gogrep warns after a full run: of every
// fixture, with no selection flags, and not interrupted.
func warnUntested(w io.Writer, untested []string) {
	switch len(untested) {
	case 0:
		return
	case 1:
		fmt.Fprintln(w, "gogrep: warning: 1 project rule has no test fixture:")
	default:
		fmt.Fprintf(w, "gogrep: warning: %d project rules have no test fixture:\n", len(untested))
	}
	for _, id := range untested {
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

// quoted returns the lines of output, each prefixed with "> ", without
// trailing blanks and without blank lines at the start or end. CRLF counts
// as a line end.
func quoted(output []byte) []string {
	s := strings.TrimRight(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n")
	if s == "" {
		return nil
	}
	ls := strings.Split(s, "\n")
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
