package gogrep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"

	"github.com/odipar/gogrep/internal/rules"
	"github.com/odipar/gogrep/internal/ruletest"
)

// A Stage is where a rule test failed.
type Stage string

const (
	StageSetup  Stage = "SETUP"  // the fixture is malformed
	StageRule   Stage = "RULE"   // rule.ref names no rule, or opengrep rejects the rule
	StageRun    Stage = "RUN"    // opengrep failed, or its output cannot be trusted
	StageResult Stage = "RESULT" // expected.txt is missing or differs
)

// TestOptions configure Engine.Test; nil means the zero TestOptions, which
// run every fixture and write results into the fixtures, as `gogrep test`
// does.
type TestOptions struct {
	// Selection keeps only fixtures whose rule it selects. Unlike Scan, the
	// zero Selection selects every rule (no default suite), and Filters
	// alone narrow every rule. Fixtures that fail at SETUP or RULE always
	// run, so a typo cannot hide a test.
	Selection

	// Paths select fixtures: those below each path and the one containing
	// it. A relative path is relative to the project directory; every path
	// must lie inside its ProjectTestsDir and select a test. Empty means
	// every fixture.
	Paths []string

	// Jobs is how many opengrep processes run at once, each with -j 1: 0
	// means one per CPU, -N one per CPU less N, and always at least 1.
	Jobs int

	Learn     bool // a test that fails at RESULT writes its results as expected.txt and counts as learned
	KeepSARIF bool // keep each fixture's raw opengrep output as actual.sarif

	// ReadOnly writes and removes nothing in the fixtures: no actual.txt,
	// expected.txt or actual.sarif. Learn and KeepSARIF must be false. Use
	// it for the fixtures of a clone you do not want changed.
	ReadOnly bool

	// Progress, if not nil, is called on Test's goroutine: once with done 0
	// and a nil r when the tests are planned and opengrep is found, then
	// once per test, in fixture order, as soon as it and every test before
	// it are done.
	Progress func(done, total int, r *TestResult)
}

// A TestResult is how one fixture's test went.
type TestResult struct {
	Name            string   // the fixture, a slash path relative to the project directory
	Dir             string   // the fixture directory, absolute
	RuleID          string   // the qualified id rule.ref resolved to; "" at SETUP, or at RULE when it names no rule
	Stage           Stage    // where the test failed; "" when it passed or was learned
	Learned         bool     // the results became expected.txt (Learn)
	MissingExpected bool     // the fixture has no expected.txt
	Diff            string   // unified diff from expected.txt to the results; "" when they are equal
	Details         []string // why the test failed, if not for its results
	Command         []string // the opengrep command line, executable first, run in Dir; nil when opengrep did not run
	Stderr          []byte   // opengrep's stderr
	FileErrors      []error  // fixture files that could not be written or removed
}

// A TestReport is the outcome of Engine.Test.
type TestReport struct {
	Results []*TestResult // the reported tests, in order: all of them unless ctx ended the run
	Passed  int           // learned tests included
	Learned int
	Failed  []string // names of the tests that failed, sorted

	// Untested are the ids of project rules that no fixture's rule.ref
	// names, sorted. It is set only for a complete run of every fixture
	// with the zero Selection.
	Untested []string
}

// Test runs the rule test fixtures under ProjectTestsDir of dir, an absolute
// project directory, each in its own opengrep process, as `gogrep test`
// does. It always loads the project's rules, which the fixtures exist to
// test. Unless opts.ReadOnly is set, it writes actual.txt, expected.txt
// (Learn) and actual.sarif (KeepSARIF) into fixtures, 0o600 via a temporary
// file and rename, and removes stale ones. So do not run two Tests, or a
// Test and AcceptTests, on one directory at once, unless every Test is
// ReadOnly. A failing test is a result, not an error.
//
// Test returns an error wrapping ErrNoTestRoot when dir has no
// ProjectTestsDir; an error for a path that does not exist, lies outside it
// or selects no test; a *SelectionError or ErrNoRules; an error when no test
// matches the selection; and an error wrapping ErrNoOpengrep when a test
// needs opengrep and none is found (tests that fail at SETUP or RULE need
// none). When ctx is done, Test starts no more opengrep processes, kills the
// running ones, writes no files for their tests, and returns the tests
// reported so far with an error wrapping ctx.Err().
func (e *Engine) Test(ctx context.Context, dir string, opts *TestOptions) (*TestReport, error) {
	if opts == nil {
		opts = &TestOptions{}
	}
	if opts.ReadOnly && (opts.Learn || opts.KeepSARIF) {
		return nil, errors.New("TestOptions.ReadOnly excludes Learn and KeepSARIF")
	}
	fixtures, err := discover(dir, opts.Paths)
	if err != nil {
		return nil, err
	}
	tests, untested, err := e.planTests(dir, fixtures, opts.Selection)
	if err != nil {
		return nil, err
	}
	if len(tests) == 0 {
		return nil, errors.New("no tests match the selection")
	}
	r := &ruletest.Runner{Threads: opts.Jobs, Learn: opts.Learn, KeepSARIF: opts.KeepSARIF, ReadOnly: opts.ReadOnly}
	report := &TestReport{}
	if slices.ContainsFunc(tests, func(t *ruletest.Test) bool { return t.Rule != nil }) {
		info, xdg, err := e.opengrep(ctx)
		switch {
		case ctx.Err() != nil:
			return report, ctx.Err()
		case err != nil:
			return nil, err
		}
		r.Bin, r.Exec = info.Path, e.testExec(xdg)
	}

	if opts.Progress != nil {
		opts.Progress(0, len(tests), nil)
	}
	_, err = r.Run(ctx, tests, func(v *ruletest.Verdict) {
		res := testResult(v)
		report.Results = append(report.Results, res)
		switch {
		case res.Stage != "":
			report.Failed = append(report.Failed, res.Name)
		case res.Learned:
			report.Passed++
			report.Learned++
		default:
			report.Passed++
		}
		if opts.Progress != nil {
			opts.Progress(len(report.Results), len(tests), res)
		}
	})
	slices.Sort(report.Failed)
	if err != nil {
		return report, err
	}
	if len(opts.Paths) == 0 {
		report.Untested = untested
	}
	return report, nil
}

// testResult returns the TestResult of a test that went as v says.
func testResult(v *ruletest.Verdict) *TestResult {
	res := &TestResult{
		Name: v.Name, Dir: v.Dir, Stage: Stage(v.Stage), Learned: v.Learned, MissingExpected: v.Missing,
		Diff: v.Diff, Details: v.Details, Command: v.Command, Stderr: v.Stderr, FileErrors: v.FileErrors,
	}
	if v.Rule != nil {
		res.RuleID = v.Rule.ID
	}
	return res
}

// discover returns the fixtures that paths select in the project in dir.
func discover(dir string, paths []string) ([]*ruletest.Fixture, error) {
	if err := checkDir(dir, false); err != nil {
		return nil, err
	}
	fixtures, err := ruletest.Discover(dir, filepath.FromSlash(ProjectTestsDir), paths)
	if errors.Is(err, ruletest.ErrNoRoot) {
		return nil, fmt.Errorf("%w: %s", ErrNoTestRoot, ProjectTestsDir)
	}
	return fixtures, err
}

// planTests returns the tests of fixtures, of the project in dir, whose rules
// sel selects: every test that has a rule has its Config. untested is set
// for the zero Selection: the ids of the project rules that no test tests.
func (e *Engine) planTests(dir string, fixtures []*ruletest.Fixture, sel Selection) (tests []*ruletest.Test, untested []string, err error) {
	env, err := e.loadEnv(dir, false)
	if err != nil {
		return nil, nil, err
	}
	ids, active, err := sel.filter(env)
	if err != nil {
		return nil, nil, err
	}
	var keep func(*rules.Rule) bool
	if active {
		keep = func(r *rules.Rule) bool { return ids[r.ID] }
	}
	tests = ruletest.Plan(fixtures, allRules(env), keep)
	configs := map[*rules.Rule]string{}
	for _, t := range tests {
		if t.Rule == nil {
			continue
		}
		if configs[t.Rule] == "" {
			if configs[t.Rule], err = e.writeRules([]*rules.Rule{t.Rule}); err != nil {
				return nil, nil, fmt.Errorf("writing rule %s: %w", t.Rule.ID, err)
			}
		}
		t.Config = configs[t.Rule]
	}
	if !active {
		untested = ruletest.Untested(env.Sets["project"], tests)
	}
	return tests, untested, nil
}

// testExec returns how Test runs opengrep for a fixture, as runHermetic does,
// with the runtime xdg.
func (e *Engine) testExec(xdg string) ruletest.Exec {
	return func(ctx context.Context, dir string, args []string) (stdout, stderr []byte, code int, err error) {
		var out, errb bytes.Buffer
		err = e.runHermetic(ctx, args[0], xdg, dir, args[1:], &out, &errb)
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.Exited() {
			return out.Bytes(), errb.Bytes(), exitErr.ExitCode(), nil
		}
		return out.Bytes(), errb.Bytes(), 0, err
	}
}

// An Acceptance is one fixture whose actual.txt AcceptTests tried to make its
// expected.txt.
type Acceptance struct {
	Name string // the fixture, a slash path relative to the project directory
	Err  error  // why actual.txt could not become expected.txt; nil when it did
}

// AcceptTests renames the actual.txt of each fixture that paths select
// (every fixture when paths is empty) to expected.txt, mode 0o600. paths are
// as in TestOptions. Fixtures without actual.txt, and fixtures that fail at
// SETUP, are skipped. It returns one Acceptance per fixture it tried, in
// order; its error is set only when the fixtures cannot be discovered.
func (e *Engine) AcceptTests(dir string, paths []string) ([]Acceptance, error) {
	fixtures, err := discover(dir, paths)
	if err != nil {
		return nil, err
	}
	var out []Acceptance
	for _, a := range ruletest.Accept(fixtures) {
		out = append(out, Acceptance{Name: a.Name, Err: a.Err})
	}
	return out, nil
}
