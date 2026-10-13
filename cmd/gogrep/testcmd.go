package gogrep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/odipar/gogrep/internal/engine"
	"github.com/odipar/gogrep/internal/opengrep"
	"github.com/odipar/gogrep/internal/ruletest"
)

// testUsage is the help text of gogrep test.
const testUsage = `Usage:
  gogrep test [run] [flags] [path...]   run rule test fixtures
  gogrep test accept [path...]          make each actual.txt the new expected.txt

Paths default to opengrep/gogrep/rules/test and must lie inside it.

Flags (run):
  --learn                  write expected.txt for tests whose results differ
  -j, --threads N          opengrep processes at once (default and 0: CPU count;
                           -N: CPU count minus N)
  --keep-sarif             keep each fixture's raw SARIF as actual.sarif
  --show-opengrep-output   print each fixture's opengrep command and stderr
  --rule, --suite, --gogrep-lang, --gogrep-category, --gogrep-ruleset
                           run only fixtures whose rule is selected

opengrep's own test runner: gogrep opengrep test ...
Exit codes: 0 all passed, 1 a test failed, 2 usage or setup error, 130 interrupted.
`

// testArgs are the arguments of gogrep test, without gogrep's own flags.
type testArgs struct {
	accept     bool // gogrep test accept
	help       bool
	paths      []string
	threads    int // -j: 0 means one per CPU, -N one per CPU less N
	learn      bool
	keepSARIF  bool
	showOutput bool
}

// parseTestArgs parses the arguments that follow "test". Flags may come
// before or after paths; opengrep's flags are not accepted, since gogrep test
// runs opengrep itself.
func parseTestArgs(args []string) (testArgs, error) {
	var a testArgs
	if len(args) > 0 && (args[0] == "run" || args[0] == "accept") {
		a.accept = args[0] == "accept"
		args = args[1:]
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, val, hasVal := strings.Cut(arg, "=")
		switch {
		case !strings.HasPrefix(arg, "-"):
			a.paths = append(a.paths, arg)
		case arg == "-h" || arg == "--help":
			a.help = true
		case a.accept:
			return a, fmt.Errorf("gogrep test accept takes only paths, not %s", arg)
		case name == "-j" || name == "--threads":
			if !hasVal {
				if i+1 == len(args) {
					return a, fmt.Errorf("%s needs a value", name)
				}
				i++
				val = args[i]
			}
			n, err := strconv.Atoi(val)
			if err != nil {
				return a, fmt.Errorf("%s needs a number, not %q", name, val)
			}
			a.threads = n
		case arg == "--learn":
			a.learn = true
		case arg == "--keep-sarif":
			a.keepSARIF = true
		case arg == "--show-opengrep-output":
			a.showOutput = true
		default:
			return a, fmt.Errorf("unknown flag %s; gogrep test does not forward flags to opengrep", arg)
		}
	}
	return a, nil
}

// runTest implements gogrep test: it runs the rule test fixtures under
// opengrep/gogrep/rules/test that args and sel select, or with accept makes
// their actual results the expected ones, and returns the exit code.
func (c *cli) runTest(args []string, sel selection) int {
	a, err := parseTestArgs(args)
	if err == nil && a.accept && (sel.explicit || len(sel.Filters) > 0) {
		err = errors.New("gogrep test accept takes only paths, not --rule, --suite or --gogrep-* flags")
	}
	if err != nil {
		fmt.Fprintf(c.stderr, "gogrep: %v\n", err)
		return 2
	}
	if a.help {
		io.WriteString(c.stdout, testUsage)
		return 0
	}
	fixtures, err := c.discover(a.paths)
	if err == nil {
		if a.accept {
			return accept(fixtures, c.stdout, c.stderr)
		}
		var code int
		if code, err = c.runFixtures(fixtures, a, sel); err == nil {
			return code
		}
	}
	fmt.Fprintf(c.stderr, "gogrep: %v\n", explain(err))
	return 2
}

// discover returns the fixtures that paths select in the project in the
// current directory.
func (c *cli) discover(paths []string) ([]*ruletest.Fixture, error) {
	fixtures, err := ruletest.Discover(c.dir, filepath.FromSlash(engine.ProjectTestsDir), paths)
	if errors.Is(err, ruletest.ErrNoRoot) {
		return nil, fmt.Errorf("no %s directory here; run gogrep test from the project root", engine.ProjectTestsDir)
	}
	return fixtures, err
}

// runFixtures runs the tests of the fixtures whose rules sel selects and
// returns the exit code. It returns an error, for exit code 2, when it
// cannot run them.
func (c *cli) runFixtures(fixtures []*ruletest.Fixture, a testArgs, sel selection) (int, error) {
	if sel.empty() {
		return 0, errNoRules
	}
	tests, untested, err := c.eng.PlanTests(c.dir, fixtures, sel.Selection)
	if err != nil {
		return 0, err
	}
	if len(tests) == 0 {
		return 0, errors.New("no tests match the selection")
	}

	// An interrupt stops the opengrep processes, and the tests that
	// finished are reported.
	ctx, stop := interruptContext()
	defer stop()
	r := &ruletest.Runner{Exec: execFixture, Threads: a.threads, Learn: a.learn, KeepSARIF: a.keepSARIF}
	if slices.ContainsFunc(tests, func(t *ruletest.Test) bool { return t.Rule != nil }) {
		// A missing opengrep is an error, rather than a failure of every
		// test; tests that fail before opengrep runs need none.
		info, err := c.eng.Opengrep(ctx)
		if err != nil {
			return 0, err
		}
		r.Bin = info.Path
	}
	report := &testReport{stdout: c.stdout, stderr: c.stderr, total: len(tests), showOutput: a.showOutput}
	report.start()
	if _, err := r.Run(ctx, tests, report.add); err != nil {
		return report.interrupted(), nil
	}
	code := report.finish()
	if len(a.paths) == 0 {
		warnUntested(c.stderr, untested)
	}
	return code, nil
}

// accept implements gogrep test accept: it makes the actual.txt of each
// fixture its expected.txt, prints "Accepted <fixture>" for each, and
// returns the exit code, 2 when a file could not be renamed.
func accept(fixtures []*ruletest.Fixture, stdout, stderr io.Writer) int {
	code := 0
	for _, a := range ruletest.Accept(fixtures) {
		if a.Err != nil {
			fmt.Fprintf(stderr, "gogrep: accepting %s/actual.txt: %v\n", a.Name, a.Err)
			code = 2
			continue
		}
		fmt.Fprintf(stdout, "Accepted %s\n", a.Name)
	}
	return code
}

// execFixture runs opengrep for one fixture, as ruletest.Exec describes, in
// a process group of its own that cancelling ctx kills.
func execFixture(ctx context.Context, dir string, args []string) (stdout, stderr []byte, code int, err error) {
	var out, errb bytes.Buffer
	c := &opengrep.Cmd{Path: args[0], Args: args[1:], Dir: dir, Env: opengrep.UTF8Env(os.Environ()), Stdout: &out, Stderr: &errb}
	err = c.Run(ctx)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.Exited() {
		return out.Bytes(), errb.Bytes(), exitErr.ExitCode(), nil
	}
	return out.Bytes(), errb.Bytes(), 0, err
}
