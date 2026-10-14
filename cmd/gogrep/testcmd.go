package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/odipar/gogrep"
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
	if a.accept {
		return c.accept(a.paths)
	}
	return c.runFixtures(a, sel)
}

// runFixtures runs the tests that a and sel select, prints the report and
// returns the exit code.
func (c *cli) runFixtures(a testArgs, sel selection) int {
	opts := &gogrep.TestOptions{Selection: sel.Selection, Paths: a.paths, Jobs: a.threads, Learn: a.learn, KeepSARIF: a.keepSARIF}
	if sel.empty() {
		// It selects no rules, where the zero Selection selects every
		// one: so does a Filter without values.
		opts.Selection = gogrep.Selection{Filters: []gogrep.Filter{{Field: "id"}}}
	}
	report := &testReport{stdout: c.stdout, stderr: c.stderr, showOutput: a.showOutput}
	opts.Progress = func(_, total int, r *gogrep.TestResult) {
		if r == nil {
			report.total = total
			report.start()
			return
		}
		report.add(r)
	}

	// An interrupt stops the opengrep processes, and the tests that
	// finished are reported.
	ctx, stop := interruptContext()
	defer stop()
	rep, err := c.eng.Test(ctx, c.dir, opts)
	switch {
	case err != nil && ctx.Err() != nil:
		return report.interrupted()
	case err != nil:
		fmt.Fprintf(c.stderr, "gogrep: %v\n", explain(err))
		return 2
	}
	code := report.finish()
	warnUntested(c.stderr, rep.Untested)
	return code
}

// accept implements gogrep test accept: it makes the actual.txt of each
// fixture that paths select its expected.txt, prints "Accepted <fixture>" for
// each, and returns the exit code, 2 when a file could not be renamed.
func (c *cli) accept(paths []string) int {
	accepted, err := c.eng.AcceptTests(c.dir, paths)
	if err != nil {
		fmt.Fprintf(c.stderr, "gogrep: %v\n", explain(err))
		return 2
	}
	code := 0
	for _, a := range accepted {
		if a.Err != nil {
			fmt.Fprintf(c.stderr, "gogrep: accepting %s/actual.txt: %v\n", a.Name, a.Err)
			code = 2
			continue
		}
		fmt.Fprintf(c.stdout, "Accepted %s\n", a.Name)
	}
	return code
}
