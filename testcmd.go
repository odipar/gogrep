package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/odipar/gogrep/internal/rules"
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
func runTest(args []string, sel selection, stdout, stderr io.Writer) int {
	a, err := parseTestArgs(args)
	if err == nil && a.accept && (sel.explicit || len(sel.narrow) > 0) {
		err = errors.New("gogrep test accept takes only paths, not --rule, --suite or --gogrep-* flags")
	}
	if err != nil {
		fmt.Fprintf(stderr, "gogrep: %v\n", err)
		return 2
	}
	if a.help {
		io.WriteString(stdout, testUsage)
		return 0
	}
	fixtures, err := ruletest.Discover(projectTestsDir, a.paths)
	if err == nil {
		if a.accept {
			return ruletest.Accept(fixtures, stdout, stderr)
		}
		var code int
		if code, err = runFixtures(fixtures, a, sel, stdout, stderr); err == nil {
			return code
		}
	}
	fmt.Fprintf(stderr, "gogrep: %v\n", err)
	return 2
}

// runFixtures runs the tests of the fixtures whose rules sel selects and
// returns the exit code. It returns an error, for exit code 2, when it
// cannot run them.
func runFixtures(fixtures []*ruletest.Fixture, a testArgs, sel selection, stdout, stderr io.Writer) (int, error) {
	env, err := loadEnv()
	if err != nil {
		return 0, err
	}
	ids, active, err := sel.filter(env)
	if err != nil {
		return 0, err
	}
	var keep func(*rules.Rule) bool
	if active {
		keep = func(r *rules.Rule) bool { return ids[r.ID] }
	}
	tests := ruletest.Plan(fixtures, allRules(env), keep)
	if len(tests) == 0 {
		return 0, errors.New("no tests match the selection")
	}

	r := &ruletest.Runner{Exec: execFixture, Threads: a.threads, Learn: a.learn, KeepSARIF: a.keepSARIF, ShowOutput: a.showOutput}
	configs := map[*rules.Rule]string{}
	for _, t := range tests {
		if t.Rule == nil {
			continue
		}
		if r.Bin == "" {
			if r.Bin, err = testBin(); err != nil {
				return 0, err
			}
		}
		if configs[t.Rule] == "" {
			if configs[t.Rule], err = rules.Write([]*rules.Rule{t.Rule}); err != nil {
				return 0, fmt.Errorf("writing rule %s: %w", t.Rule.ID, err)
			}
		}
		t.Config = configs[t.Rule]
	}

	// A scan leaves Ctrl-C to its one opengrep process; gogrep test catches
	// it, stops its opengrep processes and reports the tests that finished.
	// A signal gogrep was started with ignored, as nohup does SIGHUP, stays
	// ignored; given no signals at all, NotifyContext would catch every one.
	ctx, stop := context.Background(), context.CancelFunc(func() {})
	if sigs := slices.DeleteFunc(slices.Clone(interrupts), signal.Ignored); len(sigs) > 0 {
		ctx, stop = signal.NotifyContext(ctx, sigs...)
	}
	defer stop()
	code := r.Run(ctx, tests, stdout, stderr)
	if code != 130 && len(a.paths) == 0 && !active {
		ruletest.WarnUntested(stderr, env.Sets["project"], tests)
	}
	return code, nil
}

// testBin returns the opengrep binary that gogrep test runs, as an absolute
// path: each opengrep process runs in its fixture's directory, where a
// relative $OPENGREP_BIN would name another file. A binary that is missing
// is an error, for exit code 2, rather than a failure of every test.
func testBin() (string, error) {
	bin, err := opengrepBin()
	if err == nil {
		bin, err = exec.LookPath(bin)
	}
	if err == nil {
		bin, err = filepath.Abs(bin)
	}
	if err != nil {
		return "", err
	}
	if fi, err := os.Stat(bin); err != nil || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("opengrep binary %s is not a regular file", bin)
	}
	return bin, nil
}

// execFixture runs opengrep for one fixture, as ruletest.Exec describes.
func execFixture(ctx context.Context, dir string, args []string) (stdout, stderr []byte, code int, err error) {
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	killTree(cmd)
	cmd.Dir, cmd.Env = dir, utf8Env(os.Environ())
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.WaitDelay = time.Second
	err = cmd.Run()
	// A process killed on Windows exits with code 1, so after an interrupt
	// an exit code is not trusted.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.Exited() && ctx.Err() == nil {
		return out.Bytes(), errb.Bytes(), exitErr.ExitCode(), nil
	}
	return out.Bytes(), errb.Bytes(), 0, err
}
