package ruletest

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/odipar/gogrep/internal/rules"
)

// Exec runs opengrep in the directory dir: args[0] is the binary and the rest
// are its arguments. It returns opengrep's stdout, stderr and exit code; err
// is set when opengrep could not start or did not exit normally, for example
// because ctx was done and it was killed.
type Exec func(ctx context.Context, dir string, args []string) (stdout, stderr []byte, code int, err error)

// A Test is a fixture to run, with the rule its rule.ref names.
type Test struct {
	*Fixture
	Rule   *rules.Rule // the rule under test; nil when the test fails at SETUP or RULE
	Err    error       // why rule.ref names no rule: the test fails at RULE
	Config string      // an opengrep config file that holds only Rule (see rules.Write)
}

// Plan returns a test for each fixture, with the rule among all that the
// reference of a fixture that passed discovery names (see Resolve). When keep
// is not nil, the tests of rules it rejects are left out. Tests that fail at
// SETUP or RULE are always kept, so a typo cannot hide a test.
func Plan(fixtures []*Fixture, all []*rules.Rule, keep func(*rules.Rule) bool) []*Test {
	var tests []*Test
	for _, f := range fixtures {
		t := &Test{Fixture: f}
		if f.Setup == nil {
			t.Rule, t.Err = Resolve(f.Ref, f.Namespace, all)
		}
		if t.Rule == nil || keep == nil || keep(t.Rule) {
			tests = append(tests, t)
		}
	}
	return tests
}

// A Runner runs tests, each in its own opengrep process, and reports them.
type Runner struct {
	Bin        string // the opengrep binary
	Exec       Exec
	Threads    int  // opengrep processes at once: 0 means one per CPU, -N one per CPU less N, and at least 1
	Learn      bool // make the results of tests that fail at RESULT their expected.txt
	KeepSARIF  bool // keep each fixture's opengrep output as actual.sarif
	ShowOutput bool // print each fixture's opengrep command line and stderr
}

// Run runs tests and reports them on stdout in order, each as soon as it and
// every test before it are done, followed by a summary. It returns gogrep's
// exit code: 0 when every test passed, 1 when a test failed, 2 when a file in
// a fixture could not be written or removed, and 130 when ctx was done before
// every test was reported. ctx is done when gogrep is interrupted: Run then
// starts no more opengrep processes, Exec kills the running ones, and the
// tests that had not finished are neither reported nor touch their files.
func (r *Runner) Run(ctx context.Context, tests []*Test, stdout, stderr io.Writer) int {
	fmt.Fprintf(stdout, "Executing %d tests.\n", len(tests))
	outs := make([]Output, len(tests))
	finished := make([]bool, len(tests)) // ran to the end before ctx was done
	done := make([]chan struct{}, len(tests))
	jobs := make(chan int)
	for i, t := range tests {
		done[i] = make(chan struct{})
		if t.Rule == nil {
			finished[i] = true
			close(done[i])
		}
	}
	go func() {
		defer close(jobs)
		first := true
		for i, t := range tests {
			if t.Rule == nil {
				continue
			}
			select {
			case jobs <- i:
			case <-ctx.Done():
				return
			}
			// On its first run, opengrep unpacks itself into the user's
			// cache, and runs that start meanwhile can crash (SIGBUS).
			if first {
				first = false
				select {
				case <-done[i]:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	var wg sync.WaitGroup
	for range r.threads(len(tests)) {
		wg.Go(func() {
			for i := range jobs {
				if ctx.Err() == nil {
					outs[i] = r.exec(ctx, tests[i])
					finished[i] = ctx.Err() == nil
				}
				close(done[i])
			}
		})
	}
	defer wg.Wait()

	var s tally
	for i, t := range tests {
		if !ready(ctx, done[i]) || !finished[i] {
			fmt.Fprintln(stderr, "gogrep: interrupted")
			return 130
		}
		v := r.judge(t, outs[i], stderr)
		s.add(t, v)
		v.print(stdout, i+1, len(tests), t)
		if r.ShowOutput && t.Rule != nil {
			// opengrep ran in the fixture, on sample paths relative to it.
			fmt.Fprintf(stdout, "  $ (cd %s && %s)\n", commandLine([]string{t.Name}), commandLine(r.args(t)))
			for _, l := range quoted(outs[i].Stderr) {
				fmt.Fprintf(stdout, "  %s\n", l)
			}
		}
	}
	s.print(stdout)
	return s.code()
}

// ready waits until done is closed or ctx is done, and reports whether done
// is closed.
func ready(ctx context.Context, done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	case <-ctx.Done():
	}
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// threads returns how many opengrep processes run at once for n tests.
func (r *Runner) threads(n int) int {
	j := r.Threads
	if j <= 0 {
		j += runtime.NumCPU()
	}
	return max(min(j, n), 1)
}

// args returns the command line that runs opengrep with the test's rule on
// its samples, as the design's §6.2 describes.
func (r *Runner) args(t *Test) []string {
	args := []string{r.Bin, "scan", "--config", t.Config, "--no-rewrite-rule-ids", "--sarif", "--disable-version-check", "--timeout", "0", "-j", "1", "--"}
	for _, s := range t.Samples {
		args = append(args, "."+string(filepath.Separator)+filepath.FromSlash(s))
	}
	return args
}

func (r *Runner) exec(ctx context.Context, t *Test) Output {
	var out Output
	out.Stdout, out.Stderr, out.Code, out.Err = r.Exec(ctx, t.Dir, r.args(t))
	return out
}
