package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"

	"github.com/odipar/gogrep/internal/opengrep"
	"github.com/odipar/gogrep/internal/rules"
	"github.com/odipar/gogrep/internal/ruletest"
)

// This file lets the gogrep command's test reach the engine until Test
// exists; the step that adds it removes this file.

// PlanTests returns the tests of fixtures, of the project in dir, whose rules
// sel selects, as Test runs them: every test that has a rule has its Config.
// untested is set for the zero Selection: the ids of the project rules that
// no test tests.
func (e *Engine) PlanTests(dir string, fixtures []*ruletest.Fixture, sel Selection) (tests []*ruletest.Test, untested []string, err error) {
	if err := checkDir(dir, false); err != nil {
		return nil, nil, err
	}
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

// TestExec returns the opengrep that Test runs, prepared as Opengrep
// prepares it, and how Test runs it for each fixture: in a process group of
// its own that a done ctx kills, without the SEMGREP_* and OPENGREP_*
// variables of Config.Env, and with a log file of its own.
func (e *Engine) TestExec(ctx context.Context) (string, ruletest.Exec, error) {
	info, xdg, err := e.opengrep(ctx)
	if err != nil {
		return "", nil, err
	}
	env := withRuntime(opengrep.UTF8Env(opengrep.HermeticEnv(e.env)), xdg)
	run := func(ctx context.Context, dir string, args []string) (stdout, stderr []byte, code int, err error) {
		if e.cacheErr != nil {
			return nil, nil, 0, e.cacheErr
		}
		log, err := opengrep.LogFile(e.cacheDir)
		if err != nil {
			return nil, nil, 0, err
		}
		defer os.Remove(log)
		var out, errb bytes.Buffer
		c := &opengrep.Cmd{Path: args[0], Args: args[1:], Dir: dir, Env: append(slices.Clip(env), "SEMGREP_LOG_FILE="+log), Stdout: &out, Stderr: &errb}
		err = c.Run(ctx)
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.Exited() {
			return out.Bytes(), errb.Bytes(), exitErr.ExitCode(), nil
		}
		return out.Bytes(), errb.Bytes(), 0, err
	}
	return info.Path, run, nil
}
