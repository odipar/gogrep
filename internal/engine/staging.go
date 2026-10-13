package engine

import (
	"fmt"

	"github.com/odipar/gogrep/internal/rules"
	"github.com/odipar/gogrep/internal/ruletest"
)

// This file lets the gogrep command reach the engine's rule handling until
// Command and Test exist; the steps that add them remove it.

// SelectionFile writes the rules that sel selects for a scan of dir to an
// opengrep config file in CacheDir and returns its path.
func (e *Engine) SelectionFile(dir string, sel Selection, noProject bool) (string, error) {
	if err := checkDir(dir, false); err != nil {
		return "", err
	}
	env, err := e.loadEnv(dir, noProject)
	if err != nil {
		return "", err
	}
	selected, err := sel.resolve(env)
	if err != nil {
		return "", err
	}
	file, err := e.writeRules(selected)
	if err != nil {
		return "", fmt.Errorf("writing selected rules: %w", err)
	}
	return file, nil
}

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
