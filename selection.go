package gogrep

import (
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/odipar/gogrep/internal/rules"
	"github.com/odipar/gogrep/internal/suite"
)

// A Selection picks rules as the gogrep command's --suite, --rule and
// --gogrep-* flags do: the union of what Suites and Rules select, narrowed
// by every Filter. With no Suites and no Rules, Scan, Rules and Command
// start from DefaultSuite, and Test from every rule; the zero Selection is
// therefore each method's default.
type Selection struct {
	// Suites are suite names or suite files. A name is looked up as
	// <dir>/opengrep/gogrep/suites/<name>.yaml or .yml, unless project
	// rules are off, which shadows a built-in suite of that name; then
	// among the built-in suites. An entry that contains a slash or
	// backslash, or ends in .yaml or .yml, is a suite file: absolute, or
	// relative to the project directory. A suite's import: entries resolve
	// the same way.
	Suites []string

	// Rules are rule ids: a qualified id such as
	// "opengrep-rules.go.lang.security.audit.dangerous-exec-command", the
	// part of one after a dot ("dangerous-exec-command"), or a /regular
	// expression/ matched against qualified ids.
	Rules []string

	// Filters narrow the union: a rule is kept only if every Filter keeps
	// it. The gogrep command adds one Filter per --gogrep-* flag, so a
	// flag's comma-separated values are alternatives and repeated flags all
	// apply.
	Filters []Filter
}

// A Filter keeps the rules whose field Field has a value that matches one of
// Values, ignoring case; a value written /like this/ is a regular
// expression. A field with several values, such as languages or cwe,
// matches if any of them does. A Filter with no Values keeps no rule. The
// fields are those of Rule.Fields: id, ruleset, path, severity, message,
// languages, and every scalar metadata field such as category or
// confidence, also as metadata.<name>.
type Filter struct {
	Field  string
	Values []string
}

// Validate reports the first malformed entry of s, such as an invalid
// regular expression or a Filter without a Field, as a *SelectionError. It
// loads no rules, so it checks neither that suites exist nor that rules
// match; the methods that take a Selection do.
func (s Selection) Validate() error {
	for _, id := range s.Rules {
		if _, err := idFilter(id); err != nil {
			return err
		}
	}
	_, err := s.narrowing()
	return err
}

// narrowing returns s's Filters as suite filters.
func (s Selection) narrowing() ([]*suite.Suite, error) {
	var narrow []*suite.Suite
	for _, f := range s.Filters {
		if f.Field == "" {
			return nil, &SelectionError{Kind: "filter", Err: errors.New("no field")}
		}
		n, err := suite.Filter(true, f.Field, f.Values...)
		if err != nil {
			return nil, &SelectionError{Kind: "filter", Value: f.Field, Err: err}
		}
		narrow = append(narrow, n)
	}
	return narrow, nil
}

// resolve returns the rules s selects in env for Scan, Rules and Command:
// the union of its suites and rules (or DefaultSuite), narrowed by its
// filters.
func (s Selection) resolve(env *suite.Env) ([]*rules.Rule, error) {
	narrow, err := s.narrowing()
	if err != nil {
		return nil, err
	}
	if len(s.Suites) == 0 && len(s.Rules) == 0 {
		s.Suites = []string{DefaultSuite}
	}
	picked, err := s.union(env)
	if err != nil {
		return nil, err
	}
	picked = suite.Narrow(picked, narrow...)
	if len(picked) == 0 {
		return nil, ErrNoRules
	}
	return picked, nil
}

// filter returns the ids of the rules s selects for Test, which has no
// default suite: the union of its suites and rules, or every rule when it
// names none, narrowed by its filters. active is false for the zero
// Selection, which selects every rule.
func (s Selection) filter(env *suite.Env) (ids map[string]bool, active bool, err error) {
	narrow, err := s.narrowing()
	if err != nil {
		return nil, true, err
	}
	named := len(s.Suites) > 0 || len(s.Rules) > 0
	if !named && len(narrow) == 0 {
		return nil, false, nil
	}
	picked := allRules(env)
	if named {
		if picked, err = s.union(env); err != nil {
			return nil, true, err
		}
	}
	picked = suite.Narrow(picked, narrow...)
	if len(picked) == 0 {
		return nil, true, ErrNoRules
	}
	ids = map[string]bool{}
	for _, r := range picked {
		ids[r.ID] = true
	}
	return ids, true, nil
}

// union returns the rules that s's suites and rules select, sorted by id.
func (s Selection) union(env *suite.Env) ([]*rules.Rule, error) {
	var picked []*rules.Rule
	for _, name := range s.Suites {
		st, err := env.Load(name)
		if err != nil {
			return nil, err
		}
		rs, err := st.Select(env)
		if err != nil {
			return nil, err
		}
		picked = append(picked, rs...)
	}
	for _, id := range s.Rules {
		rs, err := ruleByID(env, id)
		if err != nil {
			return nil, err
		}
		picked = append(picked, rs...)
	}
	return dedupe(picked), nil
}

// ruleByID selects the rules whose qualified id is id, ends in "."+id, or
// matches /regex/.
func ruleByID(env *suite.Env, id string) ([]*rules.Rule, error) {
	f, err := idFilter(id)
	if err != nil {
		return nil, err
	}
	rs := suite.Narrow(allRules(env), f)
	if len(rs) == 0 {
		return nil, &SelectionError{Kind: "rule", Value: id, Err: ErrNoRules}
	}
	return rs, nil
}

// idFilter returns the filter that the Rules entry id stands for.
func idFilter(id string) (*suite.Suite, error) {
	pattern := id
	if !(len(id) >= 2 && strings.HasPrefix(id, "/") && strings.HasSuffix(id, "/")) {
		pattern = `/(^|\.)` + regexp.QuoteMeta(id) + `$/`
	}
	f, err := suite.Filter(true, "id", pattern)
	if err != nil {
		return nil, &SelectionError{Kind: "rule", Value: id, Err: err}
	}
	return f, nil
}

// allRules returns every rule in env, by rule set name.
func allRules(env *suite.Env) []*rules.Rule {
	var all []*rules.Rule
	for _, set := range slices.Sorted(maps.Keys(env.Sets)) {
		all = append(all, env.Sets[set]...)
	}
	return all
}

func dedupe(rs []*rules.Rule) []*rules.Rule {
	slices.SortFunc(rs, func(a, b *rules.Rule) int { return strings.Compare(a.ID, b.ID) })
	return slices.Compact(rs)
}
