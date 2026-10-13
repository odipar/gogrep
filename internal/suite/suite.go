// Package suite selects rules with query suites modelled on CodeQL's .qls
// files: a YAML list of instructions that locate rules (rules, import) and
// then filter them on their metadata (include, exclude). suites/README.md
// documents the format.
//
// As in CodeQL, the first filter that applies to a rule sets its default: a
// rule is kept only if an include matches it when that first filter is an
// include, and kept unless excluded when it is an exclude. Later filters
// override earlier ones. Filters apply to rules located before them, so rules
// located after the last filter are all selected. Values match fields
// case-insensitively; a field with several values (languages, cwe, ...)
// matches if any value does, and "<field> contain all" requires every listed
// value to match.
package suite

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/odipar/gogrep/internal/rules"
)

// A Suite is a parsed suite file.
type Suite struct {
	Name        string
	Description string
	steps       []step
}

type step struct {
	locate  []string // rule set or group names
	imports string   // suite name
	filter  *filter
	include bool
}

// A filter matches rules on which all its conditions hold.
type filter []cond

type cond struct {
	field  string
	all    bool // "<field> contain all"
	values []matcher
}

type matcher struct {
	s  string
	re *regexp.Regexp
}

// Parse reads a suite file; name is used in errors and listings.
func Parse(name string, data []byte) (*Suite, error) {
	var doc []map[string]yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("suite %s: %w", name, err)
	}
	s := &Suite{Name: name}
	for i, item := range doc {
		if len(item) != 1 {
			return nil, fmt.Errorf("suite %s: instruction %d must have exactly one key", name, i+1)
		}
		for key, n := range item {
			if err := s.add(key, &n); err != nil {
				return nil, fmt.Errorf("suite %s: instruction %d (%s): %w", name, i+1, key, err)
			}
		}
	}
	return s, nil
}

func (s *Suite) add(key string, n *yaml.Node) error {
	switch key {
	case "description":
		s.Description = n.Value
	case "rules":
		names, err := strings1(n)
		if err != nil {
			return err
		}
		s.steps = append(s.steps, step{locate: names})
	case "import":
		if n.Kind != yaml.ScalarNode || n.Value == "" {
			return fmt.Errorf("want a suite name")
		}
		s.steps = append(s.steps, step{imports: n.Value})
	case "include", "exclude":
		f, err := parseFilter(n)
		if err != nil {
			return err
		}
		s.steps = append(s.steps, step{filter: &f, include: key == "include"})
	default:
		return fmt.Errorf("unknown instruction; want description, rules, import, include or exclude")
	}
	return nil
}

func parseFilter(n *yaml.Node) (filter, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("want a mapping of field: value(s)")
	}
	var f filter
	for i := 0; i+1 < len(n.Content); i += 2 {
		field, all := n.Content[i].Value, false
		if base, ok := strings.CutSuffix(field, " contain all"); ok {
			field, all = base, true
		}
		vals, err := strings1(n.Content[i+1])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		c := cond{field: field, all: all}
		for _, v := range vals {
			m, err := newMatcher(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", field, err)
			}
			c.values = append(c.values, m)
		}
		f = append(f, c)
	}
	return f, nil
}

// strings1 reads a scalar or a list of scalars.
func strings1(n *yaml.Node) ([]string, error) {
	switch n.Kind {
	case yaml.ScalarNode:
		return []string{n.Value}, nil
	case yaml.SequenceNode:
		var vs []string
		for _, c := range n.Content {
			if c.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("want a value or a list of values")
			}
			vs = append(vs, c.Value)
		}
		return vs, nil
	}
	return nil, fmt.Errorf("want a value or a list of values")
}

// newMatcher compiles "/re/" as a regular expression and anything else as a
// literal.
func newMatcher(v string) (matcher, error) {
	if len(v) >= 2 && strings.HasPrefix(v, "/") && strings.HasSuffix(v, "/") {
		re, err := regexp.Compile(v[1 : len(v)-1])
		return matcher{re: re}, err
	}
	return matcher{s: v}, nil
}

// Filter returns a one-filter suite that includes (or excludes) rules whose
// field matches one of values ("/re/" for a regex). It is for building
// selections such as --rule in code; use it with Narrow.
func Filter(include bool, field string, values ...string) (*Suite, error) {
	c := cond{field: field}
	for _, v := range values {
		m, err := newMatcher(v)
		if err != nil {
			return nil, err
		}
		c.values = append(c.values, m)
	}
	return &Suite{steps: []step{{filter: &filter{c}, include: include}}}, nil
}

func (m matcher) match(s string) bool {
	if m.re != nil {
		return m.re.MatchString(s)
	}
	return strings.EqualFold(m.s, s)
}

func (f filter) match(r *rules.Rule) bool {
	fields := r.Fields()
	for _, c := range f {
		have := fields[c.field]
		hit := func(m matcher) bool { return slices.ContainsFunc(have, m.match) }
		if c.all && !all(c.values, hit) || !c.all && !slices.ContainsFunc(c.values, hit) {
			return false
		}
	}
	return true
}

func all[T any](xs []T, f func(T) bool) bool {
	for _, x := range xs {
		if !f(x) {
			return false
		}
	}
	return true
}

// An Env is what suites are evaluated against.
type Env struct {
	Sets   map[string][]*rules.Rule // rules by set name
	Groups map[string][]string      // group name -> set names, e.g. "bundled"
	Load   func(name string) (*Suite, error)
}

// Count returns the number of rules in env.
func (env *Env) Count() int {
	n := 0
	for _, rs := range env.Sets {
		n += len(rs)
	}
	return n
}

// Select returns the rules s selects in env, sorted by ID.
func (s *Suite) Select(env *Env) ([]*rules.Rule, error) {
	return s.selectRules(env, nil)
}

type state struct {
	order    []*rules.Rule
	selected map[*rules.Rule]bool
	filtered map[*rules.Rule]bool // some filter has set the rule's default
}

func (st *state) locate(r *rules.Rule) {
	if _, ok := st.selected[r]; !ok {
		st.order = append(st.order, r)
	}
	st.selected[r], st.filtered[r] = true, false
}

func (s *Suite) selectRules(env *Env, stack []string) ([]*rules.Rule, error) {
	if slices.Contains(stack, s.Name) && s.Name != "" {
		return nil, fmt.Errorf("suite import cycle: %s", strings.Join(append(stack, s.Name), " -> "))
	}
	stack = append(stack, s.Name)
	st := &state{selected: map[*rules.Rule]bool{}, filtered: map[*rules.Rule]bool{}}
	for _, step := range s.steps {
		switch {
		case step.locate != nil:
			for _, name := range step.locate {
				sets := []string{name}
				if g, ok := env.Groups[name]; ok {
					sets = g
				} else if _, ok := env.Sets[name]; !ok {
					return nil, fmt.Errorf("suite %s: unknown rule set %q", s.Name, name)
				}
				for _, set := range sets {
					for _, r := range env.Sets[set] {
						st.locate(r)
					}
				}
			}
		case step.imports != "":
			sub, err := env.Load(step.imports)
			if err != nil {
				return nil, fmt.Errorf("suite %s: %w", s.Name, err)
			}
			rs, err := sub.selectRules(env, stack)
			if err != nil {
				return nil, err
			}
			for _, r := range rs {
				st.locate(r)
			}
		case step.filter != nil:
			for _, r := range st.order {
				m := step.filter.match(r)
				if !st.filtered[r] {
					st.filtered[r] = true
					st.selected[r] = m == step.include
				} else if m {
					st.selected[r] = step.include
				}
			}
		}
	}
	var out []*rules.Rule
	for _, r := range st.order {
		if st.selected[r] {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b *rules.Rule) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// Narrow returns the rules in rs that every filter in fs selects, treating
// each as an include over rs.
func Narrow(rs []*rules.Rule, fs ...*Suite) []*rules.Rule {
	return slices.DeleteFunc(slices.Clone(rs), func(r *rules.Rule) bool {
		for _, s := range fs {
			for _, st := range s.steps {
				if st.filter != nil && st.filter.match(r) != st.include {
					return true
				}
			}
		}
		return false
	})
}
