package engine

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
)

// ids returns the ids of rs.
func ids(rs []Rule) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

// projectIDs returns the ids of the project rules in rs.
func projectIDs(rs []Rule) []string {
	return slices.DeleteFunc(ids(rs), func(id string) bool { return !strings.HasPrefix(id, "project.") })
}

// A project with a rule of its own and a suite that shadows the default one.
var shadowing = map[string]string{
	"opengrep/gogrep/rules/go/no-exec-command.yaml":  noExecRule,
	"opengrep/gogrep/rules/generic/todo-marker.yaml": rule("todo-marker", "generic"),
	"opengrep/gogrep/rules/test/go/x/rule.ref":       "no-exec-command\n",
	"opengrep/gogrep/suites/code-scanning.yaml":      "- description: Only the project's Go rules\n- rules: project\n- include:\n    languages: go\n",
	"opengrep/gogrep/suites/mine.yml":                "- description: Mine\n- rules: project\n",
	"opengrep/gogrep/suites/broken.yaml":             "- description: Unknown rule set\n- rules: nope\n",
	"elsewhere/local.yaml":                           "- import: mine\n",
}

func TestRules(t *testing.T) {
	t.Parallel()
	e := newEngine(t, Config{})
	dir := t.TempDir()
	writeTree(t, dir, shadowing)

	all, err := e.Rules("", &RulesOptions{Selection: Selection{Suites: []string{"all"}}})
	if err != nil || len(all) != 2121 {
		t.Fatalf("Rules of every rule without a project = %d rules, %v; want 2121", len(all), err)
	}
	if !slices.IsSortedFunc(all, func(a, b Rule) int { return strings.Compare(a.ID, b.ID) }) {
		t.Errorf("Rules are not sorted by ID")
	}
	byDefault, err := e.Rules("", nil)
	if err != nil || len(byDefault) == 0 || len(byDefault) >= len(all) {
		t.Errorf("Rules of the default suite = %d rules, %v; want some, but fewer than all", len(byDefault), err)
	}

	tests := []struct {
		name string
		opts *RulesOptions
		want []string // the project rules selected
	}{
		{"the project's default suite", nil, []string{"project.go.no-exec-command"}},
		{"a project suite file", &RulesOptions{Selection: Selection{Suites: []string{"opengrep/gogrep/suites/mine.yml"}}}, []string{"project.generic.todo-marker", "project.go.no-exec-command"}},
		{"a suite file relative to dir importing a project suite", &RulesOptions{Selection: Selection{Suites: []string{"elsewhere/local.yaml"}}}, []string{"project.generic.todo-marker", "project.go.no-exec-command"}},
		{"rules and suites unioned", &RulesOptions{Selection: Selection{Suites: []string{"mine"}, Rules: []string{"todo-marker"}}}, []string{"project.generic.todo-marker", "project.go.no-exec-command"}},
		{"filters narrow", &RulesOptions{Selection: Selection{Suites: []string{"all"}, Filters: []Filter{{Field: "ruleset", Values: []string{"project"}}, {Field: "languages", Values: []string{"generic"}}}}}, []string{"project.generic.todo-marker"}},
		{"no project rules", &RulesOptions{Selection: Selection{Suites: []string{"all"}}, NoProjectRules: true}, nil},
	}
	for _, tt := range tests {
		rs, err := e.Rules(dir, tt.opts)
		if err != nil || !slices.Equal(projectIDs(rs), tt.want) {
			t.Errorf("%s: Rules = project rules %q, %v; want %q", tt.name, projectIDs(rs), err, tt.want)
		}
	}

	// Without project rules, the default suite is the built-in one.
	rs, err := e.Rules(dir, &RulesOptions{NoProjectRules: true})
	if err != nil || !slices.Equal(ids(rs), ids(byDefault)) {
		t.Errorf("Rules without project rules = %d rules, %v; want the built-in default suite's %d", len(rs), err, len(byDefault))
	}
	if _, err := e.Rules(dir, &RulesOptions{Selection: Selection{Suites: []string{"mine"}}, NoProjectRules: true}); err == nil || err.Error() != `unknown suite "mine"` {
		t.Errorf("Rules of a project suite without project rules = %v, want an unknown suite", err)
	}

	for _, d := range []string{"relative", "."} {
		if _, err := e.Rules(d, nil); err == nil || err.Error() != fmt.Sprintf("directory %q is not an absolute path", d) {
			t.Errorf("Rules(%q) = %v, want an error", d, err)
		}
	}
	if _, err := e.Rules("", &RulesOptions{Selection: Selection{Suites: []string{"elsewhere/local.yaml"}}}); err == nil ||
		err.Error() != "suite file elsewhere/local.yaml is relative, and there is no project directory" {
		t.Errorf("Rules of a relative suite file without a directory = %v, want an error", err)
	}

	// The caller's copy.
	rs, _ = e.Rules(dir, nil)
	rs[0].Fields["id"][0] = "changed"
	if again, _ := e.Rules(dir, nil); again[0].Fields["id"][0] != again[0].ID {
		t.Errorf("changing a returned Rule changed the engine's: id field %q", again[0].Fields["id"][0])
	}
}

func TestSuites(t *testing.T) {
	t.Parallel()
	e := newEngine(t, Config{})
	dir := t.TempDir()
	writeTree(t, dir, shadowing)

	describe := func(suites []Suite) string {
		var b strings.Builder
		for _, s := range suites {
			fmt.Fprintf(&b, "%s %s %v %d %v %q\n", s.Name, s.Source, s.Default, s.Rules, s.Err, s.Description)
		}
		return b.String()
	}
	builtIn, err := e.Suites("", nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range builtIn {
		names = append(names, s.Name)
		if s.Source != "built-in" || s.Err != nil || s.Rules <= 0 || s.Default != (s.Name == DefaultSuite) {
			t.Errorf("built-in suite %s", describe([]Suite{s}))
		}
	}
	if want := []string{"all", "code-scanning", "security-and-quality", "security-extended"}; !slices.Equal(names, want) {
		t.Errorf("built-in suites = %q, want %q", names, want)
	}

	suites, err := e.Suites(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `all built-in false 2123 <nil> "Every bundled, gogrep and project rule"
broken project false -1 suite broken: unknown rule set "nope" "Unknown rule set"
code-scanning project true 1 <nil> "Only the project's Go rules"
mine project false 2 <nil> "Mine"
security-and-quality built-in false ` + fmt.Sprint(builtIn[2].Rules+2) + ` <nil> "` + builtIn[2].Description + `"
security-extended built-in false ` + fmt.Sprint(builtIn[3].Rules+2) + ` <nil> "` + builtIn[3].Description + `"
`
	if got := describe(suites); got != want {
		t.Errorf("Suites of a project =\n%s\nwant\n%s", got, want)
	}
	if again, err := e.Suites(dir, &SuitesOptions{NoProjectRules: true}); err != nil || describe(again) != describe(builtIn) {
		t.Errorf("Suites without project rules =\n%s\n%v\nwant the built-in ones", describe(again), err)
	}

	writeTree(t, dir, map[string]string{"opengrep/gogrep/suites/unparsable.yaml": "- [\n"})
	if _, err := e.Suites(dir, nil); err == nil || !strings.HasPrefix(err.Error(), "suite unparsable: yaml: ") {
		t.Errorf("Suites with an unparsable project suite = %v, want its error", err)
	}
}

// One Engine serves concurrent calls.
func TestConcurrentCalls(t *testing.T) {
	t.Parallel()
	e := newEngine(t, Config{})
	dir := t.TempDir()
	writeTree(t, dir, shadowing)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			var err error
			if i%2 == 0 {
				_, err = e.Rules(dir, &RulesOptions{Selection: Selection{Suites: []string{"all"}}})
			} else {
				_, err = e.Suites(dir, nil)
			}
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}
