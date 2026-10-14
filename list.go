package gogrep

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// A Rule is one rule an Engine can run. It is the caller's copy.
type Rule struct {
	ID     string              // stable qualified id <set>.<dir>.<id>
	Set    string              // "opengrep-rules", "0xdea", "semgrep-go", "gogrep" or "project"
	Path   string              // the rule file, a slash path within its set
	Fields map[string][]string // the values Filters and suites match on (see Filter)
}

// RulesOptions configure Engine.Rules; nil means the zero RulesOptions.
type RulesOptions struct {
	Selection
	NoProjectRules bool // as in ScanOptions
}

// Rules returns the rules opts selects, sorted by ID: the rules that a Scan
// of dir with the same options runs. dir is the absolute project directory
// whose opengrep/gogrep rules and suites take part, or "" for none (a
// relative suite file is then an error); a dir that is relative, missing or
// not a directory is an error that names it. Rules runs no opengrep.
func (e *Engine) Rules(dir string, opts *RulesOptions) ([]Rule, error) {
	if opts == nil {
		opts = &RulesOptions{}
	}
	if err := checkDir(dir, true); err != nil {
		return nil, err
	}
	env, err := e.loadEnv(dir, opts.NoProjectRules, false)
	if err != nil {
		return nil, err
	}
	rs, err := opts.Selection.resolve(env)
	if err != nil {
		return nil, err
	}
	out := make([]Rule, len(rs))
	for i, r := range rs {
		fields := maps.Clone(r.Fields())
		for k, vs := range fields {
			fields[k] = slices.Clone(vs)
		}
		out[i] = Rule{ID: r.ID, Set: r.Set, Path: r.Path, Fields: fields}
	}
	return out, nil
}

// A Suite is one suite that Selection.Suites can name.
type Suite struct {
	Name        string
	Source      string // "built-in", or "project" for one in ProjectSuitesDir, which shadows a built-in suite of that name
	Description string
	Default     bool  // Name is DefaultSuite
	Rules       int   // how many rules it selects; -1 when Err is set
	Err         error // why it cannot select rules, such as an unknown rule set
}

// SuitesOptions configure Engine.Suites; nil means the zero SuitesOptions.
type SuitesOptions struct {
	NoProjectRules bool // list only built-in suites, and count without project rules
}

// Suites returns the built-in suites and those of the project in dir ("" for
// none), sorted by name. A dir that is relative, missing or not a
// directory is an error that names it, and so is a suite file that cannot
// be read or parsed; one that parses but cannot select rules has Err set.
func (e *Engine) Suites(dir string, opts *SuitesOptions) ([]Suite, error) {
	if opts == nil {
		opts = &SuitesOptions{}
	}
	if err := checkDir(dir, true); err != nil {
		return nil, err
	}
	sources := map[string]string{}
	entries, _ := fs.ReadDir(e.src.suites, ".")
	for _, d := range entries {
		if name, ok := strings.CutSuffix(d.Name(), ".yaml"); ok {
			sources[name] = "built-in"
		}
	}
	if dir != "" && !opts.NoProjectRules {
		suitesDir := filepath.Join(dir, filepath.FromSlash(ProjectSuitesDir))
		entries, _ = os.ReadDir(suitesDir)
		for _, d := range entries {
			if ext := filepath.Ext(d.Name()); (ext == ".yaml" || ext == ".yml") && regularFile(filepath.Join(suitesDir, d.Name())) {
				sources[strings.TrimSuffix(d.Name(), ext)] = "project"
			}
		}
	}
	env, err := e.loadEnv(dir, opts.NoProjectRules, false)
	if err != nil {
		return nil, err
	}
	var suites []Suite
	for _, name := range slices.Sorted(maps.Keys(sources)) {
		s, err := env.Load(name)
		if err != nil {
			return nil, err
		}
		n := -1
		rs, err := s.Select(env)
		if err == nil {
			n = len(rs)
		}
		suites = append(suites, Suite{Name: name, Source: sources[name], Description: s.Description, Default: name == DefaultSuite, Rules: n, Err: err})
	}
	return suites, nil
}
