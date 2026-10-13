package main

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/odipar/gogrep/internal/bundle"
	"github.com/odipar/gogrep/internal/rules"
	"github.com/odipar/gogrep/internal/suite"
)

// ownRules is the repo's rules directory, embedded in every build as the
// "gogrep" rule set.
//
//go:embed rules
var ownRules embed.FS

// builtinSuites are the suites shipped with gogrep, by file name without .yaml.
//
//go:embed suites/*.yaml
var builtinSuites embed.FS

// A project's own rules and suites live under opengrep/gogrep in the current
// directory. Project rules form the "project" rule set; a project suite
// shadows a built-in one of the same name. The rules directory's test/
// subdirectory holds rule test fixtures and is never loaded as rules.
var (
	projectRulesDir  = filepath.Join("opengrep", "gogrep", "rules")
	projectTestsDir  = filepath.Join(projectRulesDir, testsDir)
	projectSuitesDir = filepath.Join("opengrep", "gogrep", "suites")
)

const (
	defaultSuite  = "code-scanning"
	bundledConfig = "bundled" // --config value that selects the bundled rules
	testsDir      = "test"    // the directory of a rule set reserved for test fixtures
)

// selection is how gogrep's own flags select rules.
type selection struct {
	suites   []string       // --suite: names or paths, unioned
	rules    []string       // --rule: ids, id suffixes or /regex/, unioned
	narrow   []*suite.Suite // --gogrep-ruleset/-lang/-category, ANDed
	explicit bool           // --suite or --rule given
}

// gogrepFlags removes gogrep's own flags from args. --suite and --rule pick
// rules (default: the code-scanning suite); the --gogrep-* filters narrow
// that selection. All take comma-separated lists and may be repeated.
func gogrepFlags(args []string) (rest []string, sel selection, err error) {
	narrowField := map[string]string{
		"--gogrep-ruleset":  "ruleset",
		"--gogrep-lang":     "languages",
		"--gogrep-category": "category",
	}
	for i := 0; i < len(args); i++ {
		name, val, hasVal := strings.Cut(args[i], "=")
		field, isNarrow := narrowField[name]
		if name != "--suite" && name != "--rule" && !isNarrow {
			rest = append(rest, args[i])
			continue
		}
		if !hasVal {
			if i+1 == len(args) {
				return nil, sel, fmt.Errorf("%s needs a value", name)
			}
			i++
			val = args[i]
		}
		var vals []string
		for _, v := range strings.Split(val, ",") {
			if v = strings.TrimSpace(v); v != "" {
				vals = append(vals, v)
			}
		}
		switch name {
		case "--suite":
			sel.suites, sel.explicit = append(sel.suites, vals...), true
		case "--rule":
			sel.rules, sel.explicit = append(sel.rules, vals...), true
		default:
			f, err := suite.Filter(true, field, vals...)
			if err != nil {
				return nil, sel, fmt.Errorf("%s: %w", name, err)
			}
			sel.narrow = append(sel.narrow, f)
		}
	}
	return rest, sel, nil
}

// withRules points a scan at the selected bundled rules when it names no
// rules itself (no --config, -e/--pattern or $SEMGREP_RULES), when it uses
// --config bundled, or when --suite or --rule is given. The selection goes to
// opengrep as one generated config with stable rule ids, and the scan skips
// the project's rule test fixtures: a project .semgrepignore replaces
// opengrep's default exclusion of test/ directories.
func withRules(args []string, sel selection) ([]string, error) {
	if len(args) == 0 || args[0] != "scan" {
		return args, nil
	}

	var out []string
	explicit, useBundled := os.Getenv("SEMGREP_RULES") != "", sel.explicit
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c" || a == "-f" || a == "--config":
			explicit = true
			if i+1 < len(args) && args[i+1] == bundledConfig {
				useBundled = true
				i++
				continue
			}
		case a == "--config="+bundledConfig:
			explicit, useBundled = true, true
			continue
		case strings.HasPrefix(a, "--config=") || a == "-e" || a == "--pattern" || strings.HasPrefix(a, "--pattern="):
			explicit = true
		}
		out = append(out, a)
	}
	if explicit && !useBundled {
		return args, nil
	}

	env, err := loadEnv()
	if err != nil {
		return nil, err
	}
	if env.Count() == 0 {
		if useBundled {
			return nil, errors.New("this gogrep build has no bundled rules")
		}
		return args, nil // nothing bundled: leave the scan to opengrep
	}
	selected, err := sel.resolve(env)
	if err != nil {
		return nil, err
	}
	file, err := rules.Write(selected)
	if err != nil {
		return nil, fmt.Errorf("writing selected rules: %w", err)
	}
	// Insert right after "scan": after a user's "--" they would be targets.
	own := []string{"--config", file, "--no-rewrite-rule-ids", "--exclude=" + filepath.ToSlash(projectTestsDir)}
	return slices.Concat(out[:1], own, out[1:]), nil
}

// resolve returns the rules sel selects: the union of its suites and rules
// (or the default suite), narrowed by its filters.
func (sel selection) resolve(env *suite.Env) ([]*rules.Rule, error) {
	var picked []*rules.Rule
	suites := sel.suites
	if !sel.explicit {
		suites = []string{defaultSuite}
	}
	for _, name := range suites {
		s, err := env.Load(name)
		if err != nil {
			return nil, err
		}
		rs, err := s.Select(env)
		if err != nil {
			return nil, err
		}
		picked = append(picked, rs...)
	}
	for _, id := range sel.rules {
		rs, err := ruleByID(env, id)
		if err != nil {
			return nil, err
		}
		picked = append(picked, rs...)
	}
	picked = suite.Narrow(dedupe(picked), sel.narrow...)
	if len(picked) == 0 {
		return nil, errors.New("the --suite/--rule/--gogrep-* selection matches no rules")
	}
	return picked, nil
}

// ruleByID selects rules whose qualified id is id, ends in "."+id, or
// matches /regex/.
func ruleByID(env *suite.Env, id string) ([]*rules.Rule, error) {
	pattern := id
	if !(len(id) >= 2 && strings.HasPrefix(id, "/") && strings.HasSuffix(id, "/")) {
		pattern = `/(^|\.)` + regexp.QuoteMeta(id) + `$/`
	}
	f, err := suite.Filter(true, "id", pattern)
	if err != nil {
		return nil, fmt.Errorf("--rule %s: %w", id, err)
	}
	var all []*rules.Rule
	for _, set := range slices.Sorted(maps.Keys(env.Sets)) {
		all = append(all, env.Sets[set]...)
	}
	rs := suite.Narrow(all, f)
	if len(rs) == 0 {
		return nil, fmt.Errorf("--rule %s matches no rule; list them with: gogrep rules --suite all", id)
	}
	return rs, nil
}

func dedupe(rs []*rules.Rule) []*rules.Rule {
	slices.SortFunc(rs, func(a, b *rules.Rule) int { return strings.Compare(a.ID, b.ID) })
	return slices.Compact(rs)
}

// loadEnv parses all rule sets: the bundled ones, gogrep's own and the
// project's, the last two without their test fixtures. Groups: "bundled" (the
// pinned third-party sets) and "all".
func loadEnv() (*suite.Env, error) {
	sets := map[string]rules.Set{}
	var bundled []string
	for name, archive := range bundle.RuleSets() {
		set, err := rules.FromTarGz(archive)
		if err != nil {
			return nil, fmt.Errorf("reading bundled rule set %s: %w", name, err)
		}
		sets[name] = set
		bundled = append(bundled, name)
	}
	own, err := fs.Sub(ownRules, "rules")
	if err != nil {
		return nil, err
	}
	if sets["gogrep"], err = rules.FromFS(own, testsDir); err != nil {
		return nil, err
	}
	sets["project"] = rules.Set{}
	if fi, err := os.Stat(projectRulesDir); err == nil && fi.IsDir() {
		if sets["project"], err = rules.FromFS(os.DirFS(projectRulesDir), testsDir); err != nil {
			return nil, fmt.Errorf("reading %s: %w", projectRulesDir, err)
		}
	}

	parsed, err := rules.Parse(sets)
	if err != nil {
		return nil, err
	}
	env := &suite.Env{
		Sets:   map[string][]*rules.Rule{},
		Groups: map[string][]string{"bundled": bundled, "all": slices.Collect(maps.Keys(sets))},
		Load:   loadSuite,
	}
	for name := range sets {
		env.Sets[name] = nil
	}
	for _, r := range parsed {
		env.Sets[r.Set] = append(env.Sets[r.Set], r)
	}
	return env, nil
}

// loadSuite finds a suite by file path, then in the project's suites, then
// among the built-in ones.
func loadSuite(name string) (*suite.Suite, error) {
	if strings.ContainsAny(name, `/\`) || strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		return suite.Parse(name, data)
	}
	for _, ext := range []string{".yaml", ".yml"} {
		if data, err := os.ReadFile(filepath.Join(projectSuitesDir, name+ext)); err == nil {
			return suite.Parse(name, data)
		}
	}
	if data, err := builtinSuites.ReadFile("suites/" + name + ".yaml"); err == nil {
		return suite.Parse(name, data)
	}
	return nil, fmt.Errorf("unknown suite %q; list them with: gogrep suites", name)
}

// listRules implements `gogrep rules`: print the rules a selection picks.
func listRules(w io.Writer, sel selection) error {
	env, err := loadEnv()
	if err != nil {
		return err
	}
	rs, err := sel.resolve(env)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tCATEGORY\tCONFIDENCE\tLANGUAGES")
	for _, r := range rs {
		f := r.Fields()
		get := func(k string) string {
			if v := strings.Join(f[k], ","); v != "" {
				return v
			}
			return "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, get("severity"), get("category"), get("confidence"), get("languages"))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(rs) == 1 {
		fmt.Fprintln(os.Stderr, "1 rule")
	} else {
		fmt.Fprintf(os.Stderr, "%d rules\n", len(rs))
	}
	return nil
}

// listSuites implements `gogrep suites`: print the available suites.
func listSuites(w io.Writer) error {
	names := map[string]string{}
	entries, _ := builtinSuites.ReadDir("suites")
	for _, e := range entries {
		names[strings.TrimSuffix(e.Name(), ".yaml")] = "built-in"
	}
	entries, _ = os.ReadDir(projectSuitesDir)
	for _, e := range entries {
		if ext := filepath.Ext(e.Name()); ext == ".yaml" || ext == ".yml" {
			names[strings.TrimSuffix(e.Name(), ext)] = "project"
		}
	}
	env, err := loadEnv()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SUITE\tSOURCE\tRULES\tDESCRIPTION")
	for _, name := range slices.Sorted(maps.Keys(names)) {
		s, err := loadSuite(name)
		if err != nil {
			return err
		}
		count := "-"
		if rs, err := s.Select(env); err == nil {
			count = fmt.Sprint(len(rs))
		}
		if name == defaultSuite {
			name += " (default)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, names[strings.TrimSuffix(name, " (default)")], count, s.Description)
	}
	return tw.Flush()
}
