package gogrep

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/odipar/gogrep/internal/engine"
)

// bundledConfig is the --config value that selects the bundled rules.
const bundledConfig = "bundled"

// selection is how gogrep's own flags select rules.
type selection struct {
	engine.Selection
	explicit bool // --suite or --rule given
}

// empty reports whether sel is --suite or --rule given without a value, and
// no other: it selects no rules, where the engine's zero Selection selects
// the default suite.
func (sel selection) empty() bool {
	return sel.explicit && len(sel.Suites) == 0 && len(sel.Rules) == 0
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
			sel.Suites, sel.explicit = append(sel.Suites, vals...), true
		case "--rule":
			sel.Rules, sel.explicit = append(sel.Rules, vals...), true
		default:
			f := engine.Filter{Field: field, Values: vals}
			var se *engine.SelectionError
			if err := (engine.Selection{Filters: []engine.Filter{f}}).Validate(); errors.As(err, &se) {
				return nil, sel, fmt.Errorf("%s: %w", name, se.Err)
			}
			sel.Filters = append(sel.Filters, f)
		}
	}
	return rest, sel, nil
}

// withRules points a scan at the selected bundled rules when it names no
// rules itself (no --config, -e/--pattern or $SEMGREP_RULES), when it uses
// --config bundled, or when --suite or --rule is given. The selection goes to
// opengrep as one generated config with stable rule ids, the scan makes no
// version check, whatever $OPENGREP_ENABLE_VERSION_CHECK says, and it skips
// the project's rule test fixtures: a project .semgrepignore replaces
// opengrep's default exclusion of test/ directories.
func (c *cli) withRules(args []string, sel selection) ([]string, error) {
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

	if sel.empty() {
		return nil, errNoRules
	}
	file, err := c.eng.SelectionFile(c.dir, sel.Selection, false)
	if err != nil {
		return nil, err
	}
	// Insert right after "scan": after a user's "--" they would be targets.
	own := []string{"--config", file, "--no-rewrite-rule-ids", "--disable-version-check", "--exclude=" + engine.ProjectTestsDir}
	return slices.Concat(out[:1], own, out[1:]), nil
}

var errNoRules = errors.New("the --suite/--rule/--gogrep-* selection matches no rules")

// explain words the engine's selection errors as gogrep does: in terms of
// its flags, and saying how to list what they take.
func explain(err error) error {
	var se *engine.SelectionError
	switch {
	case errors.As(err, &se) && se.Kind == "rule":
		if se.Err == engine.ErrNoRules {
			return fmt.Errorf("--rule %s matches no rule; list them with: gogrep rules --suite all", se.Value)
		}
		return fmt.Errorf("--rule %s: %w", se.Value, se.Err)
	case errors.Is(err, engine.ErrUnknownSuite):
		return fmt.Errorf("%w; list them with: gogrep suites", err)
	case errors.Is(err, engine.ErrNoRules):
		return errNoRules
	}
	return err
}

// listRules implements `gogrep rules`: print the rules a selection picks, and
// their count to stderr.
func (c *cli) listRules(sel selection) error {
	if sel.empty() {
		return errNoRules
	}
	rs, err := c.eng.Rules(c.dir, &engine.RulesOptions{Selection: sel.Selection})
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tCATEGORY\tCONFIDENCE\tLANGUAGES")
	for _, r := range rs {
		get := func(k string) string {
			if v := strings.Join(r.Fields[k], ","); v != "" {
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
		fmt.Fprintln(c.stderr, "1 rule")
	} else {
		fmt.Fprintf(c.stderr, "%d rules\n", len(rs))
	}
	return nil
}

// listSuites implements `gogrep suites`: print the available suites.
func (c *cli) listSuites() error {
	suites, err := c.eng.Suites(c.dir, nil)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SUITE\tSOURCE\tRULES\tDESCRIPTION")
	for _, s := range suites {
		name, count := s.Name, "-"
		if s.Default {
			name += " (default)"
		}
		if s.Err == nil {
			count = fmt.Sprint(s.Rules)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, s.Source, count, s.Description)
	}
	return tw.Flush()
}
