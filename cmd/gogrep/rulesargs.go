package gogrep

import (
	"errors"
	"fmt"
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

var errNoRules = errors.New("the --suite/--rule/--gogrep-* selection matches no rules")

// explain words the engine's selection errors as gogrep does: in terms of
// its flags, and saying how to list what they take; and a missing test root
// in terms of the current directory.
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
	case errors.Is(err, engine.ErrNoTestRoot):
		return fmt.Errorf("no %s directory here; run gogrep test from the project root", engine.ProjectTestsDir)
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
