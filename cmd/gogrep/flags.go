package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/odipar/gogrep"
)

// bundledConfig is the --config value that selects the bundled rules.
const bundledConfig = "bundled"

// selection is how gogrep's own flags select rules.
type selection struct {
	gogrep.Selection
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
			f := gogrep.Filter{Field: field, Values: vals}
			var se *gogrep.SelectionError
			if err := (gogrep.Selection{Filters: []gogrep.Filter{f}}).Validate(); errors.As(err, &se) {
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
	var se *gogrep.SelectionError
	switch {
	case errors.As(err, &se) && se.Kind == "rule":
		if se.Err == gogrep.ErrNoRules {
			return fmt.Errorf("--rule %s matches no rule; list them with: gogrep rules --suite all", se.Value)
		}
		return fmt.Errorf("--rule %s: %w", se.Value, se.Err)
	case errors.Is(err, gogrep.ErrUnknownSuite):
		return fmt.Errorf("%w; list them with: gogrep suites", err)
	case errors.Is(err, gogrep.ErrNoRules):
		return errNoRules
	case errors.Is(err, gogrep.ErrNoTestRoot):
		return fmt.Errorf("no %s directory here; run gogrep test from the project root", gogrep.ProjectTestsDir)
	}
	return err
}
