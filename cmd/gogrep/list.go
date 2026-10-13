package main

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/odipar/gogrep"
)

// listRules implements `gogrep rules`: print the rules a selection picks, and
// their count to stderr.
func (c *cli) listRules(sel selection) error {
	if sel.empty() {
		return errNoRules
	}
	rs, err := c.eng.Rules(c.dir, &gogrep.RulesOptions{Selection: sel.Selection})
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
