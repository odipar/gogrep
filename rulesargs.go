package main

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/odipar/gogrep/internal/bundle"
	"github.com/odipar/gogrep/internal/rules"
)

// ownRules is the repo's rules directory, embedded in every build as the
// "gogrep" rule set.
//
//go:embed rules
var ownRules embed.FS

// projectRulesDir holds a project's own rules; scans using the bundled rules
// add it when it exists in the current directory.
var projectRulesDir = filepath.Join("opengrep", "gogrep", "rules")

// bundledConfig is the --config value that names the bundled rules explicitly.
const bundledConfig = "bundled"

// gogrepFlags removes gogrep's own flags from args and returns the rule filter
// they set. Each takes a comma-separated list and may be repeated:
//
//	--gogrep-ruleset  rule sets, e.g. opengrep-rules,gogrep
//	--gogrep-lang     languages (top-level rule directory), e.g. go,python
//	--gogrep-category metadata.category, e.g. security,correctness
func gogrepFlags(args []string) (rest []string, f rules.Filter, err error) {
	targets := map[string]*[]string{
		"--gogrep-ruleset":  &f.Sets,
		"--gogrep-lang":     &f.Langs,
		"--gogrep-category": &f.Categories,
	}
	for i := 0; i < len(args); i++ {
		name, val, hasVal := strings.Cut(args[i], "=")
		dst, ok := targets[name]
		if !ok {
			rest = append(rest, args[i])
			continue
		}
		if !hasVal {
			if i+1 == len(args) {
				return nil, f, fmt.Errorf("%s needs a value", name)
			}
			i++
			val = args[i]
		}
		for _, v := range strings.Split(val, ",") {
			if v = strings.TrimSpace(v); v != "" {
				*dst = append(*dst, v)
			}
		}
	}
	return rest, f, nil
}

// withRules points a scan at the bundled rules when it names no rules itself
// (no --config, -e/--pattern or $SEMGREP_RULES), and expands --config bundled.
// The bundled rules are the embedded rule sets that pass f plus, when present,
// the project's rules in projectRulesDir.
func withRules(args []string, f rules.Filter) ([]string, error) {
	if len(args) == 0 || args[0] != "scan" {
		return args, nil
	}

	var out []string
	explicit, useBundled := os.Getenv("SEMGREP_RULES") != "", false
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

	dirs, err := bundledRuleDirs(f)
	if err != nil {
		return nil, err
	}
	if len(dirs) == 0 {
		if useBundled {
			return nil, fmt.Errorf("no bundled rules match the --gogrep-* filters")
		}
		return args, nil // nothing bundled: let opengrep report the missing config
	}
	for _, d := range dirs {
		out = append(out, "--config", d)
	}
	return out, nil
}

func bundledRuleDirs(f rules.Filter) ([]string, error) {
	sets := map[string]rules.Set{}
	for name, archive := range bundle.RuleSets() {
		set, err := rules.FromTarGz(archive)
		if err != nil {
			return nil, fmt.Errorf("reading bundled rule set %s: %w", name, err)
		}
		sets[name] = set
	}
	own, err := fs.Sub(ownRules, "rules")
	if err != nil {
		return nil, err
	}
	if sets["gogrep"], err = rules.FromFS(own); err != nil {
		return nil, err
	}

	var dirs []string
	dir, n, err := rules.Dir(sets, f)
	if err != nil {
		return nil, fmt.Errorf("writing bundled rules: %w", err)
	}
	if n > 0 {
		dirs = append(dirs, dir)
	}
	if fi, err := os.Stat(projectRulesDir); err == nil && fi.IsDir() {
		dirs = append(dirs, projectRulesDir)
	}
	return dirs, nil
}
