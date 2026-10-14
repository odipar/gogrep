package main

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/odipar/gogrep"
)

// lintUsage is the help text of gogrep lint.
const lintUsage = `Usage:
  gogrep lint [--suite NAME] [--sarif] [path...]   check opengrep rule files

Paths are rule files and directories relative to the current directory
(default opengrep/gogrep/rules). The rule test fixtures under
opengrep/gogrep/rules/test are never linted.

Flags:
  --suite NAME   lint with suite NAME (default rule-lint); a project suite of
                 that name overrides the built-in one
  --sarif        print the SARIF log instead of the problems and summary

Exit codes: 0 no problems, 1 problems found, 2 usage or setup error, 130 interrupted.
`

// lintArgs are the arguments of gogrep lint, without gogrep's own flags.
type lintArgs struct {
	help  bool
	sarif bool
	paths []string
}

// parseLintArgs parses the arguments that follow "lint". Flags may come
// before or after paths; opengrep's flags are not accepted, since gogrep lint
// runs opengrep itself.
func parseLintArgs(args []string) (lintArgs, error) {
	var a lintArgs
	for _, arg := range args {
		switch {
		case !strings.HasPrefix(arg, "-"):
			a.paths = append(a.paths, arg)
		case arg == "-h" || arg == "--help":
			a.help = true
		case arg == "--sarif":
			a.sarif = true
		default:
			return a, fmt.Errorf("unknown flag %s; gogrep lint does not forward flags to opengrep", arg)
		}
	}
	return a, nil
}

// lintSuite returns the suite that gogrep's own flags give gogrep lint: the
// one --suite names, or "" for gogrep.LintSuite.
func lintSuite(sel selection) (string, error) {
	switch {
	case len(sel.Rules) > 0 || len(sel.Filters) > 0:
		return "", errors.New("gogrep lint takes --suite, not --rule or --gogrep-* flags")
	case sel.explicit && len(sel.Suites) != 1:
		return "", errors.New("gogrep lint takes one --suite NAME")
	case len(sel.Suites) == 1:
		return sel.Suites[0], nil
	}
	return "", nil
}

// runLint implements gogrep lint: it runs the lint suite on the rule files
// under the paths of args, prints the problems it finds and a summary, or
// the SARIF log, and returns the exit code. Suppressed findings are no
// problems. A file with a problem counts as a rule file even when it is not
// YAML, as with another suite.
func (c *cli) runLint(args []string, sel selection) int {
	a, err := parseLintArgs(args)
	var suite string
	if err == nil {
		suite, err = lintSuite(sel)
	}
	if err != nil {
		fmt.Fprintf(c.stderr, "gogrep: %v\n", err)
		return 2
	}
	if a.help {
		io.WriteString(c.stdout, lintUsage)
		return 0
	}
	paths := a.paths
	if len(paths) == 0 {
		if fi, err := os.Stat(filepath.Join(c.dir, filepath.FromSlash(gogrep.ProjectRulesDir))); err != nil || !fi.IsDir() {
			fmt.Fprintf(c.stderr, "gogrep: no %s here; name the rules to lint\n", gogrep.ProjectRulesDir)
			return 2
		}
		paths = []string{filepath.FromSlash(gogrep.ProjectRulesDir)}
	}
	// opengrep reports a missing path only once it has run, as exit code 2.
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(c.dir, p)); filepath.IsLocal(p) && errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(c.stderr, "gogrep: %s does not exist\n", p)
			return 2
		}
	}

	ctx, stop := interruptContext()
	defer stop()
	res, err := c.eng.Lint(ctx, c.dir, &gogrep.LintOptions{Paths: paths, Suite: suite})
	switch {
	case err != nil && ctx.Err() != nil:
		fmt.Fprintln(c.stderr, "gogrep: interrupted")
		return 130
	case err != nil:
		fmt.Fprintf(c.stderr, "gogrep: %v\n", explain(err))
		return 2
	}
	problems := slices.DeleteFunc(slices.Clone(res.Findings), func(f gogrep.Finding) bool { return f.Suppressed })
	code := 0
	if len(problems) > 0 {
		code = 1
	}
	if a.sarif {
		c.stdout.Write(res.SARIF)
		return code
	}
	files, err := ruleFiles(c.dir, paths)
	if err != nil {
		fmt.Fprintf(c.stderr, "gogrep: %v\n", err)
		return 2
	}
	slices.SortStableFunc(problems, func(x, y gogrep.Finding) int {
		return cmp.Or(strings.Compare(x.Path, y.Path), cmp.Compare(x.StartLine, y.StartLine),
			cmp.Compare(x.StartColumn, y.StartColumn), strings.Compare(x.RuleID, y.RuleID))
	})
	withProblems := map[string]bool{}
	for _, f := range problems {
		fmt.Fprintf(c.stdout, "%s:%d:%d: %s (%s): %s\n", f.Path, f.StartLine, f.StartColumn, f.RuleID, severity(f.Level), oneLine(f.Message))
		withProblems[path.Clean(f.Path)] = true
		files[path.Clean(f.Path)] = true
	}
	for _, d := range res.Diagnostics {
		fmt.Fprintf(c.stderr, "gogrep: opengrep: %s\n", oneLine(d.Message))
	}
	if len(problems) == 0 {
		fmt.Fprintf(c.stderr, "No problems in %s.\n", count(len(files), "rule file"))
	} else {
		fmt.Fprintf(c.stderr, "%s in %d of %s.\n", count(len(problems), "problem"), len(withProblems), count(len(files), "rule file"))
	}
	return code
}

// ruleFiles returns the rule files that a lint of paths in dir scans, as
// slash paths relative to dir: the .yaml and .yml files under the paths,
// outside the rule test fixtures. opengrep reports no files it scanned, so
// this is gogrep's count; it does not apply .semgrepignore or git's file
// list.
func ruleFiles(dir string, paths []string) (map[string]bool, error) {
	files := map[string]bool{}
	fixtures := strings.ToLower(gogrep.ProjectTestsDir)
	for _, p := range paths {
		err := filepath.WalkDir(filepath.Join(dir, p), func(name string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(dir, name)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if lower := strings.ToLower(rel); d.IsDir() && (lower == fixtures || strings.HasPrefix(lower, fixtures+"/")) {
				return filepath.SkipDir
			}
			if ext := path.Ext(rel); d.Type().IsRegular() && (ext == ".yaml" || ext == ".yml") {
				files[rel] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

// severity returns the opengrep severity that a finding's SARIF level stands
// for.
func severity(level string) string {
	if level == "note" {
		return "INFO"
	}
	return strings.ToUpper(level)
}

// oneLine returns s with every run of white space, line breaks included, made
// one space.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// count returns n and noun, in the plural unless n is 1.
func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
