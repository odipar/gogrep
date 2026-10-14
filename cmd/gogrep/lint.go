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
	"strconv"
	"strings"

	"github.com/odipar/gogrep"
)

// lintUsage is the help text of gogrep lint.
const lintUsage = `Usage:
  gogrep lint [--suite NAME] [--sarif] [path...]   check opengrep rule files

Paths are rule files and directories relative to, and inside, the current
directory (default opengrep/gogrep/rules). Every .yaml and .yml file below
them is linted, whatever .semgrepignore and .gitignore say, and a symlink as
the file inside the current directory that it leads to. The rule test
fixtures under opengrep/gogrep/rules/test are never linted. A rule file that
opengrep cannot parse is a problem of the check syntax-error.

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
// problems, but rule files that opengrep cannot parse are. The rule files of
// the summary are those Lint scanned, and any other file that a problem is
// in.
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
	// Lint's errors for these name no current directory, and its error for
	// a missing path is a stat error.
	for _, p := range paths {
		if !filepath.IsLocal(p) {
			fmt.Fprintf(c.stderr, "gogrep: %q is not a relative path inside the current directory\n", p)
			return 2
		}
		if _, err := os.Stat(filepath.Join(c.dir, p)); errors.Is(err, fs.ErrNotExist) {
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
	var notes []gogrep.Diagnostic
	for _, d := range res.Diagnostics {
		if f, ok := syntaxError(d, res.Files); ok {
			problems = append(problems, f)
		} else {
			notes = append(notes, d)
		}
	}
	code := 0
	if len(problems) > 0 {
		code = 1
	}
	if a.sarif {
		c.stdout.Write(res.SARIF)
		return code
	}
	files := map[string]bool{}
	for _, f := range res.Files {
		files[f] = true
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
	for _, d := range notes {
		fmt.Fprintf(c.stderr, "gogrep: opengrep: %s\n", oneLine(d.Message))
	}
	if len(problems) == 0 {
		fmt.Fprintf(c.stderr, "No problems in %s.\n", count(len(files), "rule file"))
	} else {
		fmt.Fprintf(c.stderr, "%s in %d of %s.\n", count(len(problems), "problem"), len(withProblems), count(len(files), "rule file"))
	}
	return code
}

// syntaxErrorIDs are the ids of opengrep's notifications that it could not
// parse a file.
var syntaxErrorIDs = []string{"Syntax error", "Other syntax error", "Lexical error"}

// syntaxError returns, as a problem of the check syntax-error, the
// diagnostic d when it reports that opengrep could not parse one of the rule
// files: "<kind> at line <file>:<line>: <message>". The problem is at that
// line, or line 1, and its message is the rest of d's.
func syntaxError(d gogrep.Diagnostic, files []string) (gogrep.Finding, bool) {
	_, loc, ok := strings.Cut(d.Message, " at line ")
	if !ok || !slices.Contains(syntaxErrorIDs, d.ID) {
		return gogrep.Finding{}, false
	}
	var file, rest string
	for _, f := range files {
		for _, name := range []string{f, filepath.FromSlash(f)} {
			if after, ok := strings.CutPrefix(loc, name+":"); ok && len(f) > len(file) {
				file, rest = f, after
			}
		}
	}
	if file == "" {
		return gogrep.Finding{}, false
	}
	digits := rest[:len(rest)-len(strings.TrimLeft(rest, "0123456789"))]
	line, err := strconv.Atoi(digits)
	if err != nil || line < 1 {
		line = 1
	}
	msg := oneLine(strings.TrimPrefix(rest[len(digits):], ":"))
	if msg == "" {
		msg = oneLine(d.Message)
	}
	return gogrep.Finding{RuleID: "syntax-error", Level: "error", Message: msg, Path: file, StartLine: line, StartColumn: 1}, true
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
