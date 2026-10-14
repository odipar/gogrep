package gogrep

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// LintSuite is the suite Lint runs by default: the rule-quality checks of
// opengrep-rules (its yaml.semgrep rules), for missing or invalid metadata,
// missing messages or languages, duplicate ids, and slow or unsatisfiable
// patterns.
const LintSuite = "rule-lint"

// LintOptions are the options of Lint. The zero value lints
// ProjectRulesDir of the directory with LintSuite.
type LintOptions struct {
	// Paths are the files and directories to lint, relative to the
	// directory and inside it (filepath.IsLocal), as ScanOptions.Targets.
	// Empty means ProjectRulesDir.
	Paths []string

	// Suite is the lint suite; "" means LintSuite. A project suite of the
	// same name in the directory overrides the built-in one.
	Suite string

	// Stderr, if not nil, receives a live copy of opengrep's stderr, as in
	// ScanOptions.
	Stderr io.Writer
}

// Lint runs the rule-quality checks of opts.Suite on the rule files under
// opts.Paths of dir and returns the result as Scan does: findings are not
// errors. It never lints the rule test fixtures under ProjectTestsDir, whose
// samples may be YAML; a path inside it is an error.
//
// Errors are Scan's, plus plain errors for a path that is not a relative
// path inside dir or lies in ProjectTestsDir, and one naming ProjectRulesDir
// when no paths are given and dir has none.
func (e *Engine) Lint(ctx context.Context, dir string, opts *LintOptions) (*Result, error) {
	if opts == nil {
		opts = &LintOptions{}
	}
	if err := checkDir(dir, false); err != nil {
		return nil, err
	}
	paths := opts.Paths
	if len(paths) == 0 {
		if fi, err := os.Stat(filepath.Join(dir, filepath.FromSlash(ProjectRulesDir))); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("%s has no %s; name the rules to lint", dir, ProjectRulesDir)
		}
		paths = []string{filepath.FromSlash(ProjectRulesDir)}
	}
	for _, p := range paths {
		if !filepath.IsLocal(p) {
			return nil, fmt.Errorf("lint path %q is not a relative path inside the directory", p)
		}
		if inFixtures(p) {
			return nil, fmt.Errorf("%s holds rule test fixtures, which are not linted", p)
		}
	}
	suite := opts.Suite
	if suite == "" {
		suite = LintSuite
	}
	return e.Scan(ctx, dir, &ScanOptions{
		Selection: Selection{Suites: []string{suite}},
		Targets:   paths,
		Stderr:    opts.Stderr,
	})
}

// inFixtures reports whether the relative path p lies in ProjectTestsDir,
// in any letter case, as the test root is reserved in any letter case.
func inFixtures(p string) bool {
	p = strings.ToLower(path.Clean(filepath.ToSlash(p)))
	root := strings.ToLower(ProjectTestsDir)
	return p == root || strings.HasPrefix(p, root+"/")
}
