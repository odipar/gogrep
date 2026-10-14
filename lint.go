package gogrep

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// LintSuite is the suite Lint runs by default: the rule-quality checks of
// opengrep-rules (its yaml.semgrep rules), for missing or invalid metadata,
// missing messages or languages, duplicate ids, and slow or unsatisfiable
// patterns.
const LintSuite = "rule-lint"

// maxLintTargetBytes caps the length of the rule file arguments of a lint on
// the system goos: below Windows' command-line limit of 32,767 characters, as
// for the samples of a rule test fixture, and well below ARG_MAX elsewhere
// (1 MiB on macOS, more on Linux).
func maxLintTargetBytes(goos string) int {
	if goos == "windows" {
		return 30000
	}
	return 200000
}

// noFilesLog is the SARIF log of a lint without rule files, which runs no
// opengrep: one complete run, without rules, results or notifications.
const noFilesLog = `{"version": "2.1.0", "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
"runs": [{"tool": {"driver": {"name": "opengrep", "rules": []}}, "invocations": [{"executionSuccessful": true, "toolExecutionNotifications": []}], "results": []}]}`

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

// A LintResult is what one lint found: the Result of its scan, and the rule
// files it scanned.
type LintResult struct {
	*Result

	// Files are the rule files that the lint scanned, as slash paths
	// relative to the directory, sorted bytewise. A symlinked rule file is
	// listed by the path it leads to, which opengrep scans and the findings
	// name.
	Files []string
}

// Lint runs the rule-quality checks of opts.Suite on the rule files under
// opts.Paths of dir and returns the result as Scan does: findings are not
// errors.
//
// Lint, not opengrep, picks the rule files: each path that is a .yaml or
// .yml file, and every such file below each path that is a directory. A
// symlink among them stands for the file inside dir that it leads to, which
// is how Files and the findings name it. opengrep scans exactly those
// files, as named targets, so neither .semgrepignore nor .gitignore nor
// opengrep's default ignores (test/, vendor/, node_modules/ and others) hide
// a rule file. Lint enters no symlinked directory below a path; a path that
// is one, or leads through one, is resolved as a symlinked file is. It never
// lints the rule test fixtures under ProjectTestsDir, in any letter case,
// whose samples may be YAML: it skips them, and a path inside them is an
// error. When there are no rule files, Lint runs no opengrep and returns a
// complete Result without findings, whose SARIF log has no rules.
//
// Findings include those that a nosemgrep comment suppresses, with
// Suppressed set; gogrep lint does not count them as problems.
//
// A rule file that opengrep cannot parse has no findings: it appears in
// Result.Diagnostics, as a syntax error ("Other syntax error at line
// <file>:<line>: ..."). gogrep lint counts that as a problem. Unlike Scan,
// Lint is not stopped by a project rule file that does not parse: it leaves
// the file out of the project rules, and lints it.
//
// Errors are Scan's, plus plain errors for a path that is not a relative
// path inside dir, does not exist, lies in ProjectTestsDir or is a file but
// not a rule file; for a directory below a path that cannot be read; for a
// symlink that leads outside dir; for more rule files than opengrep's
// command line holds (30,000 bytes of paths on Windows, 200,000
// elsewhere); and one naming
// ProjectRulesDir when no paths are given and dir has none.
func (e *Engine) Lint(ctx context.Context, dir string, opts *LintOptions) (*LintResult, error) {
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
		if inFixtures(p, ProjectTestsDir) {
			return nil, fmt.Errorf("%s holds rule test fixtures, which are not linted", p)
		}
	}
	files, err := ruleFiles(dir, paths)
	if err != nil {
		return nil, err
	}
	targets, size := make([]string, len(files)), 0
	for i, f := range files {
		targets[i] = filepath.FromSlash(f)
		size += len(f) + 1 // and a separator
	}
	if size > maxLintTargetBytes(runtime.GOOS) {
		return nil, fmt.Errorf("too many rule files (%d) for one opengrep command line; lint subdirectories separately", len(files))
	}

	sel := Selection{Suites: []string{cmp.Or(opts.Suite, LintSuite)}}
	if len(files) == 0 {
		env, err := e.loadEnv(dir, false, true)
		if err != nil {
			return nil, err
		}
		selected, err := sel.resolve(env)
		if err != nil {
			return nil, err
		}
		res, err := result([]byte(noFilesLog), len(selected), nil)
		if err != nil {
			return nil, err
		}
		return &LintResult{Result: res}, nil
	}
	res, err := e.Scan(ctx, dir, &ScanOptions{Selection: sel, Targets: targets, Stderr: opts.Stderr, skipBrokenProject: true})
	if err != nil {
		return nil, err
	}
	return &LintResult{Result: res, Files: files}, nil
}

// ruleFiles returns the rule files that a lint of paths in dir scans, as
// Lint describes them: slash paths relative to dir, sorted.
func ruleFiles(dir string, paths []string) ([]string, error) {
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	// resolve returns the slash path, relative to dir, of the file that the
	// file name in dir is or leads to through symlinks, and whether that
	// lies inside dir.
	resolve := func(name string) (string, bool, error) {
		target, err := filepath.EvalSymlinks(name)
		if err != nil {
			return "", false, err
		}
		rel, err := filepath.Rel(realDir, target)
		return filepath.ToSlash(rel), err == nil && filepath.IsLocal(rel), nil
	}
	// The fixtures are where ProjectRulesDir leads too, when it is a
	// symlink inside dir.
	fixtures := []string{ProjectTestsDir}
	if rel, ok, err := resolve(filepath.Join(dir, filepath.FromSlash(ProjectRulesDir))); err == nil && ok && rel != ProjectRulesDir {
		fixtures = append(fixtures, path.Join(rel, testsDir))
	}

	files := map[string]bool{}
	for _, p := range paths {
		if inFixtures(p, fixtures...) {
			return nil, fmt.Errorf("%s holds rule test fixtures, which are not linted", p)
		}
		name := filepath.Join(dir, p)
		fi, err := os.Stat(name)
		if err != nil {
			return nil, renamed(err, p)
		}
		root, ok, err := resolve(name)
		switch {
		case err != nil:
			return nil, renamed(err, p)
		case !ok:
			return nil, fmt.Errorf("%s leads outside the directory through a symlink", p)
		case inFixtures(root, fixtures...):
			return nil, fmt.Errorf("%s holds rule test fixtures, which are not linted", p)
		case fi.IsDir():
		case !fi.Mode().IsRegular():
			return nil, fmt.Errorf("%s is not a regular file", p)
		case isRuleFile(root):
			files[root] = true
			continue
		case isRuleFile(filepath.ToSlash(p)):
			return nil, fmt.Errorf("%s leads to %s, which is not a .yaml or .yml file", p, root)
		default:
			return nil, fmt.Errorf("%s is not a rule file (.yaml or .yml)", p)
		}

		logical, walked := path.Clean(filepath.ToSlash(p)), filepath.Join(dir, filepath.FromSlash(root))
		err = filepath.WalkDir(walked, func(name string, d fs.DirEntry, err error) error {
			sub, relErr := filepath.Rel(walked, name)
			if relErr != nil {
				return relErr
			}
			sub = filepath.ToSlash(sub)
			rel := path.Join(root, sub)
			switch {
			case err != nil:
				return renamed(err, rel)
			case d.IsDir() && (inFixtures(rel, fixtures...) || inFixtures(path.Join(logical, sub), fixtures...)):
				return filepath.SkipDir
			case d.IsDir() || !isRuleFile(rel):
				return nil
			case d.Type().IsRegular():
				files[rel] = true
				return nil
			case d.Type()&fs.ModeSymlink == 0:
				return nil // a device or a pipe, which could be endless
			}
			fi, err := os.Stat(name)
			if err != nil {
				return renamed(err, rel)
			}
			if !fi.Mode().IsRegular() {
				return nil // a symlinked directory is not entered
			}
			target, ok, err := resolve(name)
			switch {
			case err != nil:
				return renamed(err, rel)
			case !ok:
				return fmt.Errorf("%s leads outside the directory through a symlink", rel)
			case !isRuleFile(target):
				return fmt.Errorf("%s leads to %s, which is not a .yaml or .yml file", rel, target)
			}
			files[target] = true
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return slices.Sorted(maps.Keys(files)), nil
}

// isRuleFile reports whether the file p is named as a rule file: .yaml or
// .yml, as gogrep loads rules and opengrep scans YAML.
func isRuleFile(p string) bool {
	ext := path.Ext(p)
	return ext == ".yaml" || ext == ".yml"
}

// renamed returns err, an error about a file, with the file named p.
func renamed(err error, p string) error {
	if pe, ok := err.(*fs.PathError); ok {
		return &fs.PathError{Op: pe.Op, Path: p, Err: pe.Err}
	}
	return err
}

// inFixtures reports whether the relative path p lies in one of the
// fixture roots, in any letter case, as the test root is reserved in any
// letter case, also when it is a nested project's: a root that p's path
// contains as whole elements, as in testdata/project/opengrep/gogrep/rules/test.
func inFixtures(p string, roots ...string) bool {
	p = "/" + strings.ToLower(path.Clean(filepath.ToSlash(p))) + "/"
	return slices.ContainsFunc(roots, func(root string) bool {
		return strings.Contains(p, "/"+strings.ToLower(root)+"/")
	})
}
