// Package engine is gogrep's Go API while it is being built: step 18 of
// docs/design/library-api.md moves it to the module root as package gogrep.
// Until then, New takes the files that the module root embeds as an
// argument.
package engine

import (
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/odipar/gogrep/internal/rules"
	"github.com/odipar/gogrep/internal/rulesets"
	"github.com/odipar/gogrep/internal/suite"
)

// DefaultSuite is the suite that Scan, Rules and Command run when a
// Selection names no suites and no rules.
const DefaultSuite = "code-scanning"

// Slash paths, relative to a project directory, of what gogrep reads there.
const (
	ProjectRulesDir  = "opengrep/gogrep/rules"      // the "project" rule set
	ProjectTestsDir  = "opengrep/gogrep/rules/test" // rule test fixtures; never loaded as rules
	ProjectSuitesDir = "opengrep/gogrep/suites"     // project suites; they shadow built-in ones
)

// testsDir is the directory of a rule set that holds its rule test fixtures.
const testsDir = "test"

// Files are the files that the gogrep module embeds at its root, which
// go:embed cannot reach from this package.
type Files struct {
	Rules  fs.FS  // gogrep's own rule set, "gogrep"
	Suites fs.FS  // the built-in suites, as <name>.yaml files
	Pins   []byte // opengrep.json
}

// A Config configures an Engine. The zero Config is ready to use: files go
// under the user cache directory, opengrep gets the process environment, and
// nothing is logged. Fields added later will default to the old behaviour.
type Config struct {
	// CacheDir is where gogrep keeps the opengrep executable, opengrep's
	// unpacked runtime, rule selections, locks and per-run logs. It must be
	// absolute. Empty means filepath.Join(os.UserCacheDir(), "gogrep"),
	// resolved in New and shared with the gogrep command; if
	// os.UserCacheDir fails, the operations that need the cache return
	// that error. Directories are created 0o700 and files 0o600 (0o700 for
	// the executable).
	CacheDir string

	// Env is the environment opengrep runs in, as in exec.Cmd.Env. nil
	// means os.Environ() as of New.
	Env []string

	// Logger receives gogrep's own records at Debug and Info level. nil
	// discards them. The package never changes slog's default logger, and
	// opengrep's own output never goes to Logger.
	Logger *slog.Logger
}

// An Engine scans directories, lists rules and suites, and runs rule test
// fixtures.
//
// An Engine is safe for concurrent use by multiple goroutines. No method
// reads or changes the process's working directory, signal dispositions or
// standard streams, and none reads environment variables beyond the
// defaults Config documents. Every directory argument must be absolute.
type Engine struct {
	cacheDir string
	cacheErr error // why there is no cacheDir
	env      []string
	log      *slog.Logger
	files    Files

	ownRules func() ([]*rules.Rule, error) // the "gogrep" rule set, parsed once
}

// New returns an Engine for cfg and files. It runs nothing and reads no
// file: gogrep's built-in rule sets are parsed (about 0.13 s, once per
// process) when first needed. It returns an error only for an invalid cfg,
// such as a relative CacheDir.
func New(cfg Config, files Files) (*Engine, error) {
	e := &Engine{cacheDir: cfg.CacheDir, env: slices.Clone(cfg.Env), log: cfg.Logger, files: files}
	switch {
	case e.cacheDir == "":
		cache, err := os.UserCacheDir()
		if err != nil {
			e.cacheErr = err
		} else {
			e.cacheDir = filepath.Join(cache, "gogrep")
		}
	case !filepath.IsAbs(e.cacheDir):
		return nil, fmt.Errorf("Config.CacheDir %s is not an absolute path", cfg.CacheDir)
	}
	if e.env == nil {
		e.env = os.Environ()
	}
	if e.log == nil {
		e.log = slog.New(slog.DiscardHandler)
	}
	e.ownRules = sync.OnceValues(func() ([]*rules.Rule, error) {
		set, err := rules.FromFS(files.Rules, testsDir)
		if err != nil {
			return nil, err
		}
		parsed, err := parse(map[string]rules.Set{"gogrep": set})
		return parsed["gogrep"], err
	})
	return e, nil
}

// cache returns the directory sub of CacheDir, or the error that leaves the
// engine without a CacheDir.
func (e *Engine) cache(sub string) (string, error) {
	if e.cacheErr != nil {
		return "", e.cacheErr
	}
	return filepath.Join(e.cacheDir, sub), nil
}

// writeRules writes rs to one opengrep config file among the rule
// selections in CacheDir, as rules.Write does.
func (e *Engine) writeRules(rs []*rules.Rule) (string, error) {
	dir, err := e.cache("selections")
	if err != nil {
		return "", err
	}
	return rules.Write(dir, rs)
}

// checkDir checks a directory argument: it must be absolute, or "" where
// optional is set.
func checkDir(dir string, optional bool) error {
	if (dir != "" || !optional) && !filepath.IsAbs(dir) {
		return fmt.Errorf("directory %q is not an absolute path", dir)
	}
	return nil
}

// bundledRules are the third-party rule sets that opengrep.json pins, by
// name, parsed once per process and shared read-only.
var bundledRules = sync.OnceValues(func() (map[string][]*rules.Rule, error) {
	sets := map[string]rules.Set{}
	for name, archive := range rulesets.Archives() {
		set, err := rules.FromTarGz(archive)
		if err != nil {
			return nil, fmt.Errorf("reading bundled rule set %s: %w", name, err)
		}
		sets[name] = set
	}
	return parse(sets)
})

// parse parses sets and returns their rules by set name, every set
// included.
func parse(sets map[string]rules.Set) (map[string][]*rules.Rule, error) {
	parsed, err := rules.Parse(sets)
	if err != nil {
		return nil, err
	}
	bySet := map[string][]*rules.Rule{}
	for name := range sets {
		bySet[name] = nil
	}
	for _, r := range parsed {
		bySet[r.Set] = append(bySet[r.Set], r)
	}
	return bySet, nil
}

// loadEnv returns the rule sets that a call with the project directory dir
// sees: the bundled ones, gogrep's own and the project's, the last without
// its test fixtures and empty when dir is "" or noProject is set. Groups:
// "bundled" (the pinned third-party sets) and "all". Suites load as
// Selection.Suites describes.
func (e *Engine) loadEnv(dir string, noProject bool) (*suite.Env, error) {
	bundled, err := bundledRules()
	if err != nil {
		return nil, err
	}
	own, err := e.ownRules()
	if err != nil {
		return nil, err
	}
	project, err := projectRules(dir, noProject)
	if err != nil {
		return nil, err
	}
	env := &suite.Env{
		Sets:   map[string][]*rules.Rule{"gogrep": own, "project": project},
		Groups: map[string][]string{"bundled": slices.Collect(maps.Keys(bundled))},
		Load:   e.loader(dir, noProject),
	}
	maps.Copy(env.Sets, bundled)
	env.Groups["all"] = slices.Collect(maps.Keys(env.Sets))
	return env, nil
}

// projectRules parses the "project" rule set of the project in dir.
func projectRules(dir string, noProject bool) ([]*rules.Rule, error) {
	if dir == "" || noProject {
		return nil, nil
	}
	rel := filepath.FromSlash(ProjectRulesDir)
	if fi, err := os.Stat(filepath.Join(dir, rel)); err != nil || !fi.IsDir() {
		return nil, nil
	}
	set, err := rules.FromFS(os.DirFS(filepath.Join(dir, rel)), testsDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", rel, err)
	}
	parsed, err := parse(map[string]rules.Set{"project": set})
	return parsed["project"], err
}

// loader returns how a call with the project directory dir loads suites:
// a suite file relative to dir, then a project suite unless noProject is
// set, then a built-in suite.
func (e *Engine) loader(dir string, noProject bool) func(name string) (*suite.Suite, error) {
	return func(name string) (*suite.Suite, error) {
		if strings.ContainsAny(name, `/\`) || strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			return loadSuiteFile(dir, name)
		}
		if dir != "" && !noProject {
			for _, ext := range []string{".yaml", ".yml"} {
				if data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(ProjectSuitesDir), name+ext)); err == nil {
					return parseSuite(name, data)
				}
			}
		}
		if data, err := fs.ReadFile(e.files.Suites, name+".yaml"); err == nil {
			return parseSuite(name, data)
		}
		return nil, &SelectionError{Kind: "suite", Value: name, Err: ErrUnknownSuite}
	}
}

// loadSuiteFile loads the suite file name, relative to dir unless it is
// absolute. Its errors name the file as given.
func loadSuiteFile(dir, name string) (*suite.Suite, error) {
	file := name
	if !filepath.IsAbs(name) {
		if dir == "" {
			return nil, &SelectionError{Kind: "suite", Value: name, Err: fmt.Errorf("suite file %s is relative, and there is no project directory", name)}
		}
		file = filepath.Join(dir, name)
	}
	data, err := os.ReadFile(file)
	if pe, ok := err.(*fs.PathError); ok {
		pe.Path = name
	}
	if err != nil {
		return nil, &SelectionError{Kind: "suite", Value: name, Err: err}
	}
	return parseSuite(name, data)
}

func parseSuite(name string, data []byte) (*suite.Suite, error) {
	s, err := suite.Parse(name, data)
	if err != nil {
		return nil, &SelectionError{Kind: "suite", Value: name, Err: err}
	}
	return s, nil
}
