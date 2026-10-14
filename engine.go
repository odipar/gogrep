package gogrep

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/odipar/gogrep/internal/opengrep"
	"github.com/odipar/gogrep/internal/pin"
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

// A source is where an Engine finds gogrep's own files: the rule set
// "gogrep", the built-in suites and opengrep.json, the first and last parsed
// once.
type source struct {
	suites   fs.FS                         // the built-in suites, as <name>.yaml files
	ownRules func() ([]*rules.Rule, error) // the "gogrep" rule set
	pins     func() (*pin.Pins, error)     // opengrep.json
}

// newSource returns the source of the rule set in rulesFS, the suites in
// suitesFS and the pins in pinJSON.
func newSource(rulesFS, suitesFS fs.FS, pinJSON []byte) *source {
	return &source{
		suites: suitesFS,
		ownRules: sync.OnceValues(func() ([]*rules.Rule, error) {
			set, err := rules.FromFS(rulesFS, testsDir)
			if err != nil {
				return nil, err
			}
			parsed, err := parse(map[string]rules.Set{"gogrep": set})
			return parsed["gogrep"], err
		}),
		pins: sync.OnceValues(func() (*pin.Pins, error) {
			p, err := pin.Parse(pinJSON)
			if err != nil {
				return nil, fmt.Errorf("opengrep.json: %w", err)
			}
			return p, nil
		}),
	}
}

// A Config configures an Engine. The zero Config is ready to use: opengrep is
// the pinned build from the cache (or a verified one on PATH), files go under
// the user cache directory, opengrep gets the process environment, and
// nothing is logged. Fields added later will default to the old behaviour.
type Config struct {
	// Opengrep is the opengrep executable to run: an absolute path, or a
	// name without a path separator that is looked up in the process's
	// PATH when first needed. It is used whatever its version;
	// OpengrepInfo.Pinned reports whether it is the pinned build. New
	// rejects a relative path that contains a separator. Empty means: find
	// opengrep as Engine.Opengrep describes. The package never reads
	// $OPENGREP_BIN; the gogrep command passes it here.
	Opengrep string

	// EmbeddedOpengrep is an opengrep executable compiled into the program,
	// for example with go:embed. Its SHA-256 must be the pinned one for the
	// running GOOS/GOARCH (glibc or musl on Linux); otherwise Opengrep
	// returns an *IntegrityError. It is written once to CacheDir. gogrep's
	// release builds set it.
	EmbeddedOpengrep []byte

	// AllowUnpinned lets the engine run an opengrep found on PATH whose
	// SHA-256 is not the pinned one. Findings then depend on that
	// opengrep's version. The gogrep command sets it, as it has always run
	// any opengrep on PATH.
	AllowUnpinned bool

	// CacheDir is where gogrep keeps the opengrep executable, opengrep's
	// unpacked runtime, rule selections, locks and per-run logs. It must be
	// absolute. Empty means filepath.Join(os.UserCacheDir(), "gogrep"),
	// resolved in New and shared with the gogrep command; if
	// os.UserCacheDir fails, the operations that need the cache return
	// that error. Directories are created 0o700 and files 0o600 (0o700 for
	// the executable). On Linux and macOS it should be ASCII: opengrep
	// 1.30.2 runs no command, printing nothing and exiting 0, when its
	// runtime is under a path that is not. Under such a CacheDir, gogrep
	// leaves the runtime where opengrep keeps it by itself
	// ($XDG_CACHE_HOME/opengrep or ~/.cache/opengrep, from Env), which must
	// then be ASCII, and, as on Windows, has one opengrep unpack it there
	// alone, across goroutines and processes, so that concurrent first runs
	// do not crash; runtime-<sha16>.ready in CacheDir then records for which
	// XDG_CACHE_HOME and HOME that was done, and in which directory, so that a
	// runtime removed since (a cleaned ~/.cache) is prepared again.
	CacheDir string

	// Env is the environment opengrep runs in, as in exec.Cmd.Env. nil
	// means os.Environ() as of New. Scan and Test remove every SEMGREP_*
	// and OPENGREP_* variable from it and set SEMGREP_LOG_FILE to a file of
	// their own; Command does neither. All add LC_ALL=C.UTF-8 unless Env
	// itself selects a UTF-8 locale (PYTHONUTF8=1 on Windows), since
	// opengrep crashes on non-ASCII rules otherwise, and on Linux and macOS
	// set XDG_CACHE_HOME to the runtime directory in CacheDir once it is
	// prepared, unless CacheDir is not ASCII. opengrep runs git, which it
	// finds through Env's PATH.
	Env []string

	// Logger receives gogrep's own records at Debug and Info level: which
	// opengrep it found, extraction, downloads, runtime preparation, lock
	// waits and each opengrep command line. nil discards them. The package
	// never changes slog's default logger, and opengrep's own output never
	// goes to Logger.
	Logger *slog.Logger
}

// An Engine scans directories, lists rules and suites, and runs rule test
// fixtures.
//
// An Engine is safe for concurrent use by multiple goroutines. No method
// reads or changes the process's working directory, signal dispositions or
// standard streams, and none reads environment variables beyond the
// defaults Config documents. Every directory argument must be the absolute
// path of an existing directory. Methods that run opengrep take a context:
// when it is done, they kill the opengrep processes they started, with every
// process those started, and return an error that wraps ctx.Err().
type Engine struct {
	cfg      Config
	cacheDir string
	cacheErr error // why there is no cacheDir
	env      []string
	log      *slog.Logger
	src      *source

	embeddedSum func() string // the SHA-256 of cfg.EmbeddedOpengrep, computed once
}

// New returns an Engine for cfg. It runs nothing and reads no file: opengrep
// is found, and gogrep's built-in rule sets are parsed (about 0.13 s, once
// per process), when first needed. It returns an error only for an invalid
// cfg, such as a relative CacheDir or a relative Opengrep path.
func New(cfg Config) (*Engine, error) {
	return newFrom(cfg, builtin)
}

// newFrom returns an Engine for cfg that reads gogrep's own files from
// src.
func newFrom(cfg Config, src *source) (*Engine, error) {
	if p := cfg.Opengrep; p != "" && !filepath.IsAbs(p) && (strings.ContainsAny(p, "/"+string(filepath.Separator)) || filepath.VolumeName(p) != "") {
		return nil, fmt.Errorf("Config.Opengrep %s is a relative path", p)
	}
	e := &Engine{cfg: cfg, cacheDir: cfg.CacheDir, env: slices.Clone(cfg.Env), log: cfg.Logger, src: src}
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
	e.embeddedSum = sync.OnceValue(func() string { return opengrep.SHA256(cfg.EmbeddedOpengrep) })
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

// checkDir checks a directory argument: it must be the absolute path of a
// directory that can be entered, or "" where optional is set.
func checkDir(dir string, optional bool) error {
	switch {
	case dir == "" && optional:
		return nil
	case !filepath.IsAbs(dir):
		return fmt.Errorf("directory %q is not an absolute path", dir)
	}
	return enterable(dir)
}

// enterable reports why a process could not run in dir: it does not exist,
// is not a directory, or cannot be searched. Statting dir/. needs what
// entering dir does.
func enterable(dir string) error {
	fi, err := os.Stat(dir + string(filepath.Separator) + ".")
	if pe, ok := err.(*fs.PathError); ok {
		err = pe.Err
	}
	switch {
	case err != nil:
		return fmt.Errorf("directory %q: %w", dir, err)
	case !fi.IsDir():
		return fmt.Errorf("directory %q: not a directory", dir)
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
// its test fixtures and empty when dir is "" or noProject is set. A project
// rule file that does not parse is an error, or, with skipBroken, left out.
// Groups: "bundled" (the pinned third-party sets) and "all". Suites load as
// Selection.Suites describes.
func (e *Engine) loadEnv(dir string, noProject, skipBroken bool) (*suite.Env, error) {
	bundled, err := bundledRules()
	if err != nil {
		return nil, err
	}
	own, err := e.src.ownRules()
	if err != nil {
		return nil, err
	}
	project, err := projectRules(dir, noProject, skipBroken)
	if err != nil {
		return nil, err
	}
	env := &suite.Env{
		Sets:   map[string][]*rules.Rule{"gogrep": own, "project": project},
		Groups: map[string][]string{"bundled": slices.Collect(maps.Keys(bundled))},
		Load:   e.loader(dir, noProject, false),
		Import: e.loader(dir, noProject, true),
		Shadowed: func(name string) (*suite.Suite, error) {
			data, err := fs.ReadFile(e.src.suites, name+".yaml")
			if err != nil {
				return nil, nil // nothing built in to extend: the import is resolved as usual
			}
			return parseSuite("built-in "+name, data)
		},
	}
	maps.Copy(env.Sets, bundled)
	env.Groups["all"] = slices.Collect(maps.Keys(env.Sets))
	return env, nil
}

// projectRules parses the "project" rule set of the project in dir. A rule
// file that does not parse is an error that names it by its path in dir,
// under ProjectRulesDir, or, with skipBroken, left out.
func projectRules(dir string, noProject, skipBroken bool) ([]*rules.Rule, error) {
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
	if skipBroken {
		for p, data := range set {
			if _, err := rules.Parse(map[string]rules.Set{"project": {p: data}}); err != nil {
				delete(set, p)
			}
		}
	}
	parsed, err := parse(map[string]rules.Set{"project": set})
	if fe := (*rules.FileError)(nil); errors.As(err, &fe) {
		return nil, fmt.Errorf("%s/%s: %w", ProjectRulesDir, fe.Path, fe.Err)
	}
	return parsed["project"], err
}

// loader returns how a call with the project directory dir loads suites:
// a suite file relative to dir, then a project suite unless noProject is
// set, then a built-in suite. A project suite is read only if it is a
// regular file, and so is a suite file if imported is set, for the suites
// that import: entries name: the caller chose the others.
func (e *Engine) loader(dir string, noProject, imported bool) func(name string) (*suite.Suite, error) {
	return func(name string) (*suite.Suite, error) {
		if strings.ContainsAny(name, `/\`) || strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			return loadSuiteFile(dir, name, imported)
		}
		if dir != "" && !noProject {
			for _, ext := range []string{".yaml", ".yml"} {
				file := filepath.Join(dir, filepath.FromSlash(ProjectSuitesDir), name+ext)
				if !regularFile(file) {
					continue
				}
				if data, err := os.ReadFile(file); err == nil {
					return parseSuite(name, data)
				}
			}
		}
		if data, err := fs.ReadFile(e.src.suites, name+".yaml"); err == nil {
			return parseSuite(name, data)
		}
		return nil, &SelectionError{Kind: "suite", Value: name, Err: ErrUnknownSuite}
	}
}

// regularFile reports whether the file name is a regular file, through a
// symlink. A repository's suites are read only from regular files, as its
// rules are (rules.FromFS): a device or a pipe could be endless.
func regularFile(name string) bool {
	fi, err := os.Stat(name)
	return err == nil && fi.Mode().IsRegular()
}

// loadSuiteFile loads the suite file name, relative to dir unless it is
// absolute; with regularOnly, only if it is a regular file. Its errors name
// the file as given.
func loadSuiteFile(dir, name string, regularOnly bool) (*suite.Suite, error) {
	file := name
	if !filepath.IsAbs(name) {
		if dir == "" {
			return nil, &SelectionError{Kind: "suite", Value: name, Err: fmt.Errorf("suite file %s is relative, and there is no project directory", name)}
		}
		file = filepath.Join(dir, name)
	}
	if regularOnly {
		if fi, err := os.Stat(file); err == nil && !fi.Mode().IsRegular() {
			return nil, &SelectionError{Kind: "suite", Value: name, Err: fmt.Errorf("suite file %s is not a regular file", name)}
		}
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
