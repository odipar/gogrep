package ruletest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// Names of the files gogrep reads and writes at the root of a fixture.
const (
	refFile      = "rule.ref"
	expectedFile = "expected.txt"
	actualFile   = "actual.txt"
	sarifFile    = "actual.sarif"
)

// maxTargetBytes caps the length of a fixture's sample arguments, which keeps
// opengrep's command line below Windows' limit of 32,767 characters.
const maxTargetBytes = 30000

// A Fixture is one test: a directory under the test root that holds a
// rule.ref. Discover also returns broken fixtures and directories that only
// look like one, with Setup set.
type Fixture struct {
	Name      string   // slash path relative to the current directory
	Dir       string   // the directory, as an OS path
	Namespace string   // slash path from the test root to the parent directory
	Ref       string   // the rule reference in rule.ref
	Samples   []string // slash paths relative to Dir, sorted bytewise
	Setup     error    // why the fixture is malformed: the test fails at SETUP
}

// Discover returns the fixtures under the test root root that paths select,
// sorted by name. A path selects the fixtures below it and the fixture that
// contains it; no paths select every fixture. A directory outside every
// fixture that has an expected.txt or actual.txt is returned as a fixture
// that fails at SETUP, and so are a symlink outside every fixture, which
// would hide the fixtures it leads to, and a fixture that breaks a rule of
// the design's §2.3. It is an error when root is not a directory or is
// spelled in another letter case, when a path does not exist, lies outside
// root or selects no test, or when there are no tests at all.
func Discover(root string, paths []string) ([]*Fixture, error) {
	t := &tree{root: root, name: path.Clean(filepath.ToSlash(root)), entries: map[string]fs.DirEntry{}}
	// A case-insensitive file system would find a Test directory here,
	// which scans then do not exclude, as other file systems do not.
	siblings, _ := os.ReadDir(filepath.Dir(root))
	for _, e := range siblings {
		if base := filepath.Base(root); e.Name() != base && strings.EqualFold(e.Name(), base) {
			return nil, fmt.Errorf("%s must be spelled %s", path.Join(path.Dir(t.name), e.Name()), t.name)
		}
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("no %s directory here; run gogrep test from the project root", t.name)
	}
	selected, err := t.relPaths(paths)
	if err != nil {
		return nil, err
	}
	err = fs.WalkDir(os.DirFS(root), ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && p != "." {
			t.entries[p] = d
			t.paths = append(t.paths, p)
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", t.name, err)
	}
	slices.Sort(t.paths)

	var orphans []string
	for _, p := range t.paths {
		switch path.Base(p) {
		case refFile:
			t.fixtures = append(t.fixtures, path.Dir(p))
		case expectedFile, actualFile:
			orphans = append(orphans, path.Dir(p))
		}
	}
	slices.Sort(t.fixtures)
	orphans = slices.DeleteFunc(orphans, func(o string) bool {
		return slices.ContainsFunc(t.fixtures, func(dir string) bool { return within(o, dir) })
	})

	var out []*Fixture
	used := make([]bool, len(selected)) // whether each path selects a test
	pick := func(dir string) bool {
		picked := len(selected) == 0
		for i, p := range selected {
			if within(p, dir) || within(dir, p) {
				picked, used[i] = true, true
			}
		}
		return picked
	}
	for _, dir := range t.fixtures {
		if pick(dir) {
			out = append(out, t.fixture(dir))
		}
	}
	slices.Sort(orphans)
	for _, dir := range slices.Compact(orphans) {
		if pick(dir) {
			name := expectedFile
			if _, ok := t.entries[path.Join(dir, name)]; !ok {
				name = actualFile
			}
			out = append(out, &Fixture{
				Name:  t.display(dir),
				Dir:   filepath.Join(root, filepath.FromSlash(dir)),
				Setup: fmt.Errorf("%s has no %s next to it", name, refFile),
			})
		}
	}
	// The walk does not follow symlinks, so the fixtures behind a symlinked
	// fixture or namespace directory would silently not run.
	for _, p := range t.paths {
		if t.entries[p].Type()&fs.ModeSymlink == 0 ||
			slices.ContainsFunc(t.fixtures, func(dir string) bool { return within(p, dir) }) || !pick(p) {
			continue
		}
		out = append(out, &Fixture{
			Name:  t.display(p),
			Dir:   filepath.Join(root, filepath.FromSlash(p)),
			Setup: fmt.Errorf("symlinks are not supported in the test root: %s", p),
		})
	}
	// A path that selects nothing is an error even next to others that
	// do, so a mistyped path cannot pass silently.
	var none []string
	for i, u := range used {
		if !u {
			none = append(none, paths[i])
		}
	}
	if len(out) == 0 && len(paths) == 0 {
		none = []string{t.name}
	}
	if len(none) > 0 {
		return nil, fmt.Errorf("no tests found under %s", strings.Join(none, ", "))
	}
	slices.SortFunc(out, func(a, b *Fixture) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// A tree is the test root as Discover reads it.
type tree struct {
	root     string                 // OS path
	name     string                 // slash path, as shown
	entries  map[string]fs.DirEntry // every entry below the root, by slash path
	paths    []string               // the keys of entries, sorted bytewise
	fixtures []string               // directories with a rule.ref, sorted
}

// relPaths returns paths, relative or absolute OS paths written with / or \,
// as slash paths relative to the root.
func (t *tree) relPaths(paths []string) ([]string, error) {
	absRoot, err := filepath.Abs(t.root)
	if err != nil {
		return nil, err
	}
	var rels []string
	for _, p := range paths {
		native := filepath.FromSlash(strings.ReplaceAll(p, `\`, "/"))
		abs, err := filepath.Abs(native)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(absRoot, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			var ok bool
			if rel, ok = t.linkedRel(abs); !ok {
				return nil, fmt.Errorf("%s is not under %s", p, t.name)
			}
		}
		if _, err := os.Lstat(native); errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s does not exist", p)
		} else if err != nil {
			return nil, err
		}
		rels = append(rels, filepath.ToSlash(rel))
	}
	return rels, nil
}

// linkedRel returns the absolute path abs, which does not lie under the root
// as written, relative to the root if a leading part of it is the root's
// directory reached another way: /tmp/p and /private/tmp/p name the same
// directory on macOS, where /tmp is a symlink, and editors pass such
// resolved paths. The shortest such part counts, so a symlink below the root
// is never followed.
func (t *tree) linkedRel(abs string) (string, bool) {
	root, err := os.Stat(t.root)
	if err != nil {
		return "", false
	}
	rel := ""
	for d := abs; ; d = filepath.Dir(d) {
		if fi, err := os.Stat(d); err == nil && os.SameFile(fi, root) {
			rel, _ = filepath.Rel(d, abs)
		}
		if filepath.Dir(d) == d {
			return rel, rel != ""
		}
	}
}

// display returns the name of the directory dir below the root.
func (t *tree) display(dir string) string { return path.Join(t.name, dir) }

// fixture returns the fixture in the directory dir, checking it.
func (t *tree) fixture(dir string) *Fixture {
	f := &Fixture{Name: t.display(dir), Dir: filepath.Join(t.root, filepath.FromSlash(dir))}
	if strings.Contains(dir, "/") {
		f.Namespace = path.Dir(dir)
	}
	f.Setup = t.check(f, dir)
	return f
}

// check returns the first rule of the design's §2.3 that the fixture f in
// the directory dir breaks, and sets its samples and reference.
func (t *tree) check(f *Fixture, dir string) error {
	if f.Namespace == "" {
		return fmt.Errorf("fixtures live in %s/<namespace>/<fixture>/", t.name)
	}
	for _, name := range []string{refFile, expectedFile, actualFile, sarifFile} {
		if d, ok := t.entries[path.Join(dir, name)]; ok && !d.Type().IsRegular() {
			return fmt.Errorf("%s must be a regular file", name)
		}
	}
	for p := path.Dir(dir); ; p = path.Dir(p) {
		if _, found := slices.BinarySearch(t.fixtures, p); found {
			return fmt.Errorf("fixture is nested inside %s", t.display(p))
		}
		if p == "." {
			break
		}
	}
	if nested := below(t.fixtures, dir); len(nested) > 0 {
		return fmt.Errorf("fixture contains nested fixture %s", t.display(nested[0]))
	}

	entries := below(t.paths, dir)
	for _, p := range entries {
		if name := path.Base(p); path.Dir(p) == dir && !reserved(name) && regressionLike(name) {
			return fmt.Errorf("unknown regression file %s; the expected file is %s", name, expectedFile)
		}
	}
	targetBytes := 0
	for _, p := range entries {
		d, name, rel := t.entries[p], path.Base(p), p[len(dir)+1:]
		switch {
		case d.IsDir() || ignored(name):
			continue
		case path.Dir(p) == dir && (reserved(name) || strings.HasPrefix(name, ".gogrep-") && strings.HasSuffix(name, ".tmp")):
			continue
		case d.Type()&fs.ModeSymlink != 0:
			return fmt.Errorf("symlinks are not supported in fixtures: %s", rel)
		case !d.Type().IsRegular():
			return fmt.Errorf("special files are not supported in fixtures: %s", rel)
		}
		f.Samples = append(f.Samples, rel)
		targetBytes += len("./") + len(rel) + 1
	}
	switch {
	case len(f.Samples) == 0:
		return errors.New("no code samples")
	case targetBytes > maxTargetBytes:
		return fmt.Errorf("too many sample files (%d); split the fixture", len(f.Samples))
	}

	data, err := os.ReadFile(filepath.Join(f.Dir, refFile))
	if err != nil {
		return err
	}
	f.Ref, err = ParseRef(data)
	return err
}

// reserved reports whether gogrep reads or writes the file name at the root
// of a fixture.
func reserved(name string) bool {
	return name == refFile || name == expectedFile || name == actualFile || name == sarifFile
}

// regressionLike reports whether a file name at the root of a fixture looks
// like a regression file: it starts with expected or actual, or it differs
// from one of gogrep's names only in case, which some file systems ignore.
func regressionLike(name string) bool {
	switch strings.ToLower(name) {
	case expectedFile, actualFile, sarifFile:
		return true
	}
	return strings.HasPrefix(name, "expected") || strings.HasPrefix(name, "actual")
}

// ignored reports whether a file is operating system clutter, which is never
// a sample.
func ignored(name string) bool {
	switch strings.ToLower(name) {
	case ".ds_store", "thumbs.db", "desktop.ini":
		return true
	}
	return false
}

// below returns the slash paths in sorted that lie below dir, which is not
// ".". Since sorted is sorted bytewise, they are adjacent.
func below(sorted []string, dir string) []string {
	prefix := dir + "/"
	i, _ := slices.BinarySearch(sorted, prefix)
	j := i
	for j < len(sorted) && strings.HasPrefix(sorted[j], prefix) {
		j++
	}
	return sorted[i:j]
}

// within reports whether the slash path p is dir or lies below it.
func within(p, dir string) bool {
	return dir == "." || p == dir || strings.HasPrefix(p, dir+"/")
}
