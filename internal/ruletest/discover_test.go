package ruletest

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// testRoot is the test root, relative to the directory the tests run in.
var testRoot = filepath.Join("opengrep", "gogrep", "rules", "test")

// writeTree creates files, keyed by slash path, under dir.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// fixtureTree creates a test root in a new current directory, with a fixture
// for each check of the design's §2.3, and returns the fixtures Discover
// should find in it with no paths.
func fixtureTree(t *testing.T) []summary {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	files := map[string]string{
		"go.mod":         "module fixtures\n",
		".gitattributes": "* -text\n",

		"go/exec-command/rule.ref":                 "# comment\nno-exec-command\n",
		"go/exec-command/expected.txt":             "",
		"go/exec-command/actual.txt":               "",
		"go/exec-command/actual.sarif":             "{}",
		"go/exec-command/.gogrep-123.tmp":          "",
		"go/exec-command/.DS_Store":                "",
		"go/exec-command/sample.go":                "package sample\n",
		"go/exec-command/-dash.go":                 "package sample\n",
		"go/exec-command/a-b.go":                   "package sample\n",
		"go/exec-command/a/b.go":                   "package a\n",
		"go/exec-command/.github/workflows/ci.yml": "on: push\n",
		"go/exec-command/vendor/v.go":              "package v\n",
		"go/exec-command/sub/runner_test.go":       "package sub\n",
		"go/exec-command/sub/expected.txt":         "",
		"go/exec-command/sub/.gogrep-1.tmp":        "",
		"go/exec-command/sub/Thumbs.db":            "",
		"go/exec-command/sub/DESKTOP.INI":          "",

		"go/net/dial-basic/rule.ref": "dial",
		"go/net/dial-basic/d.go":     "package d\n",

		"shallow/rule.ref": "x\n",
		"shallow/x.go":     "package x\n",

		"nested/outer/rule.ref":       "x\n",
		"nested/outer/a.go":           "package a\n",
		"nested/outer/inner/rule.ref": "x\n",
		"nested/outer/inner/b.go":     "package b\n",

		"setup/ref-dir/rule.ref/x.go":    "package x\n",
		"setup/expected-dir/rule.ref":    "x\n",
		"setup/expected-dir/a.go":        "package a\n",
		"setup/typo/rule.ref":            "x\n",
		"setup/typo/expected.text":       "",
		"setup/typo/a.go":                "package a\n",
		"setup/case/rule.ref":            "x\n",
		"setup/case/Expected.txt":        "",
		"setup/case/a.go":                "package a\n",
		"setup/actually/rule.ref":        "x\n",
		"setup/actually/actually.go":     "package a\n",
		"setup/actually/sub/actually.go": "package a\n",
		"setup/empty/rule.ref":           "x\n",
		"setup/empty/expected.txt":       "",
		"setup/empty/.DS_Store":          "",
		"setup/bad-ref/rule.ref":         "a\nb\n",
		"setup/bad-ref/a.go":             "package a\n",

		"orphan/old-name/expected.txt":  "",
		"orphan/old-name/a.go":          "package a\n",
		"orphan/actual-only/actual.txt": "",
	}
	// Sample arguments ("./" + path + a separator) of 120 bytes each: 250 fill
	// the 30,000 bytes allowed exactly.
	files["setup/many/rule.ref"] = "x\n"
	files["setup/too-many/rule.ref"] = "x\n"
	for i := range 250 {
		files[fmt.Sprintf("setup/many/%s%03d.go", strings.Repeat("x", 111), i)] = ""
		files[fmt.Sprintf("setup/too-many/%s%03d.go", strings.Repeat("x", 112), i)] = ""
	}
	writeTree(t, testRoot, files)
	if err := os.Mkdir(filepath.Join(testRoot, "setup", "expected-dir", "expected.txt"), 0o700); err != nil {
		t.Fatal(err)
	}

	var many []string
	for i := range 250 {
		many = append(many, fmt.Sprintf("%s%03d.go", strings.Repeat("x", 111), i))
	}
	root := "opengrep/gogrep/rules/test/"
	want := []summary{
		{Name: root + "go/exec-command", Namespace: "go", Ref: "no-exec-command", Samples: []string{
			"-dash.go", ".github/workflows/ci.yml", "a-b.go", "a/b.go", "sample.go",
			"sub/.gogrep-1.tmp", "sub/expected.txt", "sub/runner_test.go", "vendor/v.go",
		}},
		{Name: root + "go/net/dial-basic", Namespace: "go/net", Ref: "dial", Samples: []string{"d.go"}},
		{Name: root + "nested/outer", Namespace: "nested", Setup: "fixture contains nested fixture " + root + "nested/outer/inner"},
		{Name: root + "nested/outer/inner", Namespace: "nested/outer", Setup: "fixture is nested inside " + root + "nested/outer"},
		{Name: root + "orphan/actual-only", Setup: "actual.txt has no rule.ref next to it"},
		{Name: root + "orphan/old-name", Setup: "expected.txt has no rule.ref next to it"},
		{Name: root + "setup/actually", Namespace: "setup", Setup: "unknown regression file actually.go; the expected file is expected.txt"},
		{Name: root + "setup/bad-ref", Namespace: "setup", Setup: "rule.ref has 2 references; a fixture tests exactly one rule"},
		{Name: root + "setup/case", Namespace: "setup", Setup: "unknown regression file Expected.txt; the expected file is expected.txt"},
		{Name: root + "setup/empty", Namespace: "setup", Setup: "no code samples"},
		{Name: root + "setup/expected-dir", Namespace: "setup", Setup: "expected.txt must be a regular file"},
		{Name: root + "setup/many", Namespace: "setup", Ref: "x", Samples: many},
		{Name: root + "setup/ref-dir", Namespace: "setup", Setup: "rule.ref must be a regular file"},
		{Name: root + "setup/too-many", Namespace: "setup", Setup: "too many sample files (250); split the fixture"},
		{Name: root + "setup/typo", Namespace: "setup", Setup: "unknown regression file expected.text; the expected file is expected.txt"},
		{Name: root + "shallow", Setup: "fixtures live in opengrep/gogrep/rules/test/<namespace>/<fixture>/"},
	}

	link := filepath.Join(testRoot, "setup", "symlink")
	writeTree(t, link, map[string]string{"rule.ref": "x\n", "a.go": "package a\n"})
	if err := os.Symlink("a.go", filepath.Join(link, "b.go")); err != nil {
		t.Logf("not testing symlinks: %v", err)
		os.RemoveAll(link)
	} else {
		want = append(want, summary{Name: root + "setup/symlink", Namespace: "setup", Setup: "symlinks are not supported in fixtures: b.go"})
	}
	// Discovery does not follow symlinks, so it reports a symlinked fixture
	// or namespace directory rather than skip the fixtures behind it.
	shared := filepath.Join(dir, "shared")
	writeTree(t, shared, map[string]string{"fx/rule.ref": "x\n", "fx/a.go": "package a\n"})
	for _, l := range []struct{ name, target string }{{"links/fx", filepath.Join(shared, "fx")}, {"linkns", shared}} {
		p := filepath.Join(testRoot, filepath.FromSlash(l.name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(l.target, p); err != nil {
			t.Logf("not testing symlinks: %v", err)
			continue
		}
		want = append(want, summary{Name: root + l.name, Setup: "symlinks to directories are not supported in the test root: " + l.name})
	}
	// Symlinks to files, or to nothing, hide no fixture and are ignored like
	// any other file outside the fixtures.
	writeTree(t, shared, map[string]string{"go.mod": "module fixtures\n"})
	for _, l := range []struct{ name, target string }{{"linked-go.mod", filepath.Join(shared, "go.mod")}, {"dangling", filepath.Join(shared, "nope")}} {
		if err := os.Symlink(l.target, filepath.Join(testRoot, l.name)); err != nil {
			t.Logf("not testing symlinks: %v", err)
		}
	}
	if runtime.GOOS != "windows" {
		writeTree(t, testRoot, map[string]string{"setup/socket/rule.ref": "x\n", "setup/socket/a.go": "package a\n"})
		l, err := net.Listen("unix", filepath.Join(testRoot, "setup", "socket", "sock"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		want = append(want, summary{Name: root + "setup/socket", Namespace: "setup", Setup: "special files are not supported in fixtures: sock"})
	}
	slices.SortFunc(want, func(a, b summary) int { return strings.Compare(a.Name, b.Name) })
	return want
}

// A summary is a Fixture in a form tests can compare, without the samples
// of a fixture that fails at SETUP.
type summary struct {
	Name, Namespace, Ref string
	Samples              []string
	Setup                string
}

func (s summary) String() string {
	samples := fmt.Sprintf("%q", s.Samples)
	if len(s.Samples) > 10 {
		samples = fmt.Sprintf("%d samples from %q to %q", len(s.Samples), s.Samples[0], s.Samples[len(s.Samples)-1])
	}
	return fmt.Sprintf("{%s ns=%q ref=%q %s setup=%q}", s.Name, s.Namespace, s.Ref, samples, s.Setup)
}

func summarize(fs []*Fixture) []summary {
	var out []summary
	for _, f := range fs {
		s := summary{Name: f.Name, Namespace: f.Namespace, Ref: f.Ref, Samples: f.Samples, Setup: errText(f.Setup)}
		if f.Setup != nil {
			s.Samples = nil
		}
		out = append(out, s)
	}
	return out
}

func TestDiscover(t *testing.T) {
	want := fixtureTree(t)
	fixtures, err := Discover(testRoot, nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	got := summarize(fixtures)
	for i := range max(len(got), len(want)) {
		switch {
		case i >= len(got):
			t.Errorf("missing fixture %v", want[i])
		case i >= len(want):
			t.Errorf("unexpected fixture %v", got[i])
		case got[i].Name != want[i].Name || got[i].Namespace != want[i].Namespace || got[i].Ref != want[i].Ref ||
			!slices.Equal(got[i].Samples, want[i].Samples) || got[i].Setup != want[i].Setup:
			t.Errorf("fixture %d = %v\nwant %v", i, got[i], want[i])
		}
	}
	if want := filepath.Join(testRoot, "go", "exec-command"); fixtures[0].Dir != want {
		t.Errorf("Dir = %q, want %q", fixtures[0].Dir, want)
	}
}

func TestDiscoverPaths(t *testing.T) {
	var all []string
	for _, f := range fixtureTree(t) {
		all = append(all, strings.TrimPrefix(f.Name, "opengrep/gogrep/rules/test/"))
	}
	abs, err := filepath.Abs(filepath.Join(testRoot, "go", "net", "dial-basic", "rule.ref"))
	if err != nil {
		t.Fatal(err)
	}
	root := "opengrep/gogrep/rules/test"
	type pathsTest struct {
		name  string
		paths []string
		want  []string // fixture names below the root
		err   string
	}
	tests := []pathsTest{
		{"test root", []string{root}, all, ""},
		{"test root with a slash", []string{root + "/"}, all, ""},
		{"namespace", []string{root + "/go"}, []string{"go/exec-command", "go/net/dial-basic"}, ""},
		{"fixture", []string{"./" + root + "/go/exec-command"}, []string{"go/exec-command"}, ""},
		{"sample in a subdirectory", []string{root + "/go/exec-command/sub/runner_test.go"}, []string{"go/exec-command"}, ""},
		{"backslashes", []string{`opengrep\gogrep\rules\test\go\net`}, []string{"go/net/dial-basic"}, ""},
		{"absolute rule.ref", []string{abs}, []string{"go/net/dial-basic"}, ""},
		{"unclean", []string{root + "/../test/go/net//dial-basic/."}, []string{"go/net/dial-basic"}, ""},
		{"inside a nested fixture", []string{root + "/nested/outer/inner/b.go"}, []string{"nested/outer", "nested/outer/inner"}, ""},
		{"orphan", []string{root + "/orphan/old-name/a.go"}, []string{"orphan/old-name"}, ""},
		{"several, overlapping", []string{root + "/shallow", root + "/go/net", root + "/go/net/dial-basic/d.go"}, []string{"go/net/dial-basic", "shallow"}, ""},
		{"rules directory", []string{"opengrep/gogrep/rules"}, nil, "opengrep/gogrep/rules is not under opengrep/gogrep/rules/test"},
		{"current directory", []string{"."}, nil, ". is not under opengrep/gogrep/rules/test"},
		{"escaping the root", []string{root + "/../test2"}, nil, root + "/../test2 is not under opengrep/gogrep/rules/test"},
		{"absolute outside", []string{filepath.Dir(abs) + "/../../../../x"}, nil, filepath.Dir(abs) + "/../../../../x is not under opengrep/gogrep/rules/test"},
		{"missing", []string{root + "/go/nope"}, nil, root + "/go/nope does not exist"},
		{"no fixture", []string{root + "/go.mod", root + "/.gitattributes"}, nil, "no tests found under " + root + "/go.mod, " + root + "/.gitattributes"},
		{"one path without a fixture", []string{root + "/go/net", root + "/go.mod", root + "/shallow"}, nil, "no tests found under " + root + "/go.mod"},
	}
	if slices.Contains(all, "linkns") {
		tests = append(tests,
			pathsTest{"symlinked fixture", []string{root + "/links/fx"}, []string{"links/fx"}, ""},
			pathsTest{"through a symlinked namespace", []string{root + "/linkns/fx/a.go"}, []string{"linkns"}, ""},
		)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixtures, err := Discover(testRoot, tt.paths)
			var got []string
			for _, f := range fixtures {
				got = append(got, strings.TrimPrefix(f.Name, root+"/"))
			}
			if !slices.Equal(got, tt.want) || errText(err) != tt.err {
				t.Errorf("Discover(%q) = %q, %q; want %q, %q", tt.paths, got, errText(err), tt.want, tt.err)
			}
		})
	}
}

// A path in the wrong case exists on a case-insensitive file system but
// names no fixture, so it fails there too.
func TestDiscoverPathCase(t *testing.T) {
	fixtureTree(t)
	root := "opengrep/gogrep/rules/test"
	_, err := Discover(testRoot, []string{root + "/go/net", root + "/GO/exec-command"})
	if got := errText(err); got != "no tests found under "+root+"/GO/exec-command" && got != root+"/GO/exec-command does not exist" {
		t.Errorf("Discover with a path in the wrong case: %q", got)
	}
}

// An absolute path may reach the test root through symlinks other than
// those of the current directory, as resolved paths from editors do.
func TestDiscoverLinkedPaths(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create symlinks: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	writeTree(t, filepath.Join(real, testRoot), map[string]string{"go/x/rule.ref": "x\n", "go/x/a.go": "package a\n"})
	for _, cwd := range []string{link, resolved} {
		t.Chdir(cwd)
		for _, base := range []string{real, link, resolved} {
			for _, p := range []string{filepath.Join(base, testRoot, "go"), filepath.Join(base, testRoot, "go", "x", "a.go"), filepath.Join(base, testRoot)} {
				fixtures, err := Discover(testRoot, []string{p})
				if err != nil || len(fixtures) != 1 || fixtures[0].Name != "opengrep/gogrep/rules/test/go/x" {
					t.Errorf("in %s, Discover(%q) = %v, %v; want the fixture go/x", cwd, p, summarize(fixtures), err)
				}
			}
		}
		outside := filepath.Join(resolved, "opengrep", "gogrep", "rules")
		if _, err := Discover(testRoot, []string{outside}); errText(err) != outside+" is not under opengrep/gogrep/rules/test" {
			t.Errorf("in %s, Discover(%q) = %q, want it not under the test root", cwd, outside, errText(err))
		}
	}
}

// On a case-sensitive file system a Test directory can sit next to the test
// root. It is reserved, since nothing reads it; a file named so is not.
func TestDiscoverRootCaseVariant(t *testing.T) {
	t.Chdir(t.TempDir())
	writeTree(t, testRoot, map[string]string{"go/x/rule.ref": "x\n", "go/x/a.go": "package a\n"})
	upper := filepath.Join(filepath.Dir(testRoot), "TEST")
	if err := os.WriteFile(upper, nil, 0o600); err != nil {
		t.Skipf("the file system ignores case: %v", err)
	}
	if _, err := Discover(testRoot, nil); err != nil {
		t.Errorf("Discover with a TEST file next to the test root: %v", err)
	}
	if err := os.Remove(upper); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(upper, 0o700); err != nil {
		t.Fatal(err)
	}
	want := "opengrep/gogrep/rules/TEST is reserved: rules in it do not load, and fixtures belong in opengrep/gogrep/rules/test"
	if _, err := Discover(testRoot, nil); errText(err) != want {
		t.Errorf("Discover with a TEST directory next to the test root: %q, want %q", errText(err), want)
	}
}

func TestDiscoverRoot(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := Discover(testRoot, nil); errText(err) != "no opengrep/gogrep/rules/test directory here; run gogrep test from the project root" {
		t.Errorf("Discover without a test root: %q", errText(err))
	}
	// Whether or not the file system ignores case.
	upper := filepath.Join(filepath.Dir(testRoot), "Test")
	writeTree(t, upper, map[string]string{"go/x/rule.ref": "x\n", "go/x/a.go": "package a\n"})
	if _, err := Discover(testRoot, nil); errText(err) != "opengrep/gogrep/rules/Test must be spelled opengrep/gogrep/rules/test" {
		t.Errorf("Discover with a Test directory: %q", errText(err))
	}
	if err := os.RemoveAll(upper); err != nil {
		t.Fatal(err)
	}
	writeTree(t, testRoot, map[string]string{"go.mod": "module fixtures\n", "go/x/a.go": "package a\n"})
	if _, err := Discover(testRoot, nil); errText(err) != "no tests found under opengrep/gogrep/rules/test" {
		t.Errorf("Discover without fixtures: %q", errText(err))
	}

	// A rule.ref in the test root makes the root a fixture that holds all others.
	writeTree(t, testRoot, map[string]string{"rule.ref": "x\n", "expected.txt": "", "go/x/rule.ref": "x\n"})
	fixtures, err := Discover(testRoot, []string{"opengrep/gogrep/rules/test/go/x"})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	got := summarize(fixtures)
	want := []summary{
		{Name: "opengrep/gogrep/rules/test", Setup: "fixtures live in opengrep/gogrep/rules/test/<namespace>/<fixture>/"},
		{Name: "opengrep/gogrep/rules/test/go/x", Namespace: "go", Setup: "fixture is nested inside opengrep/gogrep/rules/test"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Discover = %v, want %v", got, want)
	}
}
