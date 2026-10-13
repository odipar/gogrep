package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

// rule returns a rule file holding one rule per id.
func rule(ids ...string) []byte {
	var b strings.Builder
	b.WriteString("rules:\n")
	for _, id := range ids {
		b.WriteString("  - id: " + id + "\n    languages: [go]\n    severity: WARNING\n    message: m\n    pattern: f()\n")
	}
	return []byte(b.String())
}

func ids(rs []*Rule) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func TestFromFSSkipDirs(t *testing.T) {
	fsys := fstest.MapFS{
		"README.md":                {Data: []byte("# rules\n")},
		"go/a.yaml":                {Data: rule("a")},
		"go/test/b.yaml":           {Data: rule("b")},
		"go/tests/c.yaml":          {Data: rule("c")},
		"testing/d.yaml":           {Data: rule("d")},
		"test.yaml":                {Data: rule("e")},
		"test/go/exec/rule.ref":    {Data: []byte("a\n")},
		"test/go/exec/sample.yaml": {Data: []byte("rules: [\n")},
		"test/go/exec/sub/x.go":    {Data: []byte("package sub\n")},
		"Test/x/y.yaml":            {Data: []byte("rules: [\n")},
		"TEST/z.yaml":              {Data: rule("z")},
	}
	without := func(skipped ...string) []string {
		return slices.DeleteFunc(slices.Sorted(maps.Keys(fsys)), func(p string) bool {
			return slices.Contains(skipped, p)
		})
	}
	withoutTest := without("test/go/exec/rule.ref", "test/go/exec/sample.yaml", "test/go/exec/sub/x.go", "Test/x/y.yaml", "TEST/z.yaml")

	tests := []struct {
		name     string
		skipDirs []string
		want     []string
	}{
		{"none", nil, without()},
		{"top-level test only", []string{"test"}, withoutTest},
		{"missing dir", []string{"nope", "test"}, withoutTest},
		{"nested path", []string{"go/test"}, without("go/test/b.yaml")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set, err := FromFS(fsys, tt.skipDirs...)
			if err != nil {
				t.Fatalf("FromFS: %v", err)
			}
			if got := slices.Sorted(maps.Keys(set)); !slices.Equal(got, tt.want) {
				t.Errorf("FromFS(%q) paths = %q, want %q", tt.skipDirs, got, tt.want)
			}
			if got, want := string(set["go/a.yaml"]), string(fsys["go/a.yaml"].Data); got != want {
				t.Errorf("go/a.yaml = %q, want %q", got, want)
			}
		})
	}
}

// A test root that is a symlink (to fixtures shared between projects) must be
// skipped too, not read as a file. So are other symlinked directories, which
// WalkDir does not enter, and devices, which could be endless; a symlinked
// file is read.
func TestFromFSSkipsSymlinkedDir(t *testing.T) {
	dir := t.TempDir()
	shared := t.TempDir()
	if err := os.WriteFile(filepath.Join(shared, "x.yaml"), []byte("rules: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "go"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go", "a.yaml"), rule("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shared, filepath.Join(dir, "test")); err != nil {
		t.Skipf("cannot create symlinks: %v", err)
	}
	links := map[string]string{"go/shared": shared, "go/linked.yaml": filepath.Join(shared, "x.yaml")}
	if runtime.GOOS != "windows" {
		links["go/zero.yaml"] = "/dev/zero"
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, filepath.FromSlash(name))); err != nil {
			t.Fatal(err)
		}
	}
	set, err := FromFS(os.DirFS(dir), "test")
	if err != nil {
		t.Fatalf("FromFS: %v", err)
	}
	if got, want := slices.Sorted(maps.Keys(set)), []string{"go/a.yaml", "go/linked.yaml"}; !slices.Equal(got, want) {
		t.Errorf("FromFS paths = %q, want %q", got, want)
	}
}

func TestParseIDs(t *testing.T) {
	sets := map[string]Set{
		"project": {
			"top.yaml":       rule("top"),
			"go/a.yaml":      rule("dup", "same", "same"),
			"go/b.yml":       rule("dup"),
			"go/net/c.yaml":  rule("dial"),
			"go/noid.yaml":   []byte("rules:\n  - message: no id\n  - id: \"\"\n"),
			"go/notes.json":  rule("ignored"),
			"go/LICENSE":     []byte("not: [yaml\n"),
			"go/README.md":   []byte("# not a rule file\n"),
			"go/x/y/z.yaml":  rule("deep"),
			"go/x/y/z2.yaml": rule("deep"),
		},
		"gogrep": {"go/a.yaml": rule("dup")},
	}
	rs, err := Parse(sets)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{
		"gogrep.go.dup",
		"project.go.a.same",
		"project.go.b.dup",
		"project.go.dup",
		"project.go.net.dial",
		"project.go.same",
		"project.go.x.y.deep",
		"project.go.x.y.z2.deep",
		"project.top",
	}
	if got := ids(rs); !slices.Equal(got, want) {
		t.Errorf("Parse ids = %q, want %q", got, want)
	}

	byID := map[string]*Rule{}
	for _, r := range rs {
		byID[r.ID] = r
	}
	if r := byID["project.go.b.dup"]; r == nil || r.Set != "project" || r.Path != "go/b.yml" {
		t.Errorf("project.go.b.dup = %+v, want set project, path go/b.yml", r)
	}
	f := byID["project.go.net.dial"].Fields()
	if got := f["ruleset"]; !slices.Equal(got, []string{"project"}) {
		t.Errorf("ruleset field = %q, want [project]", got)
	}
	if got := f["languages"]; !slices.Equal(got, []string{"go"}) {
		t.Errorf("languages field = %q, want [go]", got)
	}
}

func TestParseMalformedYAMLAborts(t *testing.T) {
	sets := map[string]Set{
		"gogrep":  {"go/a.yaml": rule("a")},
		"project": {"go/x.yaml": []byte("rules: [\n")},
	}
	rs, err := Parse(sets)
	if err == nil {
		t.Fatalf("Parse = %q, want an error", ids(rs))
	}
	if want := "project/go/x.yaml: yaml: "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("Parse error = %q, want prefix %q", err, want)
	}
}

func TestParseIgnoresNonRuleYAML(t *testing.T) {
	for _, data := range []string{
		"",
		"# nothing\n",
		"---\n",
		"just text\n",
		"- id: x\n",
		"name: x\nvalue: [1, 2]\n",
		"rules: x\n",
		"rules:\n  id: x\n",
	} {
		rs, err := Parse(map[string]Set{"project": {"x.yaml": []byte(data)}})
		if err != nil || len(rs) != 0 {
			t.Errorf("Parse(%q) = %q, %v; want no rules and no error", data, ids(rs), err)
		}
	}
}

// written is the rule file Write writes for the rules of writeRules.
const written = `rules:
    - id: project.go.a
      languages: [go]
      severity: WARNING
      message: m
      pattern: f()
    - id: project.go.b
      languages: [go]
      severity: WARNING
      message: m
      pattern: f()
`

// writeRules returns the rules project.go.a and project.go.b.
func writeRules(t *testing.T) []*Rule {
	t.Helper()
	rs, err := Parse(map[string]Set{"project": {"go/a.yaml": rule("a", "b")}})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// checkWritten checks that file, in dir, holds data and is named after it,
// and that dir holds no other file.
func checkWritten(t *testing.T, dir, file, data string) {
	t.Helper()
	sum := sha256.Sum256([]byte(data))
	if want := filepath.Join(dir, hex.EncodeToString(sum[:])[:16]+".yaml"); file != want {
		t.Errorf("Write = %s, want %s", file, want)
	}
	if got, err := os.ReadFile(file); string(got) != data {
		t.Errorf("%s = %q, %v; want %q", file, got, err, data)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Errorf("%s holds %v, %v; want only %s", dir, entries, err, filepath.Base(file))
	}
}

func TestWrite(t *testing.T) {
	t.Parallel()
	rs := writeRules(t)
	parent := filepath.Join(t.TempDir(), "gogrep")
	dir := filepath.Join(parent, "selections")
	file, err := Write(dir, rs)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	checkWritten(t, dir, file, written)
	for _, r := range rs {
		if id := value(r.node, "id").Value; id != strings.TrimPrefix(r.ID, "project.go.") {
			t.Errorf("Write changed the id of rule %s to %q", r.ID, id)
		}
	}
	if runtime.GOOS != "windows" {
		for p, want := range map[string]os.FileMode{file: 0o600, dir: 0o700 | os.ModeDir, parent: 0o700 | os.ModeDir} {
			if fi, err := os.Stat(p); err != nil || fi.Mode() != want {
				t.Errorf("%s: mode %v, %v; want %v", p, fi.Mode(), err, want)
			}
		}
	}

	if again, err := Write(dir, writeRules(t)); err != nil || again != file {
		t.Errorf("Write of the same rules = %s, %v; want %s", again, err, file)
	}
	other, err := Write(dir, rs[1:])
	if err != nil || other == file {
		t.Fatalf("Write of another selection = %s, %v; want another file", other, err)
	}
	if data, err := os.ReadFile(other); err != nil || !strings.HasPrefix(string(data), "rules:\n    - id: project.go.b\n") || strings.Contains(string(data), "project.go.a") {
		t.Errorf("%s = %q, %v; want only project.go.b", other, data, err)
	}
}

// Reusing a file marks it used, for pruning.
func TestWriteRefreshesModTime(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file, err := Write(dir, writeRules(t))
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(file, old, old); err != nil {
		t.Fatal(err)
	}
	if again, err := Write(dir, writeRules(t)); err != nil || again != file {
		t.Fatalf("Write again = %s, %v; want %s", again, err, file)
	}
	fi, err := os.Stat(file)
	if err != nil || !fi.ModTime().After(old.Add(47*time.Hour)) {
		t.Errorf("modification time after Write = %v, %v; want about now", fi.ModTime(), err)
	}
	checkWritten(t, dir, file, written)
}

// A Write that loses the race to rename its file into place uses the
// winner's, which has the same content; any other failure is an error.
func TestWriteRenameFallback(t *testing.T) {
	t.Parallel()
	data := []byte(written)
	t.Run("lost the race", func(t *testing.T) {
		dir := t.TempDir()
		file, err := write(dir, data, func(_, newpath string) error {
			if err := os.WriteFile(newpath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			return errors.New("in use")
		})
		if err != nil {
			t.Fatalf("write = %s, %v; want the file another Write renamed into place", file, err)
		}
		checkWritten(t, dir, file, written)
	})

	t.Run("failed", func(t *testing.T) {
		dir := t.TempDir()
		file, err := write(dir, data, func(string, string) error { return errors.New("in use") })
		if err == nil || err.Error() != "in use" {
			t.Errorf("write = %s, %v; want the rename's error", file, err)
		}
		if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
			t.Errorf("%s holds %v, %v; want nothing", dir, entries, err)
		}
	})

	t.Run("a directory in the way", func(t *testing.T) {
		dir := t.TempDir()
		sum := sha256.Sum256(data)
		blocked := filepath.Join(dir, hex.EncodeToString(sum[:])[:16]+".yaml")
		if err := os.MkdirAll(filepath.Join(blocked, "x"), 0o700); err != nil {
			t.Fatal(err)
		}
		if file, err := Write(dir, writeRules(t)); err == nil {
			t.Errorf("Write = %s, nil; want an error", file)
		}
		if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
			t.Errorf("%s holds %v, %v; want only the directory", dir, entries, err)
		}
	})
}

func TestWriteConcurrent(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "selections")
	rs := writeRules(t)
	files := make([]string, 8)
	errs := make([]error, len(files))
	var wg sync.WaitGroup
	for i := range files {
		wg.Go(func() { files[i], errs[i] = Write(dir, rs) })
	}
	wg.Wait()
	for i := range files {
		if errs[i] != nil || files[i] != files[0] {
			t.Errorf("Write %d = %s, %v; want %s", i, files[i], errs[i], files[0])
		}
	}
	checkWritten(t, dir, files[0], written)
}
