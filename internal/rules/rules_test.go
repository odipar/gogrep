package rules

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
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
