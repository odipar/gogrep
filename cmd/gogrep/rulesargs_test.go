package gogrep

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/odipar/gogrep/internal/engine"
)

const noExecRule = `rules:
  - id: no-exec-command
    languages: [go]
    severity: WARNING
    message: Avoid running $CMD with exec.Command
    pattern: exec.Command($CMD, ...)
`

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

// isolateCache points os.UserCacheDir at a temporary directory, so the test
// never writes to the user's cache.
func isolateCache(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir) // Linux
	t.Setenv("HOME", dir)           // macOS: $HOME/Library/Caches
	t.Setenv("LocalAppData", dir)   // Windows
}

func TestWithRules(t *testing.T) {
	isolateCache(t)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"opengrep/gogrep/rules/go/no-exec-command.yaml": noExecRule})
	t.Chdir(dir)
	t.Setenv("SEMGREP_RULES", "")
	c := newTestCLI(t)

	tests := []struct {
		args []string
		want []string // the args after "scan" and gogrep's injected ones; nil: args unchanged
	}{
		{[]string{"scan", "."}, []string{"."}},
		{[]string{"scan", "--rule", "no-exec-command", "--sarif", "."}, []string{"--sarif", "."}},
		{[]string{"scan", "--config", "bundled", "."}, []string{"."}},
		{[]string{"scan", "--config=bundled", "."}, []string{"."}},
		{[]string{"scan", "--rule=no-exec-command", "--", "-x.go"}, []string{"--", "-x.go"}},
		{[]string{"scan", "--config", "my-rules/", "."}, nil},
		{[]string{"scan", "--config=auto", "."}, nil},
		{[]string{"scan", "-e", "exec.Command(...)", "--lang", "go", "."}, nil},
		{[]string{"ci"}, nil},
		{[]string{"--version"}, nil},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			args, sel, err := gogrepFlags(tt.args)
			if err != nil {
				t.Fatalf("gogrepFlags: %v", err)
			}
			got, err := c.withRules(args, sel)
			if err != nil {
				t.Fatalf("withRules: %v", err)
			}
			if tt.want == nil {
				if !slices.Equal(got, args) {
					t.Errorf("withRules(%q) = %q, want it unchanged", args, got)
				}
				return
			}
			want := slices.Concat([]string{"scan", "--config", "<abs config>", "--no-rewrite-rule-ids", "--disable-version-check", "--exclude=opengrep/gogrep/rules/test"}, tt.want)
			if len(got) > 2 && filepath.IsAbs(got[2]) {
				got[2] = "<abs config>"
			}
			if !slices.Equal(got, want) {
				t.Errorf("withRules(%q) = %q, want %q", args, got, want)
			}
		})
	}

	t.Run("SEMGREP_RULES", func(t *testing.T) {
		t.Setenv("SEMGREP_RULES", "my-rules/")
		args := []string{"scan", "."}
		if got, err := c.withRules(args, selection{}); err != nil || !slices.Equal(got, args) {
			t.Errorf("withRules(%q) = %q, %v; want it unchanged", args, got, err)
		}
	})
}

func TestGogrepFlags(t *testing.T) {
	filter := func(field string, values ...string) engine.Filter { return engine.Filter{Field: field, Values: values} }
	tests := []struct {
		args   []string
		rest   []string
		want   selection
		errMsg string
	}{
		{nil, nil, selection{}, ""},
		{[]string{"scan", "--rule", "no-exec-command", "."}, []string{"scan", "."},
			selection{engine.Selection{Rules: []string{"no-exec-command"}}, true}, ""},
		{[]string{"--rule=no-exec-command,todo-marker"}, nil,
			selection{engine.Selection{Rules: []string{"no-exec-command", "todo-marker"}}, true}, ""},
		{[]string{"--gogrep-lang", "go"}, nil,
			selection{engine.Selection{Filters: []engine.Filter{filter("languages", "go")}}, false}, ""},
		{[]string{"--suite", "all", "--gogrep-lang=generic", "--gogrep-lang", "go, c", "--gogrep-category=security", "--gogrep-ruleset", "project"}, nil,
			selection{engine.Selection{Suites: []string{"all"}, Filters: []engine.Filter{
				filter("languages", "generic"), filter("languages", "go", "c"), filter("category", "security"), filter("ruleset", "project"),
			}}, true}, ""},
		{[]string{"--suite="}, nil, selection{explicit: true}, ""},
		{[]string{"--gogrep-lang="}, nil, selection{engine.Selection{Filters: []engine.Filter{filter("languages")}}, false}, ""},
		{[]string{"--suite"}, nil, selection{}, "--suite needs a value"},
		{[]string{"--gogrep-lang", "/(/"}, nil, selection{}, "--gogrep-lang: error parsing regexp: missing closing ): `(`"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			rest, sel, err := gogrepFlags(tt.args)
			if tt.errMsg != "" {
				if err == nil || err.Error() != tt.errMsg {
					t.Errorf("gogrepFlags(%q) error = %v, want %q", tt.args, err, tt.errMsg)
				}
				return
			}
			if err != nil || !slices.Equal(rest, tt.rest) || !reflect.DeepEqual(sel, tt.want) {
				t.Errorf("gogrepFlags(%q) = %q, %+v, %v; want %q, %+v", tt.args, rest, sel, err, tt.rest, tt.want)
			}
		})
	}
}
