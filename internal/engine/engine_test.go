package engine

import (
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// testFiles are the files that the module root embeds, read from the
// repository.
var testFiles = sync.OnceValue(func() Files {
	pins, err := os.ReadFile(filepath.Join("..", "..", "opengrep.json"))
	if err != nil {
		panic(err)
	}
	return Files{
		Rules:  os.DirFS(filepath.Join("..", "..", "rules")),
		Suites: os.DirFS(filepath.Join("..", "..", "suites")),
		Pins:   pins,
	}
})

// newEngine returns an Engine with cfg, a temporary CacheDir unless cfg
// sets one, and an empty environment unless cfg sets one.
func newEngine(t *testing.T, cfg Config) *Engine {
	t.Helper()
	if cfg.CacheDir == "" {
		cfg.CacheDir = t.TempDir()
	}
	if cfg.Env == nil {
		cfg.Env = []string{}
	}
	e, err := New(cfg, testFiles())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

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

// rule returns a rule file that holds the rule id.
func rule(id, lang string) string {
	return "rules:\n  - id: " + id + "\n    languages: [" + lang + "]\n    severity: WARNING\n    message: m\n    pattern: f()\n"
}

const noExecRule = `rules:
  - id: no-exec-command
    languages: [go]
    severity: WARNING
    message: Avoid running $CMD with exec.Command
    pattern: exec.Command($CMD, ...)
`

func TestNew(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{CacheDir: "cache"}, testFiles()); err == nil || err.Error() != "Config.CacheDir cache is not an absolute path" {
		t.Errorf("New with a relative CacheDir = %v, want an error", err)
	}

	e, err := New(Config{}, testFiles())
	if err != nil {
		t.Fatal(err)
	}
	cache, err := os.UserCacheDir()
	if want := filepath.Join(cache, "gogrep"); err == nil && e.cacheDir != want {
		t.Errorf("default CacheDir = %s, want %s", e.cacheDir, want)
	}
	if !slices.Equal(e.env, os.Environ()) || e.log == nil {
		t.Errorf("the zero Config's Env and Logger are %d variables and %v; want os.Environ() and a discarding logger", len(e.env), e.log)
	}

	env := []string{"A=1"}
	e, err = New(Config{CacheDir: t.TempDir(), Env: env}, testFiles())
	env[0] = "A=2"
	if err != nil || !slices.Equal(e.env, []string{"A=1"}) {
		t.Errorf("Engine.env = %q, %v; want New's copy of Config.Env", e.env, err)
	}
}

// The project's rule test fixtures are never loaded as rules, whatever the
// letter case of their directory.
func TestLoadEnvSkipsProjectTests(t *testing.T) {
	t.Parallel()
	for _, test := range []string{"test", "Test"} {
		dir := t.TempDir()
		writeTree(t, dir, map[string]string{
			"opengrep/gogrep/rules/go/no-exec-command.yaml":                  noExecRule,
			"opengrep/gogrep/rules/" + test + "/go/exec-command/rule.ref":    "no-exec-command\n",
			"opengrep/gogrep/rules/" + test + "/go/exec-command/broken.yaml": "rules: [\n",
			"opengrep/gogrep/rules/" + test + "/go/exec-command/live.yaml":   noExecRule,
			"opengrep/gogrep/rules/" + test + "/live.yaml":                   noExecRule,
		})
		env, err := newEngine(t, Config{}).loadEnv(dir, false)
		if err != nil {
			t.Fatalf("loadEnv: %v", err)
		}
		var got []string
		for _, r := range env.Sets["project"] {
			got = append(got, r.ID)
		}
		if want := []string{"project.go.no-exec-command"}; !slices.Equal(got, want) {
			t.Errorf("project rules with %s/ = %q, want %q", test, got, want)
		}
	}
}

func TestLoadEnvProjectErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"opengrep/gogrep/rules/go/bad.yaml": "rules: [\n"})
	e := newEngine(t, Config{})
	if _, err := e.loadEnv(dir, false); err == nil || !strings.HasPrefix(err.Error(), "project/go/bad.yaml: yaml: ") {
		t.Errorf("loadEnv of a broken project rule = %v, want a project/go/bad.yaml error", err)
	}
	if env, err := e.loadEnv(dir, true); err != nil || env.Sets["project"] != nil {
		t.Errorf("loadEnv without project rules = %v, %v; want an empty project set", env.Sets["project"], err)
	}
}

func TestSelectionFilter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"opengrep/gogrep/rules/go/no-exec-command.yaml":  rule("no-exec-command", "go"),
		"opengrep/gogrep/rules/go/no-os-exit.yaml":       rule("no-os-exit", "go"),
		"opengrep/gogrep/rules/generic/todo-marker.yaml": rule("todo-marker", "generic"),
	})
	env, err := newEngine(t, Config{}).loadEnv(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	// Only the project's rules, so that the results are small.
	for name := range env.Sets {
		if name != "project" {
			env.Sets[name] = nil
		}
	}
	lang := func(values ...string) Filter { return Filter{Field: "languages", Values: values} }

	tests := []struct {
		sel    Selection
		want   []string // the selected ids; nil when the selection is not active
		errMsg string
	}{
		{Selection{}, nil, ""},
		{Selection{Rules: []string{"no-exec-command"}}, []string{"project.go.no-exec-command"}, ""},
		{Selection{Rules: []string{"no-exec-command", "todo-marker"}}, []string{"project.generic.todo-marker", "project.go.no-exec-command"}, ""},
		{Selection{Filters: []Filter{lang("go")}}, []string{"project.go.no-exec-command", "project.go.no-os-exit"}, ""},
		{Selection{Suites: []string{"all"}, Filters: []Filter{lang("generic")}}, []string{"project.generic.todo-marker"}, ""},
		{Selection{Suites: []string{"all"}, Filters: []Filter{lang("generic", "go"), lang("/^g/")}}, []string{"project.generic.todo-marker", "project.go.no-exec-command", "project.go.no-os-exit"}, ""},
		{Selection{Suites: []string{"all"}, Filters: []Filter{lang("generic"), lang("go")}}, nil, "the selection matches no rules"},
		{Selection{Filters: []Filter{lang()}}, nil, "the selection matches no rules"},
		{Selection{Rules: []string{"nope"}}, nil, "rule nope matches no rule"},
		{Selection{Rules: []string{"no-exec-command"}, Filters: []Filter{lang("generic")}}, nil, "the selection matches no rules"},
	}
	for _, tt := range tests {
		ids, active, err := tt.sel.filter(env)
		if tt.errMsg != "" {
			if err == nil || err.Error() != tt.errMsg {
				t.Errorf("filter(%+v) error = %v, want %q", tt.sel, err, tt.errMsg)
			}
			continue
		}
		if err != nil {
			t.Fatalf("filter(%+v): %v", tt.sel, err)
		}
		got := slices.Sorted(maps.Keys(ids))
		if active != (tt.want != nil) || !slices.Equal(got, tt.want) {
			t.Errorf("filter(%+v) = %q, %v; want %q, %v", tt.sel, got, active, tt.want, tt.want != nil)
		}
	}
}

func TestSelectionErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"opengrep/gogrep/rules/go/no-exec-command.yaml": noExecRule,
		"suites/imports.yaml":                           "- import: web\n",
		"suites/bad.yaml":                               "- frobnicate: x\n",
	})
	e := newEngine(t, Config{})
	// The operating system's words for a missing file.
	_, err := os.ReadFile(filepath.Join(dir, "suites", "missing.yaml"))
	var notExist *fs.PathError
	if !errors.As(err, &notExist) {
		t.Fatalf("reading a missing file: %v", err)
	}
	tests := []struct {
		sel   Selection
		kind  string
		value string
		is    error
		text  string
	}{
		{Selection{Suites: []string{"web"}}, "suite", "web", ErrUnknownSuite, `unknown suite "web"`},
		{Selection{Suites: []string{"suites/imports.yaml"}}, "suite", "web", ErrUnknownSuite, `suite suites/imports.yaml: unknown suite "web"`},
		{Selection{Suites: []string{"suites/missing.yaml"}}, "suite", "suites/missing.yaml", fs.ErrNotExist, "open suites/missing.yaml: " + notExist.Err.Error()},
		{Selection{Suites: []string{"suites/bad.yaml"}}, "suite", "suites/bad.yaml", nil,
			"suite suites/bad.yaml: instruction 1 (frobnicate): unknown instruction; want description, rules, import, include or exclude"},
		{Selection{Rules: []string{"use-of-md6"}}, "rule", "use-of-md6", ErrNoRules, "rule use-of-md6 matches no rule"},
		{Selection{Rules: []string{"/(/"}}, "rule", "/(/", nil, "rule /(/: error parsing regexp: missing closing ): `(`"},
		{Selection{Filters: []Filter{{Field: "languages", Values: []string{"/(/"}}}}, "filter", "languages", nil, "filter languages: error parsing regexp: missing closing ): `(`"},
		{Selection{Filters: []Filter{{Values: []string{"go"}}}}, "filter", "", nil, "filter: no field"},
	}
	for _, tt := range tests {
		_, err := e.Rules(dir, &RulesOptions{Selection: tt.sel})
		var se *SelectionError
		if !errors.As(err, &se) || se.Kind != tt.kind || se.Value != tt.value || tt.is != nil && !errors.Is(err, tt.is) || err.Error() != tt.text {
			t.Errorf("Rules(%+v) = %#v; want a *SelectionError %s %q, %q", tt.sel, err, tt.kind, tt.value, tt.text)
		}
		if strings.HasPrefix(tt.text, "unknown") || strings.HasPrefix(tt.text, "suite") || strings.HasPrefix(tt.text, "open") || tt.is == ErrNoRules {
			if err := tt.sel.Validate(); err != nil {
				t.Errorf("Validate(%+v) = %v; want nil, as it loads nothing", tt.sel, err)
			}
		} else if err := tt.sel.Validate(); err == nil || err.Error() != tt.text {
			t.Errorf("Validate(%+v) = %v; want %q", tt.sel, err, tt.text)
		}
	}
}
