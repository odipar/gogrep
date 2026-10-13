package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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

func TestLoadEnvSkipsProjectTests(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"opengrep/gogrep/rules/go/no-exec-command.yaml":          noExecRule,
		"opengrep/gogrep/rules/test/go/exec-command/rule.ref":    "no-exec-command\n",
		"opengrep/gogrep/rules/test/go/exec-command/broken.yaml": "rules: [\n",
		"opengrep/gogrep/rules/test/go/exec-command/live.yaml":   noExecRule,
		"opengrep/gogrep/rules/test/live.yaml":                   noExecRule,
	})
	t.Chdir(dir)

	env, err := loadEnv()
	if err != nil {
		t.Fatalf("loadEnv: %v", err)
	}
	var got []string
	for _, r := range env.Sets["project"] {
		got = append(got, r.ID)
	}
	if want := []string{"project.go.no-exec-command"}; !slices.Equal(got, want) {
		t.Errorf("project rules = %q, want %q", got, want)
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
			got, err := withRules(args, sel)
			if err != nil {
				t.Fatalf("withRules: %v", err)
			}
			if tt.want == nil {
				if !slices.Equal(got, args) {
					t.Errorf("withRules(%q) = %q, want it unchanged", args, got)
				}
				return
			}
			want := slices.Concat([]string{"scan", "--config", "<abs config>", "--no-rewrite-rule-ids", "--exclude=opengrep/gogrep/rules/test"}, tt.want)
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
		if got, err := withRules(args, selection{}); err != nil || !slices.Equal(got, args) {
			t.Errorf("withRules(%q) = %q, %v; want it unchanged", args, got, err)
		}
	})
}
