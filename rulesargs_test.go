package main

import (
	"os"
	"path/filepath"
	"slices"
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
