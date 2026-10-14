package gogrep

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Every method may run on many goroutines at once, on one Engine and on two
// Engines that share a CacheDir. Under -race, this also checks that they
// share no unguarded state.
func TestConcurrentMethods(t *testing.T) {
	t.Parallel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "log.json")
	writeTree(t, filepath.Dir(log), map[string]string{"log.json": `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "opengrep", "rules": [{"id": "project.go.no-exec-command"}]}},` +
		`"invocations": [{"executionSuccessful": true, "toolExecutionNotifications": []}], "results": []}]}`})
	cfg := Config{Opengrep: exe, CacheDir: t.TempDir(), Env: []string{"GOGREP_TEST_FAKE_OPENGREP=1", "GOGREP_TEST_FAKE_SARIF=" + log}}
	engines := []*Engine{newEngine(t, cfg), newEngine(t, cfg)}
	dir := t.TempDir()
	writeTree(t, dir, fixtures)
	ctx := context.Background()

	calls := []func(e *Engine) error{
		func(e *Engine) error {
			_, err := e.Rules(dir, &RulesOptions{Selection: Selection{Suites: []string{"all"}}})
			return err
		},
		func(e *Engine) error { _, err := e.Suites(dir, nil); return err },
		func(e *Engine) error { _, err := e.Scan(ctx, dir, nil); return err },
		func(e *Engine) error {
			cmd, err := e.Command(ctx, dir, &CommandOptions{Selection: &Selection{}}, "scan", "--sarif", ".")
			if err != nil {
				return err
			}
			return cmd.Run()
		},
		func(e *Engine) error { _, err := e.Test(ctx, dir, &TestOptions{ReadOnly: true, Jobs: 2}); return err },
		func(e *Engine) error { _, err := e.Opengrep(ctx); return err },
	}
	var wg sync.WaitGroup
	for range 2 {
		for _, e := range engines {
			for _, call := range calls {
				wg.Go(func() {
					if err := call(e); err != nil {
						t.Error(err)
					}
				})
			}
		}
	}
	wg.Wait()
}
