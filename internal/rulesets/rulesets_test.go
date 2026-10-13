package rulesets

import (
	"encoding/json"
	"maps"
	"os"
	"slices"
	"testing"

	"github.com/odipar/gogrep/internal/rules"
)

// TestStampsMatchPins checks that the committed archives are the rule sets
// opengrep.json pins: a rule set re-pinned without running
// tools/fetch-opengrep fails here.
func TestStampsMatchPins(t *testing.T) {
	data, err := os.ReadFile("../../opengrep.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Rules []struct{ Name, Commit, Path, Lang string }
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("opengrep.json: %v", err)
	}
	archives, stamps := Archives(), Stamps()
	var pinned []string
	for _, r := range cfg.Rules {
		pinned = append(pinned, r.Name)
		if want := r.Commit + " " + r.Path + " " + r.Lang; stamps[r.Name] != want {
			t.Errorf("%s.commit = %q, want %q as opengrep.json pins it; run go run ./tools/fetch-opengrep", r.Name, stamps[r.Name], want)
		}
		if set, err := rules.FromTarGz(archives[r.Name]); err != nil || len(set) == 0 {
			t.Errorf("%s.tar.gz holds no rules: %v", r.Name, err)
		}
	}
	slices.Sort(pinned)
	for name, got := range map[string][]string{".tar.gz": slices.Sorted(maps.Keys(archives)), ".commit": slices.Sorted(maps.Keys(stamps))} {
		if !slices.Equal(got, pinned) {
			t.Errorf("%s files are of rule sets %q, want those opengrep.json pins: %q", name, got, pinned)
		}
	}
}
