package main

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The command is a thin layer over the public API: of this module's packages,
// it imports only the root package, internal/bundle (the embedded opengrep)
// and internal/sarif (Rebrand and Check). Test imports do not count.
func TestCLIUsesPublicAPI(t *testing.T) {
	gocmd, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command:", err)
	}
	allowed := []string{"github.com/odipar/gogrep", "github.com/odipar/gogrep/internal/bundle", "github.com/odipar/gogrep/internal/sarif"}
	for _, tags := range []string{"", "gogrep_bundled"} {
		cmd := exec.Command(gocmd, "list", "-tags", tags, "-f", `{{join .Imports "\n"}}`, "github.com/odipar/gogrep/cmd/gogrep")
		cmd.Dir = repoDir
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list -tags %q: %v", tags, err)
		}
		imports := strings.Fields(string(out))
		if !slices.Contains(imports, allowed[0]) {
			t.Errorf("with tags %q, cmd/gogrep does not import %s: %q", tags, allowed[0], imports)
		}
		for _, p := range imports {
			if (p == allowed[0] || strings.HasPrefix(p, allowed[0]+"/")) && !slices.Contains(allowed, p) {
				t.Errorf("with tags %q, cmd/gogrep imports %s; it may import only %q of this module", tags, p, allowed)
			}
		}
	}
}
