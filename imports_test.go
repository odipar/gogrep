package gogrep

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The opengrep binary never enters the library's import graph, whatever the
// build tags: go mod vendor resolves the go:embed patterns of every package
// it vendors, and internal/bundle embeds files that a module download lacks.
func TestImportsNoBinary(t *testing.T) {
	t.Parallel()
	gocmd, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command:", err)
	}
	for _, tags := range []string{"", "gogrep_bundled", "gogrep_bundled,gogrep_musl"} {
		out, err := exec.Command(gocmd, "list", "-deps", "-tags", tags, ".").Output()
		if err != nil {
			t.Fatalf("go list -deps -tags %q: %v", tags, err)
		}
		if deps := strings.Fields(string(out)); slices.Contains(deps, "github.com/odipar/gogrep/internal/bundle") {
			t.Errorf("with tags %q, the library depends on internal/bundle", tags)
		}
	}
}
