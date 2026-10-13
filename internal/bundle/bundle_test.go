//go:build gogrep_bundled

package bundle

import (
	"os"
	"runtime"
	"testing"

	"github.com/odipar/gogrep/internal/opengrep"
	"github.com/odipar/gogrep/internal/pin"
)

// muslBuild is set in builds with -tags gogrep_musl.
var muslBuild bool

func TestBinaryIsPinned(t *testing.T) {
	data, err := os.ReadFile("../../opengrep.json")
	if err != nil {
		t.Fatal(err)
	}
	pins, err := pin.Parse(data)
	if err != nil {
		t.Fatalf("opengrep.json: %v", err)
	}
	key := pin.Keys(runtime.GOOS, runtime.GOARCH, muslBuild)[0]
	a, ok := pins.Assets[key]
	switch got := Binary(); {
	case !ok && len(got) > 0:
		t.Errorf("Binary() holds %d bytes; want none, since opengrep.json pins no opengrep for %s", len(got), key)
	case ok && opengrep.SHA256(got) != a.SHA256:
		t.Errorf("SHA-256 of Binary() = %s, want %s, the pin for %s", opengrep.SHA256(got), a.SHA256, key)
	}
}
