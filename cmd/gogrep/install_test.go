package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/odipar/gogrep/internal/bundle"
)

func TestInstallOpengrep(t *testing.T) {
	isolateCache(t)
	t.Setenv("OPENGREP_BIN", "")
	tests := []struct {
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{[]string{"install-opengrep", "-h"}, 0, installUsage, ""},
		{[]string{"install-opengrep", "--from"}, 2, "", "gogrep: --from needs a value\n"},
		{[]string{"install-opengrep", "--suite", "all"}, 2, "", "gogrep: gogrep install-opengrep takes --from and --base-url, not --suite\n"},
		{[]string{"install-opengrep", "--base-url=ftp://example.com"}, 1, "", "gogrep: InstallOptions.BaseURL ftp://example.com is not an http or https URL\n"},
	}
	if len(bundle.Binary()) > 0 {
		tests = tests[:3] // a bundled gogrep installs the opengrep built in
	}
	for _, tt := range tests {
		code, stdout, stderr := runGogrep(tt.args...)
		if code != tt.code || stdout != tt.stdout || stderr != tt.stderr {
			t.Errorf("gogrep %q = %d, %q, %q; want %d, %q, %q", tt.args, code, stdout, stderr, tt.code, tt.stdout, tt.stderr)
		}
	}
}

// A file that is not the pinned opengrep is refused, and nothing is
// installed.
func TestInstallOpengrepFrom(t *testing.T) {
	if len(bundle.Binary()) > 0 {
		t.Skip("a bundled gogrep installs the opengrep built in")
	}
	isolateCache(t)
	t.Setenv("OPENGREP_BIN", "")
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("opengrep", []byte("not opengrep"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("not opengrep"))
	code, stdout, stderr := runGogrep("install-opengrep", "--from", "opengrep")
	want := "gogrep: " + filepath.Join(dir, "opengrep") + ": SHA-256 " + hex.EncodeToString(sum[:]) + ", want the pinned "
	if code != 1 || stdout != "" || !strings.HasPrefix(stderr, want) || strings.Count(stderr, "\n") != 1 {
		t.Errorf("gogrep install-opengrep --from opengrep = %d, %q, %q; want 1, no stdout, %q…", code, stdout, stderr, want)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(filepath.Join(cache, "gogrep", "opengrep-*", "*")); len(left) != 0 {
		t.Errorf("the refused install left %q", left)
	}
}
