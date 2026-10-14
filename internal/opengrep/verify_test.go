package opengrep

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestFileSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "opengrep")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got, err := FileSHA256(path); err != nil || got != abc {
		t.Fatalf("FileSHA256 = %s, %v; want %s", got, err, abc)
	}

	if runtime.GOOS != "windows" {
		// An unchanged file is not read again.
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		if got, err := FileSHA256(path); err != nil || got != abc {
			t.Errorf("FileSHA256 of the unreadable, unchanged file = %s, %v; want %s from the first call", got, err, abc)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// A change of contents changes the size or the modification time.
	if err := os.WriteFile(path, []byte("abd"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	if got, err := FileSHA256(path); err != nil || got != SHA256([]byte("abd")) {
		t.Errorf("FileSHA256 of the changed file = %s, %v; want %s", got, err, SHA256([]byte("abd")))
	}

	if _, err := FileSHA256(filepath.Join(t.TempDir(), "missing")); !os.IsNotExist(err) {
		t.Errorf("FileSHA256 of a missing file: %v, want a not-exist error", err)
	}
}
