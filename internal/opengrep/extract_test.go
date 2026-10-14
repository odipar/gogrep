package opengrep

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeExe is the executable the tests extract, with its pin.
var fakeExe = []byte("#!/bin/sh\necho opengrep\n")

func checkExtracted(t *testing.T, dir, path string) {
	t.Helper()
	sum := SHA256(fakeExe)
	if want := filepath.Join(dir, "opengrep-"+sum[:16], exeName()); path != want {
		t.Errorf("Extract path = %s, want %s", path, want)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != string(fakeExe) {
		t.Errorf("extracted file = %q, %v; want %q", data, err, fakeExe)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Errorf("the executable's directory holds %v, %v; want only %s", entries, err, exeName())
	}
	if runtime.GOOS == "windows" {
		return
	}
	for p, want := range map[string]os.FileMode{path: 0o700, filepath.Dir(path): 0o700 | os.ModeDir} {
		if fi, err := os.Stat(p); err != nil || fi.Mode() != want {
			t.Errorf("%s: mode %v, %v; want %v", p, fi.Mode(), err, want)
		}
	}
}

func TestExtract(t *testing.T) {
	dir, sum := t.TempDir(), SHA256(fakeExe)
	path, got, err := Extract(dir, fakeExe, "0123", sum)
	if err != nil || got != sum {
		t.Fatalf("Extract = %s, %s, %v; want the path, %s and no error", path, got, err, sum)
	}
	checkExtracted(t, dir, path)

	t.Run("a verified file is reused", func(t *testing.T) {
		before, _ := os.Stat(path)
		again, _, err := Extract(dir, fakeExe, sum)
		after, _ := os.Stat(path)
		if err != nil || again != path || !os.SameFile(before, after) {
			t.Errorf("Extract again = %s, %v, same file %v; want %s, no error, the same file", again, err, os.SameFile(before, after), path)
		}
	})

	t.Run("a corrupted file is replaced", func(t *testing.T) {
		// As long as the old check: the size matches.
		bad := []byte(strings.ToUpper(string(fakeExe)))
		if err := os.WriteFile(path, bad, 0o700); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-time.Hour)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		again, _, err := Extract(dir, fakeExe, sum)
		if err != nil {
			t.Fatal(err)
		}
		checkExtracted(t, dir, again)
	})
}

func TestExtractRejects(t *testing.T) {
	sum := SHA256(fakeExe)
	other := SHA256([]byte("another opengrep"))
	tests := []struct {
		name   string
		pinned []string
		err    string
	}{
		{"another pin", []string{other}, "embedded: SHA-256 " + sum + ", want the pinned " + other},
		{"an invalid pin", []string{"abc"}, "embedded: SHA-256 " + sum + ", want the pinned abc"},
		{"an empty pin", []string{""}, "embedded: SHA-256 " + sum + ", want the pinned "},
		{"no pin", nil, "no pinned SHA-256 to verify the embedded opengrep against"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path, _, err := Extract(dir, fakeExe, tt.pinned...)
			if err == nil || err.Error() != tt.err || path != "" {
				t.Errorf("Extract = %q, %v; want no path and %q", path, err, tt.err)
			}
			var ie *IntegrityError
			if tt.pinned != nil && (!errors.As(err, &ie) || ie.Path != "embedded" || ie.Got != sum || ie.Want != tt.pinned[0]) {
				t.Errorf("Extract error = %#v, want an *IntegrityError", err)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Errorf("Extract wrote %v, want nothing", entries)
			}
		})
	}
}

// TestExtractConcurrently extracts one executable from 8 goroutines at once,
// as concurrent Engines would; it once raced on bundle.sum.
func TestExtractConcurrently(t *testing.T) {
	dir, sum := t.TempDir(), SHA256(fakeExe)
	paths := make([]string, 8)
	errs := make([]error, 8)
	var wg sync.WaitGroup
	for i := range paths {
		wg.Go(func() { paths[i], _, errs[i] = Extract(dir, fakeExe, sum) })
	}
	wg.Wait()
	for i := range paths {
		if errs[i] != nil || paths[i] != paths[0] {
			t.Errorf("Extract %d = %s, %v; want %s", i, paths[i], errs[i], paths[0])
		}
	}
	checkExtracted(t, dir, paths[0])
}
