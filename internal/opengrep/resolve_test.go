package opengrep

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The executables the tests find: pinned, unpinned and a second pin, as for
// Linux's other libc.
var (
	pinnedExe = []byte("#!/bin/sh\necho pinned\n")
	otherExe  = []byte("#!/bin/sh\necho unpinned\n")
	secondExe = []byte("#!/bin/sh\necho second\n")
)

// writeExe writes data as an executable file at path.
func writeExe(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// lookIn returns a lookPath that finds names in dir, as exec.LookPath would
// with PATH=dir.
func lookIn(dir string) func(string) (string, error) {
	return func(file string) (string, error) {
		if strings.ContainsAny(file, `/\`) {
			return exec.LookPath(file)
		}
		p, err := exec.LookPath(filepath.Join(dir, file))
		if err != nil {
			return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
		}
		return p, nil
	}
}

// TestFind checks the order of §4.2 row by row: each case takes away what
// the one before found.
func TestFind(t *testing.T) {
	t.Parallel()
	cache, pathDir := t.TempDir(), t.TempDir()
	explicit := writeExe(t, filepath.Join(t.TempDir(), exeName()), otherExe)
	cached := writeExe(t, cachePath(cache, SHA256(pinnedExe)), pinnedExe)
	onPath := writeExe(t, filepath.Join(pathDir, exeName()), otherExe)
	pinned := []string{SHA256(pinnedExe), SHA256(secondExe)}
	embeddedCache := t.TempDir()

	tests := []struct {
		name   string
		f      Finder
		setup  func()
		path   string
		source string
		pin    bool
	}{
		{"explicit, whatever it is", Finder{Explicit: explicit, Embedded: pinnedExe, EmbeddedSum: pinned[0], CacheDir: cache, Pinned: pinned}, nil, explicit, SourceConfig, false},
		{"explicit, looked up in PATH", Finder{Explicit: "opengrep", CacheDir: cache, Pinned: pinned}, nil, onPath, SourceConfig, false},
		{"embedded, written to the cache", Finder{Embedded: pinnedExe, EmbeddedSum: pinned[0], CacheDir: embeddedCache, Pinned: pinned}, nil, cachePath(embeddedCache, pinned[0]), SourceEmbedded, true},
		{"embedded, verified copy reused", Finder{Embedded: pinnedExe, EmbeddedSum: pinned[0], CacheDir: embeddedCache, Pinned: pinned}, nil, cachePath(embeddedCache, pinned[0]), SourceEmbedded, true},
		{"embedded, the second pin", Finder{Embedded: secondExe, EmbeddedSum: pinned[1], CacheDir: embeddedCache, Pinned: pinned}, nil, cachePath(embeddedCache, pinned[1]), SourceEmbedded, true},
		{"cached", Finder{CacheDir: cache, Pinned: pinned, AllowUnpinned: true}, nil, cached, SourceCache, true},
		{"cached, most fitting pin first", Finder{CacheDir: cache, Pinned: pinned}, func() { writeExe(t, cachePath(cache, pinned[1]), secondExe) }, cached, SourceCache, true},
		{"cached, the other pin", Finder{CacheDir: cache, Pinned: pinned}, func() { os.Remove(cached) }, cachePath(cache, pinned[1]), SourceCache, true},
		{"a corrupted cached file is absent", Finder{CacheDir: cache, Pinned: pinned[:1], AllowUnpinned: true}, func() { writeExe(t, cached, otherExe) }, onPath, SourcePath, false},
		{"PATH, pinned", Finder{CacheDir: cache, Pinned: pinned[:1]}, func() { writeExe(t, onPath, pinnedExe) }, onPath, SourcePath, true},
		{"PATH, unpinned but allowed", Finder{Pinned: pinned, AllowUnpinned: true}, func() { writeExe(t, onPath, otherExe) }, onPath, SourcePath, false},
	}
	for _, tt := range tests {
		if tt.setup != nil {
			tt.setup()
		}
		tt.f.lookPath = lookIn(pathDir)
		exe, err := tt.f.Find()
		if err != nil {
			t.Errorf("%s: Find = %v", tt.name, err)
			continue
		}
		data, _ := os.ReadFile(exe.Path)
		if exe.Path != tt.path || exe.Source != tt.source || exe.Pinned != tt.pin || exe.SHA256 != SHA256(data) {
			t.Errorf("%s: Find = %+v; want %s from %s, pinned %v", tt.name, exe, tt.path, tt.source, tt.pin)
		}
	}

	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		for _, f := range []Finder{
			{CacheDir: cache, Pinned: pinned[:1], lookPath: lookIn(pathDir)},     // an unpinned opengrep on PATH
			{Pinned: pinned, AllowUnpinned: true, lookPath: lookIn(t.TempDir())}, // none on PATH
		} {
			if exe, err := f.Find(); err != ErrNotFound {
				t.Errorf("Find = %+v, %v; want ErrNotFound", exe, err)
			}
		}
	})
}

func TestFindRejects(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing", exeName())
	if _, err := (&Finder{Explicit: missing}).Find(); err == nil || !strings.HasPrefix(err.Error(), "exec: ") {
		t.Errorf("Find of a missing explicit opengrep = %v, want exec.LookPath's error", err)
	}
	if _, err := (&Finder{Explicit: dir}).Find(); err == nil {
		t.Errorf("Find of a directory = nil error, want one")
	}

	sum := SHA256(otherExe)
	f := &Finder{Embedded: otherExe, EmbeddedSum: sum, CacheDir: dir, Pinned: []string{SHA256(pinnedExe)}}
	_, err := f.Find()
	var ie *IntegrityError
	if !errors.As(err, &ie) || ie.Path != "embedded" || ie.Want != SHA256(pinnedExe) || ie.Got != sum {
		t.Errorf("Find of an unpinned embedded opengrep = %v, want an *IntegrityError", err)
	}
	f.Pinned = nil
	if _, err := f.Find(); err == nil || err.Error() != "no pinned SHA-256 to verify the embedded opengrep against" {
		t.Errorf("Find of an embedded opengrep without pins = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("Find wrote %v, want nothing", entries)
	}
}
