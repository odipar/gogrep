package gogrep

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/odipar/gogrep/internal/opengrep"
)

// cacheTree creates files and directories, keyed by slash path, under dir:
// a name that ends in "/" is a directory. Each was last modified as long ago
// as its value says.
func cacheTree(t *testing.T, dir string, entries map[string]time.Duration) {
	t.Helper()
	for name := range entries {
		p := filepath.Join(dir, filepath.FromSlash(strings.TrimSuffix(name, "/")))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(name, "/") {
			if err := os.MkdirAll(p, 0o700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Deepest first, as creating an entry changes its directory's time.
	now := time.Now()
	for _, name := range slices.Backward(slices.Sorted(maps.Keys(entries))) {
		when := now.Add(-entries[name])
		if err := os.Chtimes(filepath.Join(dir, filepath.FromSlash(strings.TrimSuffix(name, "/"))), when, when); err != nil {
			t.Fatal(err)
		}
	}
}

// cacheEntries returns the slash paths of the entries under dir, sorted.
func cacheEntries(t *testing.T, dir string) []string {
	t.Helper()
	var got []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			rel += "/"
		}
		got = append(got, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	return got
}

func TestPruneCache(t *testing.T) {
	t.Parallel()
	pin := opengrep.SHA256(fakeOpengrep)[:16]
	const (
		month = 31 * 24 * time.Hour
		week  = 7 * 24 * time.Hour
		days  = 2 * 24 * time.Hour
		hour  = time.Hour
	)
	cache := t.TempDir()
	cacheTree(t, cache, map[string]time.Duration{
		"opengrep-" + pin + "/":                         month, // the pin's: kept
		"opengrep-" + pin + "/opengrep":                 month,
		"opengrep-" + pin + "/.download-1":              days,
		"opengrep-" + pin + "/.opengrep-2":              hour,
		"opengrep-0123456789abcdef/":                    month, // another build's, unused: removed
		"opengrep-0123456789abcdef/opengrep":            month,
		"opengrep-fedcba9876543210/":                    week,
		"opengrep-fedcba9876543210/opengrep":            month,
		"opengrep-fedcba9876543210/.download-3":         days,
		"opengrep-1111111111111111/":                    hour, // marked a day ago or less: in use
		"opengrep-1111111111111111/opengrep":            month,
		"runtime-" + pin + "/":                          month,
		"runtime-0123456789abcdef/":                     month,
		"runtime-0123456789abcdef/opengrep/":            month,
		"runtime-0123456789abcdef/opengrep/v1.29.0/":    month,
		"runtime-0123456789abcdef/opengrep/v1.29.0/lib": month,
		"runtime-0123456789abcdef.ready":                month,
		"runtime-fedcba9876543210/":                     week,
		"runtime-1111111111111111/":                     hour,
		"runtime-1111111111111111.ready":                hour,
		".runtime-1/":                                   days,
		".runtime-1/log":                                days,
		".runtime-2/":                                   hour,
		"selections/":                                   hour,
		"selections/0123456789abcdef.yaml":              month,
		"selections/fedcba9876543210.yaml":              hour,
		"selections/.tmp-1":                             days,
		"selections/.tmp-2":                             hour,
		"selections/notes.txt":                          month,
		"logs/":                                         hour,
		"logs/opengrep-1.log":                           days,
		"logs/opengrep-2.log":                           hour,
		"locks/":                                        month,
		"locks/install-0123456789abcdef.lock":           month,
		"other/":                                        month,
	})
	e := newPinnedEngine(t, Config{CacheDir: cache})
	if err := e.PruneCache(nil); err != nil {
		t.Fatal(err)
	}
	want := []string{
		".runtime-2/",
		"locks/", "locks/install-0123456789abcdef.lock", "locks/runtime-0123456789abcdef.lock", // the runtimes removed under their locks
		"logs/", "logs/opengrep-2.log",
		"opengrep-" + pin + "/", "opengrep-" + pin + "/.opengrep-2", "opengrep-" + pin + "/opengrep",
		"opengrep-1111111111111111/", "opengrep-1111111111111111/opengrep",
		"opengrep-fedcba9876543210/", "opengrep-fedcba9876543210/opengrep",
		"other/",
		"runtime-" + pin + "/",
		"runtime-1111111111111111.ready",
		"runtime-1111111111111111/",
		"runtime-fedcba9876543210/",
		"selections/", "selections/.tmp-2", "selections/fedcba9876543210.yaml", "selections/notes.txt",
	}
	slices.Sort(want)
	if got := cacheEntries(t, cache); !slices.Equal(got, want) {
		t.Errorf("after PruneCache, the cache holds\n%q\nwant\n%q", got, want)
	}

	// A MaxAge below two days keeps what runs mark once a day: here,
	// the entries of build 1111111111111111.
	if err := e.PruneCache(&PruneOptions{MaxAge: time.Minute}); err != nil {
		t.Fatal(err)
	}
	want = slices.DeleteFunc(want, func(name string) bool {
		return strings.HasPrefix(name, "opengrep-fedcba") || strings.HasPrefix(name, "runtime-fedcba") || name == "selections/fedcba9876543210.yaml"
	})
	want = append(want, "locks/runtime-fedcba9876543210.lock")
	slices.Sort(want)
	if got := cacheEntries(t, cache); !slices.Equal(got, want) {
		t.Errorf("after PruneCache with a MaxAge of a minute, the cache holds\n%q\nwant\n%q", got, want)
	}

	if err := e.PruneCache(&PruneOptions{MaxAge: -1}); err == nil {
		t.Errorf("PruneCache with a negative MaxAge = nil, want an error")
	}
	if err := newPinnedEngine(t, Config{CacheDir: filepath.Join(cache, "missing")}).PruneCache(nil); err != nil {
		t.Errorf("PruneCache of a missing cache = %v", err)
	}
}

// A run marks the executable and runtime it uses, so that PruneCache keeps
// them, at most once a day per process.
func TestMarkUsed(t *testing.T) {
	t.Parallel()
	cache := t.TempDir()
	e := newPinnedEngine(t, Config{CacheDir: cache, EmbeddedOpengrep: fakeOpengrep})
	info, err := e.Opengrep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(info.Path)
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Opengrep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.ModTime().Equal(old) {
		t.Errorf("a second run within a day marked %s again", dir)
	}

	marked.Lock()
	delete(marked.m, dir)
	marked.Unlock()
	if _, err := e.Opengrep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || time.Since(fi.ModTime()) > time.Hour {
		t.Errorf("a run did not mark %s as used", dir)
	}
}
