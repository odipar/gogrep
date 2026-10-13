package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/odipar/gogrep/internal/opengrep"
)

// fakeOpengrep is the executable that the tests pin and embed.
var fakeOpengrep = []byte("#!/bin/sh\necho 1.30.2\n")

// pinned returns the files with opengrep.json pinning sum as this
// platform's opengrep.
func pinned(sum string) Files {
	f := testFiles()
	f.Pins = []byte(`{"version": "v1.30.2", "assets": {"` + runtime.GOOS + "/" + runtime.GOARCH + `": {"name": "opengrep_test", "sha256": "` + sum + `"}}}`)
	return f
}

// newPinnedEngine returns an Engine whose opengrep.json pins fakeOpengrep.
func newPinnedEngine(t *testing.T, cfg Config) *Engine {
	t.Helper()
	if cfg.CacheDir == "" {
		cfg.CacheDir = t.TempDir()
	}
	e, err := New(cfg, pinned(opengrep.SHA256(fakeOpengrep)))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func exe(dir string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(dir, "opengrep.exe")
	}
	return filepath.Join(dir, "opengrep")
}

func TestOpengrep(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sum := opengrep.SHA256(fakeOpengrep)
	cache := t.TempDir()

	e := newPinnedEngine(t, Config{CacheDir: cache, EmbeddedOpengrep: fakeOpengrep})
	want := OpengrepInfo{Path: exe(filepath.Join(cache, "opengrep-"+sum[:16])), Source: "embedded", SHA256: sum, Pinned: true, Version: "v1.30.2"}
	if info, err := e.Opengrep(ctx); err != nil || *info != want {
		t.Errorf("Opengrep of an embedded opengrep = %+v, %v; want %+v", info, err, want)
	}

	// Another engine finds what the first extracted.
	want.Source = "cache"
	if info, err := newPinnedEngine(t, Config{CacheDir: cache}).Opengrep(ctx); err != nil || *info != want {
		t.Errorf("Opengrep of the cached opengrep = %+v, %v; want %+v", info, err, want)
	}

	// Config.Opengrep comes first, whatever its version.
	other := exe(t.TempDir())
	if err := os.WriteFile(other, []byte("another opengrep"), 0o700); err != nil {
		t.Fatal(err)
	}
	want = OpengrepInfo{Path: other, Source: "config", SHA256: opengrep.SHA256([]byte("another opengrep"))}
	if info, err := newPinnedEngine(t, Config{CacheDir: cache, Opengrep: other, EmbeddedOpengrep: fakeOpengrep}).Opengrep(ctx); err != nil || *info != want {
		t.Errorf("Opengrep of Config.Opengrep = %+v, %v; want %+v", info, err, want)
	}

	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := e.Opengrep(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Opengrep with a done ctx = %v, want context.Canceled", err)
	}
}

func TestOpengrepErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	sum := opengrep.SHA256(fakeOpengrep)

	missing := exe(filepath.Join(t.TempDir(), "missing"))
	_, err := newPinnedEngine(t, Config{Opengrep: missing}).Opengrep(ctx)
	if !errors.Is(err, ErrNoOpengrep) || !strings.HasPrefix(err.Error(), "exec: ") {
		t.Errorf("Opengrep of a missing Config.Opengrep = %v; want ErrNoOpengrep in exec.LookPath's words", err)
	}

	for _, p := range []string{filepath.Join("bin", "opengrep"), "./opengrep"} {
		if _, err := New(Config{Opengrep: p}, testFiles()); err == nil || err.Error() != "Config.Opengrep "+p+" is a relative path" {
			t.Errorf("New with Opengrep %s = %v, want an error", p, err)
		}
	}
	if _, err := New(Config{Opengrep: "opengrep-1.30"}, testFiles()); err != nil {
		t.Errorf("New with a bare name = %v, want no error", err)
	}

	cache := t.TempDir()
	_, err = newPinnedEngine(t, Config{CacheDir: cache, EmbeddedOpengrep: []byte("altered")}).Opengrep(ctx)
	var ie *IntegrityError
	if !errors.As(err, &ie) || *ie != (IntegrityError{Path: "embedded", Want: sum, Got: opengrep.SHA256([]byte("altered"))}) || errors.Is(err, ErrNoOpengrep) {
		t.Errorf("Opengrep of an altered embedded opengrep = %#v, want an *IntegrityError", err)
	}
	if entries, _ := os.ReadDir(cache); len(entries) != 0 {
		t.Errorf("Opengrep wrote %v into the cache, want nothing", entries)
	}

	// The pinned executable is not in the cache, and the one on PATH, if
	// any, is not the fake that is pinned.
	_, err = newPinnedEngine(t, Config{CacheDir: cache}).Opengrep(ctx)
	text := "no usable opengrep: v1.30.2 for " + runtime.GOOS + "/" + runtime.GOARCH + " (asset opengrep_test, sha256 " + sum[:16] + "…) is not in " +
		filepath.Join(cache, "opengrep-"+sum[:16]) + ", and no opengrep on PATH has that SHA-256; " +
		"install it with Engine.InstallOpengrep or `gogrep install-opengrep`, or set Config.Opengrep"
	if !errors.Is(err, ErrNoOpengrep) || err.Error() != text {
		t.Errorf("Opengrep without opengrep = %v\nwant %s", err, text)
	}

	otherPlatform := testFiles()
	otherPlatform.Pins = []byte(`{"version": "v1.30.2", "assets": {"plan9/amd64": {"name": "opengrep", "sha256": "` + sum + `"}}}`)
	e, err := New(Config{CacheDir: cache, EmbeddedOpengrep: fakeOpengrep}, otherPlatform)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Opengrep(ctx); !errors.Is(err, ErrNoOpengrep) || err.Error() != "opengrep.json pins no opengrep for "+runtime.GOOS+"/"+runtime.GOARCH {
		t.Errorf("Opengrep of an embedded opengrep without a pin = %v", err)
	}

	for _, pins := range []string{"", `{"version": "v1.30.2", "assets": {"` + runtime.GOOS + "/" + runtime.GOARCH + `": {"name": "opengrep", "sha256": "0123"}}}`} {
		files := testFiles()
		files.Pins = []byte(pins)
		e, err := New(Config{CacheDir: cache}, files)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Opengrep(ctx); err == nil || !strings.HasPrefix(err.Error(), "opengrep.json: ") {
			t.Errorf("Opengrep with opengrep.json %q = %v, want an opengrep.json error", pins, err)
		}
	}
}

// With AllowUnpinned, the error says there is no opengrep on PATH at all.
func TestOpengrepNotOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	cache := t.TempDir()
	sum := opengrep.SHA256(fakeOpengrep)
	_, err := newPinnedEngine(t, Config{CacheDir: cache, AllowUnpinned: true}).Opengrep(context.Background())
	if !errors.Is(err, ErrNoOpengrep) || !strings.Contains(err.Error(), "is not in "+filepath.Join(cache, "opengrep-"+sum[:16])+", and there is no opengrep on PATH; ") {
		t.Errorf("Opengrep without opengrep = %v", err)
	}
}

// Concurrent calls extract one embedded executable; they once raced on
// bundle.sum.
func TestOpengrepConcurrently(t *testing.T) {
	t.Parallel()
	e := newPinnedEngine(t, Config{EmbeddedOpengrep: fakeOpengrep})
	paths := make([]string, 8)
	var wg sync.WaitGroup
	for i := range paths {
		wg.Go(func() {
			info, err := e.Opengrep(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			paths[i] = info.Path
		})
	}
	wg.Wait()
	for _, p := range paths {
		if p != paths[0] {
			t.Errorf("Opengrep found %q, want one path", paths)
			break
		}
	}
}
