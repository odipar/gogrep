package gogrep

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxAge = 30 * 24 * time.Hour // PruneOptions.MaxAge's default
	tempAge       = 24 * time.Hour      // how old a crashed run's temporaries must be for PruneCache
	markEvery     = 24 * time.Hour      // how often a process marks what it uses
)

// selectionFile matches the names of the rule selections that rules.Write
// writes.
var selectionFile = regexp.MustCompile(`^[0-9a-f]{16}\.yaml$`)

// PruneOptions configure Engine.PruneCache; nil means the zero PruneOptions.
type PruneOptions struct {
	// MaxAge is how long an entry that no run has used is kept. Zero means
	// 30 days.
	MaxAge time.Duration
}

// PruneCache removes from CacheDir what no run has used for MaxAge: rule
// selections, and the executables and runtimes of opengrep builds other
// than this version's pins. It also removes temporaries and per-run logs
// left by crashed runs once they are a day old. The current pins'
// executables and runtimes are kept. A run marks what it uses before
// starting opengrep, at most once a day per process. PruneCache never runs
// by itself, and it touches nothing outside CacheDir, opengrep's default
// runtime directory included.
func (e *Engine) PruneCache(opts *PruneOptions) error {
	if opts == nil {
		opts = &PruneOptions{}
	}
	maxAge := opts.MaxAge
	switch {
	case maxAge < 0:
		return fmt.Errorf("PruneOptions.MaxAge is negative (%v)", maxAge)
	case maxAge == 0:
		maxAge = defaultMaxAge
	}
	if e.cacheErr != nil {
		return e.cacheErr
	}
	pins, err := e.src.pins()
	if err != nil {
		return err
	}
	current := map[string]bool{}
	for _, a := range pins.Assets {
		current[a.SHA256[:16]] = true
	}
	entries, err := os.ReadDir(e.cacheDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	p := &pruner{now: time.Now(), e: e}
	for _, d := range entries {
		name, path := d.Name(), filepath.Join(e.cacheDir, d.Name())
		switch {
		case strings.HasPrefix(name, ".runtime-"):
			p.remove(path, tempAge)
		case strings.HasPrefix(name, "opengrep-"):
			if !current[strings.TrimPrefix(name, "opengrep-")] && p.remove(path, maxAge) {
				continue
			}
			p.removeIn(path, tempAge, func(name string) bool {
				return strings.HasPrefix(name, ".download-") || strings.HasPrefix(name, ".opengrep-")
			})
		case strings.HasPrefix(name, "runtime-"):
			if !current[strings.TrimSuffix(strings.TrimPrefix(name, "runtime-"), ".ready")] {
				p.remove(path, maxAge)
			}
		case name == "selections":
			p.removeIn(path, maxAge, selectionFile.MatchString)
			p.removeIn(path, tempAge, func(name string) bool { return strings.HasPrefix(name, ".tmp-") })
		case name == "logs":
			p.removeIn(path, tempAge, func(name string) bool { return strings.HasPrefix(name, "opengrep-") })
		}
	}
	return errors.Join(p.errs...)
}

// A pruner removes what PruneCache removes, and collects the errors.
type pruner struct {
	now  time.Time
	e    *Engine
	errs []error
}

// remove removes path, with everything in it, if it was last modified more
// than age ago, and reports whether it did.
func (p *pruner) remove(path string, age time.Duration) bool {
	fi, err := os.Lstat(path)
	if err != nil || p.now.Sub(fi.ModTime()) <= age {
		return false
	}
	if err := os.RemoveAll(path); err != nil {
		p.errs = append(p.errs, err)
		return false
	}
	p.e.log.Info("pruned the cache", "removed", path, "modified", fi.ModTime())
	return true
}

// removeIn removes the entries of dir whose names match, as remove does.
// It keeps dir's modification time: removing them is no use of dir.
func (p *pruner) removeIn(dir string, age time.Duration, match func(name string) bool) {
	fi, err := os.Stat(dir)
	if err != nil {
		p.errs = append(p.errs, err)
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		p.errs = append(p.errs, err)
		return
	}
	removed := false
	for _, d := range entries {
		if match(d.Name()) && p.remove(filepath.Join(dir, d.Name()), age) {
			removed = true
		}
	}
	if removed {
		os.Chtimes(dir, time.Time{}, fi.ModTime())
	}
}

// marked holds when this process last marked each path in a cache as used.
var marked struct {
	sync.Mutex
	m map[string]time.Time
}

// markUsed records that a run is about to use the executable info and its
// runtime, where they are in CacheDir, by setting their modification times,
// at most once per markEvery for each path in this process. PruneCache
// keeps what was used recently.
func (e *Engine) markUsed(info *OpengrepInfo) {
	key := info.SHA256[:16]
	paths := []string{filepath.Join(e.cacheDir, "runtime-"+key), filepath.Join(e.cacheDir, "runtime-"+key+".ready")}
	if dir := filepath.Join(e.cacheDir, "opengrep-"+key); filepath.Dir(info.Path) == dir {
		paths = append(paths, dir)
	}
	now := time.Now()
	marked.Lock()
	defer marked.Unlock()
	if marked.m == nil {
		marked.m = map[string]time.Time{}
	}
	for _, p := range paths {
		if now.Sub(marked.m[p]) >= markEvery {
			marked.m[p] = now
			os.Chtimes(p, time.Time{}, now) // best effort, and missing paths are fine
		}
	}
}
