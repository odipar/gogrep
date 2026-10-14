package opengrep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// prepareTimeout bounds the opengrep run that unpacks its runtime, which
// takes about 8 s.
const prepareTimeout = 5 * time.Minute

// preparing holds a channel per runtime that is one while a goroutine
// prepares it, keyed by cache directory and executable checksum.
var preparing struct {
	sync.Mutex
	m map[[2]string]chan struct{}
}

// PrepareRuntime makes the runtime of the opengrep executable exe, whose
// SHA-256 is sum, ready in the cache directory dir, so that concurrent
// opengrep processes never start from a half-written one, and returns the
// XDG_CACHE_HOME that points opengrep at it.
//
// opengrep unpacks its runtime (about 245 MB) on its first run, into
// $XDG_CACHE_HOME/opengrep/<version>, and repairs it in place on later
// ones; runs that start meanwhile crash. On Linux and macOS, PrepareRuntime
// therefore runs `exe --version` with XDG_CACHE_HOME set to a private
// directory, and renames that into place as <dir>/runtime-<sha16> once it
// exited 0; a later call only checks that it is there. Where opengrep's
// runtime cannot move into dir (see staysInPlace), on Windows and under a
// dir that is not ASCII, PrepareRuntime runs `exe --version` alone, which
// unpacks it where opengrep keeps it by itself, marks that done with
// <dir>/runtime-<sha16>.ready, and returns "". The preparation is
// serialised within the process and, with a file lock, between processes.
// env is the environment it runs in.
//
// When the preparation fails, PrepareRuntime logs why to log and returns "",
// so that opengrep runs as it would by itself and reports any real error;
// when ctx is done, it returns ctx's error. A `--version` that exits 0 but
// prints nothing has failed: opengrep 1.30.2 does that for every command
// when its runtime is under a path that is not ASCII.
func PrepareRuntime(ctx context.Context, exe, sum, dir string, env []string, log *slog.Logger) (string, error) {
	key := sum[:16]
	r := &place{path: filepath.Join(dir, "runtime-"+key)}
	if staysInPlace(runtime.GOOS, dir) {
		r.path += ".ready"
		r.inPlace, r.mark = true, inPlaceMark(runtime.GOOS, env)
	}
	if r.ready() {
		return r.xdgCache(), nil
	}

	release, err := acquire(ctx, dir, sum)
	if err != nil {
		return "", err
	}
	defer release()
	if r.ready() {
		return r.xdgCache(), nil
	}
	start := time.Now()
	unlock, err := lock(ctx, filepath.Join(dir, "locks", "runtime-"+key+".lock"))
	defer unlock()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		log.Info("preparing opengrep's runtime without a lock", "err", err)
	} else if waited := time.Since(start); waited >= lockPoll {
		log.Info("waited for another process preparing opengrep's runtime", "took", waited)
	}
	if r.ready() {
		return r.xdgCache(), nil
	}

	start = time.Now()
	if r.inPlace && runtime.GOOS != "windows" {
		log.Info("opengrep cannot run with its runtime under a path that is not ASCII; it unpacks it where it keeps it by itself", "dir", dir)
	}
	log.Info("preparing opengrep's runtime", "exe", exe, "dir", r.path)
	if r.inPlace {
		err = prepareInPlace(ctx, exe, dir, r, env)
	} else {
		err = unpack(ctx, exe, dir, r.path, env)
	}
	switch {
	case ctx.Err() != nil:
		return "", ctx.Err()
	case err != nil:
		log.Info("could not prepare opengrep's runtime; opengrep runs without it", "err", err)
		return "", nil
	}
	log.Info("prepared opengrep's runtime", "dir", r.path, "took", time.Since(start))
	return r.xdgCache(), nil
}

// staysInPlace reports whether opengrep's runtime stays where opengrep
// keeps it by itself, instead of moving into the cache directory dir, on
// the system goos: on Windows, where no environment variable redirects it,
// and when dir is not ASCII, since opengrep 1.30.2 then unpacks its runtime
// but runs no command, printing nothing and exiting 0 (under the UTF-8
// locale that gogrep always sets).
func staysInPlace(goos, dir string) bool {
	return goos == "windows" || !ascii(dir)
}

// A place is where PrepareRuntime prepares a runtime: the directory path,
// or for a runtime kept in place, the marker file path, which holds mark.
type place struct {
	path    string
	inPlace bool
	mark    []byte
}

// ready reports whether the runtime is prepared: its directory is there or,
// for one kept in place, its marker holds mark and the runtime directory it
// names, if any, is still there. A marker written for another location of
// opengrep's own runtime does not count, and neither does one whose runtime
// was removed since (a cleaned ~/.cache), which would let concurrent first
// runs crash again.
func (r *place) ready() bool {
	if !r.inPlace {
		return isDir(r.path)
	}
	data, err := os.ReadFile(r.path)
	rest, ok := bytes.CutPrefix(data, r.mark)
	if err != nil || !ok {
		return false
	}
	dir, ok := bytes.CutPrefix(rest, []byte("RUNTIME="))
	dir = bytes.TrimSuffix(dir, []byte("\n"))
	return len(rest) == 0 || ok && (len(dir) == 0 || isDir(string(dir)))
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// xdgCache returns the XDG_CACHE_HOME for the prepared runtime: "" for one
// kept in place.
func (r *place) xdgCache() string {
	if r.inPlace {
		return ""
	}
	return r.path
}

// inPlaceMark returns what the marker of a runtime kept in place holds on
// the system goos: on Linux and macOS, the variables of env that pick where
// opengrep keeps it, $XDG_CACHE_HOME or else $HOME/.cache, so that a run
// with another of them prepares that one; nothing on Windows, where it is
// %LOCALAPPDATA%'s, which no environment variable moves.
func inPlaceMark(goos string, env []string) []byte {
	if goos == "windows" {
		return nil
	}
	return fmt.Appendf(nil, "XDG_CACHE_HOME=%s\nHOME=%s\n", lookup(env, "XDG_CACHE_HOME"), lookup(env, "HOME"))
}

// RemoveRuntime removes name, a runtime that PrepareRuntime prepared in the
// cache directory dir (runtime-<sha16>, or the marker runtime-<sha16>.ready
// of one kept in place), if stale reports true for it once RemoveRuntime holds the lock
// that PrepareRuntime takes. A held lock means that the runtime is being
// prepared, and it is kept. A runtime directory is first renamed into a new
// temporary <dir>/.runtime-*, so that a run that starts meanwhile finds it
// complete or absent, never half removed. RemoveRuntime reports whether it
// removed name.
func RemoveRuntime(dir, name string, stale func(fs.FileInfo) bool) (bool, error) {
	key := strings.TrimSuffix(strings.TrimPrefix(name, "runtime-"), ".ready")
	if f, err := openLock(filepath.Join(dir, "locks", "runtime-"+key+".lock")); err == nil {
		defer f.Close()
		locked, err := tryLock(f)
		switch {
		case err == nil && !locked:
			return false, nil
		case locked:
			defer unlockFile(f)
		}
	}
	path := filepath.Join(dir, name)
	fi, err := os.Lstat(path)
	if err != nil || !stale(fi) {
		return false, nil
	}
	if !fi.IsDir() {
		return true, os.Remove(path)
	}
	tmp, err := os.MkdirTemp(dir, ".runtime-*")
	if err != nil {
		return false, err
	}
	if err := os.Rename(path, filepath.Join(tmp, name)); err != nil {
		os.Remove(tmp)
		return false, err
	}
	return true, os.RemoveAll(tmp)
}

// acquire waits until no other goroutine prepares the runtime of the
// executable sum in dir, or ctx is done. release ends the preparation.
func acquire(ctx context.Context, dir, sum string) (release func(), err error) {
	preparing.Lock()
	if preparing.m == nil {
		preparing.m = map[[2]string]chan struct{}{}
	}
	key := [2]string{dir, sum}
	ch := preparing.m[key]
	if ch == nil {
		ch = make(chan struct{}, 1)
		preparing.m[key] = ch
	}
	preparing.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// unpack runs exe --version with XDG_CACHE_HOME set to a new directory in
// dir, and renames that to dst when exe exits 0.
func unpack(ctx context.Context, exe, dir, dst string, env []string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(dir, ".runtime-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	log := filepath.Join(tmp, "log")
	if _, err := runVersion(ctx, exe, append(slices.Clip(env), "XDG_CACHE_HOME="+tmp, "SEMGREP_LOG_FILE="+log)); err != nil {
		return err
	}
	if err := os.Remove(log); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil && !(&place{path: dst}).ready() {
		return err
	}
	return nil
}

// prepareInPlace runs exe --version, which unpacks its runtime where
// opengrep keeps it, and then writes the marker of r in dir: its mark and,
// on Linux and macOS, RUNTIME= the directory the runtime was unpacked in.
func prepareInPlace(ctx context.Context, exe, dir string, r *place, env []string) error {
	log, err := LogFile(dir)
	if err != nil {
		return err
	}
	defer os.Remove(log)
	version, err := runVersion(ctx, exe, append(slices.Clip(env), "SEMGREP_LOG_FILE="+log))
	if err != nil {
		return err
	}
	mark := r.mark
	if runtime.GOOS != "windows" {
		mark = fmt.Appendf(slices.Clip(mark), "RUNTIME=%s\n", ownRuntime(env, version))
	}
	return os.WriteFile(r.path, mark, 0o600)
}

// ownRuntime returns the directory where opengrep, run in env, keeps the
// runtime of version by itself on Linux and macOS:
// $XDG_CACHE_HOME/opengrep/v<version>, or else $HOME/.cache/... . It falls
// back to its parent opengrep directory, or "" when neither is there.
func ownRuntime(env []string, version string) string {
	base := lookup(env, "XDG_CACHE_HOME")
	if base == "" {
		if home := lookup(env, "HOME"); home != "" {
			base = filepath.Join(home, ".cache")
		}
	}
	if base == "" {
		return ""
	}
	for _, dir := range []string{filepath.Join(base, "opengrep", "v"+version), filepath.Join(base, "opengrep")} {
		if isDir(dir) {
			return dir
		}
	}
	return ""
}

// runVersion runs exe --version in env, within prepareTimeout, and returns
// the version it printed.
func runVersion(ctx context.Context, exe string, env []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, prepareTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	c := &Cmd{Path: exe, Args: []string{"--version"}, Env: env, Stdout: &stdout, Stderr: &stderr}
	if err := c.Run(ctx); err != nil {
		if line := lastLine(stderr.Bytes()); line != "" {
			return "", fmt.Errorf("%s --version: %w: %s", exe, err, line)
		}
		return "", fmt.Errorf("%s --version: %w", exe, err)
	}
	version := lastLine(stdout.Bytes())
	if version == "" {
		return "", fmt.Errorf("%s --version exited 0 but printed no version", exe)
	}
	return version, nil
}

// ascii reports whether s is ASCII.
func ascii(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// lastLine returns the last line of output that is not blank.
func lastLine(output []byte) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// LogFile creates an empty file for one opengrep process's log, its
// SEMGREP_LOG_FILE, as <dir>/logs/opengrep-*.log, 0o600, and returns its
// path. Remove it once the process is done.
func LogFile(dir string) (string, error) {
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(logs, "opengrep-*.log")
	if err != nil {
		return "", err
	}
	return f.Name(), f.Close()
}
