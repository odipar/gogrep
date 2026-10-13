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
// exited 0; a later call only checks that it is there. Windows has no such
// redirect: there it runs `exe --version` alone, which unpacks in place,
// marks that done with <dir>/runtime-<sha16>.ready, and returns "". The
// preparation is serialised within the process and, with a file lock,
// between processes. env is the environment it runs in.
//
// When the preparation fails, PrepareRuntime logs why to log and returns "",
// so that opengrep runs as it would by itself and reports any real error;
// when ctx is done, it returns ctx's error. A `--version` that exits 0 but
// prints nothing has failed: opengrep 1.30.2 does that for every command
// when its runtime is under a path that is not ASCII. On Linux and macOS,
// PrepareRuntime therefore prepares nothing in such a dir, and returns "".
func PrepareRuntime(ctx context.Context, exe, sum, dir string, env []string, log *slog.Logger) (string, error) {
	key := sum[:16]
	ready := filepath.Join(dir, "runtime-"+key)
	if runtime.GOOS == "windows" {
		ready += ".ready"
	} else if !ascii(dir) {
		log.Info("opengrep cannot run with its runtime under a path that is not ASCII; it runs without a prepared one", "dir", dir)
		return "", nil
	}
	if isPrepared(ready) {
		return xdgCache(ready), nil
	}

	release, err := acquire(ctx, dir, sum)
	if err != nil {
		return "", err
	}
	defer release()
	if isPrepared(ready) {
		return xdgCache(ready), nil
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
	if isPrepared(ready) {
		return xdgCache(ready), nil
	}

	start = time.Now()
	log.Info("preparing opengrep's runtime", "exe", exe, "dir", ready)
	if runtime.GOOS == "windows" {
		err = prepareInPlace(ctx, exe, dir, ready, env)
	} else {
		err = unpack(ctx, exe, dir, ready, env)
	}
	switch {
	case ctx.Err() != nil:
		return "", ctx.Err()
	case err != nil:
		log.Info("could not prepare opengrep's runtime; opengrep runs without it", "err", err)
		return "", nil
	}
	log.Info("prepared opengrep's runtime", "dir", ready, "took", time.Since(start))
	return xdgCache(ready), nil
}

// RemoveRuntime removes name, a runtime that PrepareRuntime prepared in the
// cache directory dir (runtime-<sha16>, or runtime-<sha16>.ready on
// Windows), if stale reports true for it once RemoveRuntime holds the lock
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

// isPrepared reports whether ready, a runtime directory or, on Windows, a
// marker file, is there.
func isPrepared(ready string) bool {
	fi, err := os.Stat(ready)
	return err == nil && fi.IsDir() == (runtime.GOOS != "windows")
}

// xdgCache returns the XDG_CACHE_HOME for the prepared runtime ready.
func xdgCache(ready string) string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return ready
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
	if err := runVersion(ctx, exe, append(slices.Clip(env), "XDG_CACHE_HOME="+tmp, "SEMGREP_LOG_FILE="+log)); err != nil {
		return err
	}
	if err := os.Remove(log); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil && !isPrepared(dst) {
		return err
	}
	return nil
}

// prepareInPlace runs exe --version, which unpacks its runtime where
// opengrep keeps it, and then creates the marker file ready in dir.
func prepareInPlace(ctx context.Context, exe, dir, ready string, env []string) error {
	log, err := LogFile(dir)
	if err != nil {
		return err
	}
	defer os.Remove(log)
	if err := runVersion(ctx, exe, append(slices.Clip(env), "SEMGREP_LOG_FILE="+log)); err != nil {
		return err
	}
	f, err := os.OpenFile(ready, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// runVersion runs exe --version in env, within prepareTimeout, and checks
// that it printed a version.
func runVersion(ctx context.Context, exe string, env []string) error {
	ctx, cancel := context.WithTimeout(ctx, prepareTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	c := &Cmd{Path: exe, Args: []string{"--version"}, Env: env, Stdout: &stdout, Stderr: &stderr}
	if err := c.Run(ctx); err != nil {
		if line := lastLine(stderr.Bytes()); line != "" {
			return fmt.Errorf("%s --version: %w: %s", exe, err, line)
		}
		return fmt.Errorf("%s --version: %w", exe, err)
	}
	if len(bytes.TrimSpace(stdout.Bytes())) == 0 {
		return fmt.Errorf("%s --version exited 0 but printed no version", exe)
	}
	return nil
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
