// Package bundle holds the opengrep binary embedded in gogrep builds made with
// -tags bundled (plus musl for the Alpine variant on Linux). Run
// `go run ./tools/fetch-opengrep` first to download it.
package bundle

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Path returns the path of the embedded opengrep binary, extracting it to the
// user cache directory on first use. ok is false when this build embeds none.
func Path() (path string, ok bool, err error) {
	if len(binary) == 0 {
		return "", false, nil
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", true, err
	}
	sum = strings.TrimSpace(sum)
	dir := filepath.Join(cache, "gogrep", "opengrep-"+sum[:16])
	name := "opengrep"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path = filepath.Join(dir, name)

	if fi, err := os.Stat(path); err == nil && fi.Size() == int64(len(binary)) {
		return path, true, nil
	}
	return path, true, extract(dir, path)
}

// extract writes the binary via a temp file and rename, so concurrent gogrep
// runs never execute a partially written file.
func extract(dir, path string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".opengrep-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		// Another gogrep run may have won the race (or holds the file open on Windows).
		if _, statErr := os.Stat(path); statErr == nil {
			return nil
		}
		return err
	}
	return nil
}
