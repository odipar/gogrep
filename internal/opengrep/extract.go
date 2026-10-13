// Package opengrep finds, verifies and prepares the opengrep executable that
// gogrep runs, and runs it.
package opengrep

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
)

// exeName returns the file name of the opengrep executable in the cache.
func exeName() string {
	if runtime.GOOS == "windows" {
		return "opengrep.exe"
	}
	return "opengrep"
}

// Extract makes data, an opengrep executable compiled into the program,
// available as <dir>/opengrep-<sha16>/opengrep (opengrep.exe on Windows),
// where sha16 is the first 16 hex digits of its SHA-256, and returns that
// path and the SHA-256. The SHA-256 must be one of pinned, as opengrep.json
// pins it for this platform; otherwise Extract writes nothing and returns an
// *IntegrityError. A file already in place is used only if its SHA-256 is
// data's. Otherwise data is written to a temporary file beside it, made
// executable and renamed into place, so that no process ever runs a partial
// file; when the rename fails but a file that verifies is now in place, as
// when another process won the race (or, on Windows, runs it), that file is
// used.
func Extract(dir string, data []byte, pinned ...string) (path, sum string, err error) {
	if len(pinned) == 0 {
		return "", "", errors.New("no pinned SHA-256 to verify the embedded opengrep against")
	}
	sum = SHA256(data)
	if !slices.Contains(pinned, sum) {
		return "", "", &IntegrityError{Path: "embedded", Want: pinned[0], Got: sum}
	}
	exeDir := filepath.Join(dir, "opengrep-"+sum[:16])
	path = filepath.Join(exeDir, exeName())
	if got, err := FileSHA256(path); err == nil && got == sum {
		return path, sum, nil
	}

	if err := os.MkdirAll(exeDir, 0o700); err != nil {
		return "", "", err
	}
	tmp, err := os.CreateTemp(exeDir, ".opengrep-*")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		return "", "", err
	}
	if err := os.Chmod(tmp.Name(), 0o700); err != nil {
		return "", "", err
	}
	fi, err := os.Stat(tmp.Name())
	if err != nil {
		return "", "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		if got, verr := FileSHA256(path); verr == nil && got == sum {
			return path, sum, nil
		}
		return "", "", err
	}
	remember(path, fi, sum) // the rename kept its size and modification time
	return path, sum, nil
}
