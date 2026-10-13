package ruletest

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

// writeFile replaces the file name in the fixture f with data, readable and
// writable by its owner only. It writes a temporary file, which discovery
// ignores, and renames it, so the file is never seen partly written.
func writeFile(f *Fixture, name string, data []byte) error {
	if err := replaceFile(filepath.Join(f.Dir, name), data); err != nil {
		return fmt.Errorf("writing %s: %w", path.Join(f.Name, name), err)
	}
	return nil
}

func replaceFile(file string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(file), ".gogrep-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), file)
}

// removeFile removes the file name from the fixture f, if it is there. It
// leaves a directory of that name alone, which discovery reports.
func removeFile(f *Fixture, name string) error {
	file := filepath.Join(f.Dir, name)
	if fi, err := os.Lstat(file); err == nil && fi.IsDir() {
		return nil
	}
	if err := os.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing %s: %w", path.Join(f.Name, name), err)
	}
	return nil
}

// Accept makes the actual.txt of each fixture its expected.txt and prints
// "Accepted <fixture>" on stdout. Fixtures without actual.txt are skipped,
// and so are fixtures that fail at SETUP, since gogrep test removes their
// actual.txt. Accept returns gogrep's exit code: 0, or 2 when a file could
// not be renamed, which it reports on stderr.
func Accept(fixtures []*Fixture, stdout, stderr io.Writer) int {
	code := 0
	for _, f := range fixtures {
		if f.Setup != nil {
			continue
		}
		expected := filepath.Join(f.Dir, expectedFile)
		err := os.Rename(filepath.Join(f.Dir, actualFile), expected)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err == nil {
			err = os.Chmod(expected, 0o600)
		}
		if err != nil {
			fmt.Fprintf(stderr, "gogrep: accepting %s: %v\n", path.Join(f.Name, actualFile), err)
			code = 2
			continue
		}
		fmt.Fprintf(stdout, "Accepted %s\n", f.Name)
	}
	return code
}
