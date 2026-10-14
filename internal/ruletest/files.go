package ruletest

import (
	"errors"
	"fmt"
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
// leaves a directory of that name alone, which discovery reports, and never
// reaches through a fixture directory that is a symlink, which discovery
// reports too.
func removeFile(f *Fixture, name string) error {
	if fi, err := os.Lstat(f.Dir); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return nil
	}
	file := filepath.Join(f.Dir, name)
	if fi, err := os.Lstat(file); err == nil && fi.IsDir() {
		return nil
	}
	if err := os.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing %s: %w", path.Join(f.Name, name), err)
	}
	return nil
}

// An Acceptance is a fixture whose actual.txt Accept tried to make its
// expected.txt.
type Acceptance struct {
	*Fixture
	Err error // why actual.txt could not become expected.txt; nil when it did
}

// Accept makes the actual.txt of each fixture its expected.txt, readable and
// writable by its owner only, and returns an Acceptance for each fixture
// that has an actual.txt, in order. Fixtures that fail at SETUP are skipped,
// since gogrep test removes their actual.txt.
func Accept(fixtures []*Fixture) []Acceptance {
	var out []Acceptance
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
		out = append(out, Acceptance{Fixture: f, Err: err})
	}
	return out
}
