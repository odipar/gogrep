package opengrep

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
)

// Where Find found an executable.
const (
	SourceConfig   = "config"   // Finder.Explicit
	SourceEmbedded = "embedded" // Finder.Embedded, written to the cache
	SourceCache    = "cache"    // a pinned executable in the cache
	SourcePath     = "path"     // opengrep on PATH
)

// ErrNotFound reports that Find found no opengrep to run.
var ErrNotFound = errors.New("no opengrep found")

// A Finder finds the opengrep executable to run, without using the network.
type Finder struct {
	// Explicit, if set, is the executable to run, whatever it is: an
	// absolute path, or a name without a path separator that is looked up
	// in PATH. It must be a regular file.
	Explicit string

	// Embedded is an executable compiled into the program, and EmbeddedSum
	// its SHA-256. It is written to CacheDir as Extract does.
	Embedded    []byte
	EmbeddedSum string

	// CacheDir holds the executables that Extract writes; "" means there is
	// no cache.
	CacheDir string

	// Pinned are the SHA-256s that opengrep.json pins for this platform,
	// most fitting first.
	Pinned []string

	// AllowUnpinned accepts an opengrep on PATH whose SHA-256 is not
	// pinned.
	AllowUnpinned bool

	lookPath func(file string) (string, error) // nil means exec.LookPath
}

// An Exe is an opengrep executable that Find found.
type Exe struct {
	Path   string // absolute
	Source string // SourceConfig, SourceEmbedded, SourceCache or SourcePath
	SHA256 string
	Pinned bool // SHA256 is one of Finder.Pinned
}

// Find returns the first of these that it finds: Explicit; Embedded, written
// to CacheDir; a pinned executable in CacheDir; opengrep on PATH, if it is
// pinned or AllowUnpinned is set. An Embedded whose SHA-256 is not pinned is
// an *IntegrityError, and a cached file that fails verification counts as
// absent. When it finds none, Find returns ErrNotFound. An Explicit that
// cannot be found is an error that exec.LookPath words.
func (f *Finder) Find() (*Exe, error) {
	lookPath := f.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	if f.Explicit != "" {
		path, err := lookPath(f.Explicit)
		if err != nil {
			return nil, err
		}
		if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("opengrep binary %s is not a regular file", path)
		}
		return f.exe(path, SourceConfig)
	}

	if len(f.Embedded) > 0 {
		sum := f.EmbeddedSum
		switch {
		case len(f.Pinned) == 0:
			return nil, errors.New("no pinned SHA-256 to verify the embedded opengrep against")
		case !slices.Contains(f.Pinned, sum):
			return nil, &IntegrityError{Path: "embedded", Want: f.Pinned[0], Got: sum}
		case f.CacheDir == "":
			return nil, errors.New("extracting the embedded opengrep: no cache directory")
		}
		path := cachePath(f.CacheDir, sum)
		if got, err := FileSHA256(path); err != nil || got != sum {
			if path, _, err = Extract(f.CacheDir, f.Embedded, sum); err != nil {
				return nil, fmt.Errorf("extracting the embedded opengrep: %w", err)
			}
		}
		return &Exe{Path: path, Source: SourceEmbedded, SHA256: sum, Pinned: true}, nil
	}

	if f.CacheDir != "" {
		for _, sum := range f.Pinned {
			path := cachePath(f.CacheDir, sum)
			if got, err := FileSHA256(path); err == nil && got == sum {
				return &Exe{Path: path, Source: SourceCache, SHA256: sum, Pinned: true}, nil
			}
		}
	}

	path, err := lookPath("opengrep")
	if err != nil {
		return nil, ErrNotFound
	}
	exe, err := f.exe(path, SourcePath)
	if err != nil || exe.Pinned || f.AllowUnpinned {
		return exe, err
	}
	return nil, ErrNotFound
}

// exe returns the executable at path, found as source.
func (f *Finder) exe(path, source string) (*Exe, error) {
	sum, err := FileSHA256(path)
	if err != nil {
		return nil, err
	}
	return &Exe{Path: path, Source: source, SHA256: sum, Pinned: slices.Contains(f.Pinned, sum)}, nil
}

// cachePath returns where Extract puts the executable whose SHA-256 is sum
// in the cache dir.
func cachePath(dir, sum string) string {
	return filepath.Join(dir, "opengrep-"+sum[:16], exeName())
}
