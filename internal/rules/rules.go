// Package rules writes gogrep's embedded rule sets to disk, filtered by rule
// set, language and category, so opengrep can load them with --config.
package rules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// A Set is a named rule set: file contents keyed by slash-separated path.
// Rule files are YAML; anything else (LICENSE, NOTICE) is carried along.
type Set map[string][]byte

// Filter selects rule files. An empty field matches everything.
type Filter struct {
	Sets       []string // rule set names
	Langs      []string // top-level directory of the rule file, e.g. "go"
	Categories []string // metadata.category of any rule in the file, e.g. "security"
}

// FromTarGz reads a gzipped tar of rule files.
func FromTarGz(data []byte) (Set, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	set := Set{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return set, nil
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg || !fs.ValidPath(hdr.Name) {
			continue
		}
		if set[hdr.Name], err = io.ReadAll(tr); err != nil {
			return nil, err
		}
	}
}

// FromFS reads every file in fsys.
func FromFS(fsys fs.FS) (Set, error) {
	set := Set{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		set[p], err = fs.ReadFile(fsys, p)
		return err
	})
	return set, err
}

// Dir writes the files of sets that pass f to <user cache>/gogrep/rules/<key>/<set>/,
// reusing an identical earlier result, and returns that directory with the
// number of rule files in it.
func Dir(sets map[string]Set, f Filter) (dir string, n int, err error) {
	selected := map[string]Set{}
	for name, set := range sets {
		if len(f.Sets) > 0 && !slices.Contains(f.Sets, name) {
			continue
		}
		sel := Set{}
		rules := 0
		for p, data := range set {
			if !isRule(p) {
				sel[p] = data
				continue
			}
			if matches(p, data, f) {
				sel[p] = data
				rules++
			}
		}
		if rules > 0 {
			selected[name] = sel
			n += rules
		}
	}
	if n == 0 {
		return "", 0, nil
	}

	cache, err := os.UserCacheDir()
	if err != nil {
		return "", 0, err
	}
	dir = filepath.Join(cache, "gogrep", "rules", key(selected))
	if _, err := os.Stat(dir); err == nil {
		return dir, n, nil
	}
	return dir, n, write(dir, selected)
}

func isRule(p string) bool {
	ext := path.Ext(p)
	return ext == ".yaml" || ext == ".yml"
}

var categoryRE = regexp.MustCompile(`(?m)^\s+category:\s*["']?([\w-]+)`)

func matches(p string, data []byte, f Filter) bool {
	if len(f.Langs) > 0 {
		lang, _, ok := strings.Cut(p, "/")
		if !ok || !slices.Contains(f.Langs, lang) {
			return false
		}
	}
	if len(f.Categories) > 0 {
		for _, m := range categoryRE.FindAllSubmatch(data, -1) {
			if slices.Contains(f.Categories, string(m[1])) {
				return true
			}
		}
		return false
	}
	return true
}

// key hashes the selected files, so any change in rules or filter gets its
// own directory.
func key(sets map[string]Set) string {
	h := sha256.New()
	for _, name := range slices.Sorted(maps.Keys(sets)) {
		for _, p := range slices.Sorted(maps.Keys(sets[name])) {
			fmt.Fprintf(h, "%s/%s\x00%d\x00", name, p, len(sets[name][p]))
			h.Write(sets[name][p])
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// write fills a temp dir and renames it into place, so concurrent gogrep runs
// never see a half-written rule directory.
func write(dir string, sets map[string]Set) error {
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".tmp-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for name, set := range sets {
		for p, data := range set {
			dst := filepath.Join(tmp, name, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(dst, data, 0o644); err != nil {
				return err
			}
		}
	}
	if err := os.Rename(tmp, dir); err != nil {
		if _, statErr := os.Stat(dir); statErr == nil {
			return nil // another gogrep run got there first
		}
		return err
	}
	return nil
}
