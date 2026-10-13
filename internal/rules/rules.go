// Package rules parses gogrep's rule sets into individual rules with stable,
// qualified ids, and writes a selection of them to one opengrep config file.
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
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// A Set is a named rule set: file contents keyed by slash-separated path.
// Rule files are YAML; anything else (LICENSE, NOTICE) is ignored here.
type Set map[string][]byte

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

// FromFS reads every file in fsys, except those under the directories whose
// slash-separated paths are in skipDirs, in any letter case: on a
// case-insensitive file system a Test directory is the test directory. A
// skipped directory may also be a symlink, which WalkDir reports as a file.
func FromFS(fsys fs.FS, skipDirs ...string) (Set, error) {
	set := Set{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		skip := slices.ContainsFunc(skipDirs, func(dir string) bool { return strings.EqualFold(dir, p) })
		switch {
		case err != nil:
			return err
		case skip && d.IsDir():
			return fs.SkipDir
		case skip, d.IsDir():
			return nil
		}
		set[p], err = fs.ReadFile(fsys, p)
		return err
	})
	return set, err
}

// A Rule is one opengrep rule from a rule set.
type Rule struct {
	// ID is the stable qualified id <set>.<dir>.<id>, with dots for the
	// slashes of the rule file's directory, like opengrep's own rewriting
	// but relative to the set. On a clash the file name goes before <id>.
	ID   string
	Set  string
	Path string // rule file path within the set

	node   *yaml.Node          // the rule's mapping node
	fields map[string][]string // values suites match on, see Fields
}

// Fields returns the values a suite qualifier can match, keyed by name:
// id, ruleset, path, severity, message, languages, and every scalar or
// list-of-scalars metadata field, both prefixed (metadata.category) and bare
// (category) unless the bare name is one of the others.
func (r *Rule) Fields() map[string][]string { return r.fields }

// Parse returns the rules of all sets, sorted by ID.
func Parse(sets map[string]Set) ([]*Rule, error) {
	var all []*Rule
	for _, name := range slices.Sorted(maps.Keys(sets)) {
		seen := map[string]bool{}
		set := sets[name]
		for _, p := range slices.Sorted(maps.Keys(set)) {
			if ext := path.Ext(p); ext != ".yaml" && ext != ".yml" {
				continue
			}
			rules, err := parseFile(name, p, set[p], seen)
			if err != nil {
				return nil, fmt.Errorf("%s/%s: %w", name, p, err)
			}
			all = append(all, rules...)
		}
	}
	slices.SortFunc(all, func(a, b *Rule) int { return strings.Compare(a.ID, b.ID) })
	return all, nil
}

func parseFile(set, p string, data []byte, seen map[string]bool) ([]*Rule, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, nil
	}
	list := value(doc.Content[0], "rules")
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil, nil // not a rule file
	}

	prefix := set
	if dir := path.Dir(p); dir != "." {
		prefix += "." + strings.ReplaceAll(dir, "/", ".")
	}
	var out []*Rule
	for _, n := range list.Content {
		idNode := value(n, "id")
		if idNode == nil || idNode.Value == "" {
			continue
		}
		id := prefix + "." + idNode.Value
		if seen[id] {
			id = prefix + "." + strings.TrimSuffix(path.Base(p), path.Ext(p)) + "." + idNode.Value
		}
		seen[id] = true
		r := &Rule{ID: id, Set: set, Path: p, node: n}
		r.fields = fields(r, n)
		out = append(out, r)
	}
	return out, nil
}

// value returns the value node for key in mapping node m, or nil.
func value(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// scalars returns n's value as a list of strings when it is a scalar or a
// sequence of scalars, and nil otherwise.
func scalars(n *yaml.Node) []string {
	switch {
	case n == nil:
		return nil
	case n.Kind == yaml.ScalarNode:
		return []string{n.Value}
	case n.Kind == yaml.SequenceNode:
		var vs []string
		for _, c := range n.Content {
			if c.Kind != yaml.ScalarNode {
				return nil
			}
			vs = append(vs, c.Value)
		}
		return vs
	}
	return nil
}

func fields(r *Rule, n *yaml.Node) map[string][]string {
	f := map[string][]string{
		"id":      {r.ID},
		"ruleset": {r.Set},
		"path":    {r.Path},
	}
	for _, k := range []string{"severity", "message", "languages"} {
		if vs := scalars(value(n, k)); vs != nil {
			f[k] = vs
		}
	}
	md := value(n, "metadata")
	if md == nil || md.Kind != yaml.MappingNode {
		return f
	}
	for i := 0; i+1 < len(md.Content); i += 2 {
		k, vs := md.Content[i].Value, scalars(md.Content[i+1])
		if vs == nil {
			continue
		}
		f["metadata."+k] = vs
		if _, taken := f[k]; !taken {
			f[k] = vs
		}
	}
	return f
}

// Write writes rules to one opengrep config file in the directory dir, with
// each rule's id replaced by its qualified ID, and returns its path. Run
// opengrep with --no-rewrite-rule-ids to keep those ids. Write changes no
// rule. The file is named after its content, so identical selections share
// one file: Write uses the file if it is there, refreshing its modification
// time to mark it used, and otherwise writes a temporary file and renames it
// into place. When the rename fails but the file is there by then, as when a
// concurrent Write won the race, that file is used. dir is created 0o700 if
// needed, and the file is 0o600.
func Write(dir string, rules []*Rule) (string, error) {
	seq := &yaml.Node{Kind: yaml.SequenceNode}
	for _, r := range rules {
		n := *r.node
		n.Content = slices.Clone(n.Content)
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "id" {
				n.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: r.ID}
			}
		}
		seq.Content = append(seq.Content, &n)
	}
	doc := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "rules"}, seq,
	}}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return "", err
	}
	return write(dir, data, os.Rename)
}

// write writes data to the file in dir that is named after its SHA-256, as
// Write describes, renaming the temporary file into place with rename.
func write(dir string, data []byte, rename func(oldpath, newpath string) error) (string, error) {
	sum := sha256.Sum256(data)
	file := filepath.Join(dir, hex.EncodeToString(sum[:])[:16]+".yaml")
	if isRegular(file) {
		os.Chtimes(file, time.Time{}, time.Now()) // best effort: the file is used either way
		return file, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := rename(tmp.Name(), file); err != nil && !isRegular(file) {
		return "", err
	}
	return file, nil
}

// isRegular reports whether file is a regular file.
func isRegular(file string) bool {
	fi, err := os.Stat(file)
	return err == nil && fi.Mode().IsRegular()
}
