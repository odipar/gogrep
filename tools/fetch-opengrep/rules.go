package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// rulesPin pins a GitHub rule repository to a git commit; git's content
// addressing guarantees what we get.
type rulesPin struct {
	Name   string `json:"name"` // rule set name, used in --gogrep-ruleset
	Repo   string `json:"repo"` // GitHub owner/name
	Commit string `json:"commit"`
	Path   string `json:"path,omitempty"` // repo subdirectory holding the rules
	Lang   string `json:"lang,omitempty"` // language dir to file rules under, if the repo has none
}

// fetchRules clones the pinned rules commit and packs its rule files, plus
// LICENSE, into the deterministic archive rulesDir/<name>.tar.gz, next to the
// stamp <name>.commit.
func fetchRules(pin rulesPin) error {
	if pin.Name == "" || strings.ContainsAny(pin.Name, `/\.`) {
		return fmt.Errorf("invalid rule set name %q", pin.Name)
	}
	out := filepath.Join(rulesDir, pin.Name+".tar.gz")
	stamp := filepath.Join(rulesDir, pin.Name+".commit")
	want := pin.Commit + " " + pin.Path + " " + pin.Lang
	if got, err := os.ReadFile(stamp); err == nil && string(got) == want {
		if _, err := os.Stat(out); err == nil {
			fmt.Printf("rules: %s@%.12s already present\n", pin.Repo, pin.Commit)
			return nil
		}
	}

	tmp, err := os.MkdirTemp("", "opengrep-rules-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	fmt.Printf("rules: fetching %s@%s\n", pin.Repo, pin.Commit)
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", tmp}, args...)...)
		cmd.Stderr = os.Stderr
		b, err := cmd.Output()
		return strings.TrimSpace(string(b)), err
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"fetch", "-q", "--depth", "1", "https://github.com/" + pin.Repo, pin.Commit},
		{"checkout", "-q", "FETCH_HEAD"},
	} {
		if _, err := git(args...); err != nil {
			return fmt.Errorf("rules: git %s: %w", args[0], err)
		}
	}
	if head, err := git("rev-parse", "HEAD"); err != nil || head != pin.Commit {
		return fmt.Errorf("rules: checked out %q, pinned %s (%v)", head, pin.Commit, err)
	}

	files, err := ruleFiles(tmp, pin.Path, pin.Lang)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no rule files found in %s/%s", pin.Repo, pin.Path)
	}
	n := len(files)
	for _, l := range licenseFiles(tmp) {
		files = append(files, entry{name: l, src: l})
	}
	data, err := tarGz(tmp, files)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("rules: packed %d rule files (%d KB)\n", n, len(data)/1024)
	return os.WriteFile(stamp, []byte(want), 0o600)
}

// licenseFiles returns the license and notice files at the repo root, which
// the rules' licenses require to travel with them.
func licenseFiles(root string) []string {
	entries, _ := os.ReadDir(root)
	var files []string
	for _, e := range entries {
		n := strings.ToUpper(e.Name())
		if !e.IsDir() && (strings.HasPrefix(n, "LICEN") || strings.HasPrefix(n, "COPYING") || strings.HasPrefix(n, "NOTICE")) {
			files = append(files, e.Name())
		}
	}
	return files
}

// An entry is a file to archive: its name in the archive and its slash path
// in the repo.
type entry struct{ name, src string }

// ruleFiles lists the YAML files under repo/sub that hold rules (their first
// non-comment line is "rules:"), skipping hidden dirs and rule tests. Archive
// names are relative to sub and prefixed with lang when set; files that end
// up outside a language directory (like opengrep-rules' template.yaml) are
// skipped.
func ruleFiles(repo, sub, lang string) ([]entry, error) {
	var files []entry
	root := filepath.Join(repo, filepath.FromSlash(sub))
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if lang != "" {
			rel = lang + "/" + rel
		}
		if d.IsDir() {
			if rel != "." && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		ext := path.Ext(rel)
		if (ext != ".yaml" && ext != ".yml") || !strings.Contains(rel, "/") ||
			strings.Contains(rel, ".test.") || strings.Contains(rel, ".fixed.") {
			return nil
		}
		if ok, err := isRuleFile(p); err != nil || !ok {
			return err
		}
		src, _ := filepath.Rel(repo, p)
		files = append(files, entry{name: rel, src: filepath.ToSlash(src)})
		return nil
	})
	slices.SortFunc(files, func(a, b entry) int { return strings.Compare(a.name, b.name) })
	return files, err
}

func isRuleFile(p string) (bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return strings.HasPrefix(sc.Text(), "rules:"), nil
	}
	return false, sc.Err()
}

// tarGz packs files from root with fixed metadata, so the same commit always
// yields the same bytes and checksum.
func tarGz(root string, files []entry) ([]byte, error) {
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.src)))
		if err != nil {
			return nil, err
		}
		hdr := &tar.Header{Name: f.name, Mode: 0o600, Size: int64(len(data)), Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
