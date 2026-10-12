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
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
}

// fetchRules clones the pinned rules commit and packs its rule files, plus
// LICENSE, into the deterministic archive outDir/rules/<name>.tar.gz.
func fetchRules(pin rulesPin) error {
	if pin.Name == "" || strings.ContainsAny(pin.Name, `/\.`) {
		return fmt.Errorf("invalid rule set name %q", pin.Name)
	}
	dir := filepath.Join(outDir, "rules")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	out := filepath.Join(dir, pin.Name+".tar.gz")
	stamp := filepath.Join(dir, pin.Name+".commit")
	if got, err := os.ReadFile(stamp); err == nil && string(got) == pin.Commit {
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

	files, err := ruleFiles(tmp)
	if err != nil {
		return err
	}
	data, err := tarGz(tmp, append(files, licenseFiles(tmp)...))
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("rules: packed %d rule files (%d KB)\n", len(files), len(data)/1024)
	return os.WriteFile(stamp, []byte(pin.Commit), 0o644)
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

// ruleFiles lists the YAML files under root that hold rules (their first
// non-comment line is "rules:"), skipping hidden dirs, rule tests and the
// repo's rule template.
func ruleFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
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
		files = append(files, rel)
		return nil
	})
	slices.Sort(files)
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

// tarGz packs files (slash paths relative to root) with fixed metadata, so the
// same commit always yields the same bytes and checksum.
func tarGz(root string, files []string) ([]byte, error) {
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	tw := tar.NewWriter(gz)
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return nil, err
		}
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Format: tar.FormatPAX}
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
