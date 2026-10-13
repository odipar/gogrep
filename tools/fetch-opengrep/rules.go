package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/odipar/gogrep/internal/pin"
)

// fetchRules clones the pinned rules commit and packs its rule files, plus
// LICENSE, into the deterministic archive rulesDir/<name>.tar.gz, next to the
// stamp <name>.commit.
func fetchRules(set pin.RuleSet) error {
	out := filepath.Join(rulesDir, set.Name+".tar.gz")
	stamp := filepath.Join(rulesDir, set.Name+".commit")
	want := set.Stamp()
	if got, err := os.ReadFile(stamp); err == nil && string(got) == want {
		if _, err := os.Stat(out); err == nil {
			fmt.Printf("rules: %s@%.12s already present\n", set.Repo, set.Commit)
			return nil
		}
	}
	data, n, err := packRules(set)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("rules: packed %d rule files (%d KB)\n", n, len(data)/1024)
	return os.WriteFile(stamp, []byte(want), 0o600)
}

// checkRules packs the pinned rules commit again and checks that the
// committed archive holds the same files with the same contents, and that its
// stamp is the pin's. It compares what the archives hold, not their bytes,
// which compress/flate does not promise to keep across Go releases.
func checkRules(set pin.RuleSet) error {
	if got, err := os.ReadFile(filepath.Join(rulesDir, set.Name+".commit")); err != nil || string(got) != set.Stamp() {
		return fmt.Errorf("the stamp %s.commit is %q (%v), want %q", set.Name, got, err, set.Stamp())
	}
	committed, err := os.ReadFile(filepath.Join(rulesDir, set.Name+".tar.gz"))
	if err != nil {
		return err
	}
	have, err := listing(committed)
	if err != nil {
		return fmt.Errorf("%s.tar.gz: %w", set.Name, err)
	}
	packed, _, err := packRules(set)
	if err != nil {
		return err
	}
	want, err := listing(packed)
	if err != nil {
		return err
	}
	if !slices.Equal(have, want) {
		var diff []string
		for _, l := range have {
			if !slices.Contains(want, l) {
				diff = append(diff, "  committed only: "+l)
			}
		}
		for _, l := range want {
			if !slices.Contains(have, l) {
				diff = append(diff, "  pinned commit only: "+l)
			}
		}
		if len(diff) == 0 {
			diff = append(diff, "  the same files in another order")
		}
		return fmt.Errorf("%s.tar.gz differs from %s@%s; run go run ./tools/fetch-opengrep and commit the result:\n%s",
			set.Name, set.Repo, set.Commit, strings.Join(diff, "\n"))
	}
	fmt.Printf("rules: %s.tar.gz matches %s@%.12s (%d files)\n", set.Name, set.Repo, set.Commit, len(have))
	return nil
}

// listing returns what a rule set archive holds, in order: each entry's name,
// mode and SHA-256.
func listing(archive []byte) ([]string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	var entries []string
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		if _, err := io.Copy(h, tr); err != nil {
			return nil, err
		}
		entries = append(entries, fmt.Sprintf("%s %o %x", hdr.Name, hdr.Mode, h.Sum(nil)))
	}
}

// packRules clones the pinned rules commit and returns the deterministic
// archive of its rule files and license files, and how many rule files it
// holds.
func packRules(set pin.RuleSet) ([]byte, int, error) {
	tmp, err := os.MkdirTemp("", "opengrep-rules-*")
	if err != nil {
		return nil, 0, err
	}
	defer os.RemoveAll(tmp)

	fmt.Printf("rules: fetching %s@%s\n", set.Repo, set.Commit)
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", tmp}, args...)...)
		cmd.Stderr = os.Stderr
		b, err := cmd.Output()
		return strings.TrimSpace(string(b)), err
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"fetch", "-q", "--depth", "1", "https://github.com/" + set.Repo, set.Commit},
		{"checkout", "-q", "FETCH_HEAD"},
	} {
		if _, err := git(args...); err != nil {
			return nil, 0, fmt.Errorf("rules: git %s: %w", args[0], err)
		}
	}
	if head, err := git("rev-parse", "HEAD"); err != nil || head != set.Commit {
		return nil, 0, fmt.Errorf("rules: checked out %q, pinned %s (%v)", head, set.Commit, err)
	}

	files, err := ruleFiles(tmp, set.Path, set.Lang)
	if err != nil {
		return nil, 0, err
	}
	if len(files) == 0 {
		return nil, 0, fmt.Errorf("no rule files found in %s/%s", set.Repo, set.Path)
	}
	n := len(files)
	for _, l := range licenseFiles(tmp) {
		files = append(files, entry{name: l, src: l})
	}
	data, err := tarGz(tmp, files)
	return data, n, err
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
