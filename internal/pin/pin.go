// Package pin reads opengrep.json, which pins the opengrep release gogrep
// runs, the SHA-256 of its executable for each platform, and the git commits
// of the third-party rule sets.
package pin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"slices"
	"strings"
)

// Pins are the contents of opengrep.json.
type Pins struct {
	Version string           `json:"version"` // the opengrep release tag, such as "v1.30.2"
	Assets  map[string]Asset `json:"assets"`  // keyed by platform: GOOS/GOARCH, plus /musl for musl libc
	Rules   []RuleSet        `json:"rules"`
}

// An Asset is the opengrep release asset for one platform: the executable.
type Asset struct {
	Name   string `json:"name"`   // the asset's file name in the release
	SHA256 string `json:"sha256"` // its SHA-256, in lowercase hex
}

// A RuleSet pins a GitHub rule repository to a git commit; git's content
// addressing guarantees what is fetched.
type RuleSet struct {
	Name   string `json:"name"` // rule set name, used in --gogrep-ruleset
	Repo   string `json:"repo"` // GitHub owner/name
	Commit string `json:"commit"`
	Path   string `json:"path,omitempty"` // repo subdirectory holding the rules
	Lang   string `json:"lang,omitempty"` // language dir to file rules under, if the repo has none
}

// Stamp returns the stamp that internal/rulesets keeps next to the archive
// packed from r: its commit, path and lang, joined by spaces.
func (r RuleSet) Stamp() string {
	return r.Commit + " " + r.Path + " " + r.Lang
}

var (
	pathElem = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
	platform = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+(/musl)?$`)
	hexSum   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commit   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	setName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)
)

// Parse parses and validates opengrep.json. Every checksum must be 64
// lowercase hex digits, and every name usable in a URL or file name.
func Parse(data []byte) (*Pins, error) {
	var p Pins
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the JSON object")
	}
	if !pathElem.MatchString(p.Version) {
		return nil, fmt.Errorf("invalid version %q", p.Version)
	}
	if len(p.Assets) == 0 {
		return nil, errors.New("no assets")
	}
	for key, a := range p.Assets {
		musl := strings.HasSuffix(key, "/musl")
		switch {
		case !platform.MatchString(key) || (musl && !strings.HasPrefix(key, "linux/")):
			return nil, fmt.Errorf("asset %q: the platform must be GOOS/GOARCH, or linux/GOARCH/musl", key)
		case !pathElem.MatchString(a.Name):
			return nil, fmt.Errorf("asset %s: invalid name %q", key, a.Name)
		case !hexSum.MatchString(a.SHA256):
			return nil, fmt.Errorf("asset %s: sha256 %q is not 64 lowercase hex digits", key, a.SHA256)
		}
	}
	var names []string
	for _, r := range p.Rules {
		owner, repo, _ := strings.Cut(r.Repo, "/")
		switch {
		case !setName.MatchString(r.Name) || slices.Contains([]string{"gogrep", "project", "bundled", "all"}, r.Name):
			return nil, fmt.Errorf("invalid rule set name %q", r.Name)
		case slices.Contains(names, r.Name):
			return nil, fmt.Errorf("rule set %s is pinned twice", r.Name)
		case !pathElem.MatchString(owner) || !pathElem.MatchString(repo):
			return nil, fmt.Errorf("rule set %s: repo %q is not a GitHub owner/name", r.Name, r.Repo)
		case !commit.MatchString(r.Commit):
			return nil, fmt.Errorf("rule set %s: commit %q is not 40 lowercase hex digits", r.Name, r.Commit)
		case r.Path != "" && (!fs.ValidPath(r.Path) || r.Path == "."):
			return nil, fmt.Errorf("rule set %s: invalid path %q", r.Name, r.Path)
		case r.Lang != "" && !pathElem.MatchString(r.Lang):
			return nil, fmt.Errorf("rule set %s: invalid lang %q", r.Name, r.Lang)
		}
		names = append(names, r.Name)
	}
	return &p, nil
}

// Keys returns the platform keys under which opengrep.json may pin the
// opengrep for goos/goarch, most fitting first: on Linux the musl key and the
// glibc key, in the order musl says; elsewhere only goos/goarch.
func Keys(goos, goarch string, musl bool) []string {
	key := goos + "/" + goarch
	switch {
	case goos != "linux":
		return []string{key}
	case musl:
		return []string{key + "/musl", key}
	}
	return []string{key, key + "/musl"}
}

// Musl reports whether the Linux system whose root directory is root runs
// programs for goarch with musl libc: musl's dynamic loader is there and
// glibc's is not. glibc's wins because Debian's musl package installs musl's
// loader beside it.
func Musl(root fs.StatFS, goarch string) bool {
	var musl, glibc string
	switch goarch {
	case "amd64":
		musl, glibc = "lib/ld-musl-x86_64.so.1", "lib64/ld-linux-x86-64.so.2"
	case "arm64":
		musl, glibc = "lib/ld-musl-aarch64.so.1", "lib/ld-linux-aarch64.so.1"
	default:
		return false
	}
	_, muslErr := root.Stat(musl)
	_, glibcErr := root.Stat(glibc)
	return muslErr == nil && glibcErr != nil
}
