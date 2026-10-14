package pin

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func TestParseOpengrepJSON(t *testing.T) {
	data, err := os.ReadFile("../../opengrep.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse(opengrep.json): %v", err)
	}
	if !strings.HasPrefix(p.Version, "v") || len(p.Assets) != 7 || len(p.Rules) != 3 {
		t.Errorf("opengrep.json pins %s, %d assets and %d rule sets; want a v tag, 7 and 3", p.Version, len(p.Assets), len(p.Rules))
	}
	for _, key := range []string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/amd64/musl", "linux/arm64", "linux/arm64/musl", "windows/amd64"} {
		if _, ok := p.Assets[key]; !ok {
			t.Errorf("opengrep.json pins no asset for %s", key)
		}
	}
	// fetch-opengrep -pin rewrites the file so. A Windows checkout may have
	// CRLF line ends.
	out, err := json.MarshalIndent(p, "", "  ")
	if err != nil || string(out)+"\n" != strings.ReplaceAll(string(data), "\r\n", "\n") {
		t.Errorf("Pins do not encode back to opengrep.json (%v):\n%s", err, out)
	}
}

func TestParseRejects(t *testing.T) {
	const sum = "f1aaa30b88959cb82522c4e1475816278a1f161f994509a518453c0455f9d24b"
	const commit = "f1d2b562b414783763fd02a6ed2736eaed622efa"
	pins := func(version, key, name, sha, rules string) string {
		return `{"version": "` + version + `", "assets": {"` + key + `": {"name": "` + name + `", "sha256": "` + sha + `"}}, "rules": [` + rules + `]}`
	}
	ruleSet := func(name, repo, commit, path string) string {
		return `{"name": "` + name + `", "repo": "` + repo + `", "commit": "` + commit + `", "path": "` + path + `"}`
	}
	good := ruleSet("0xdea", "0xdea/semgrep-rules", commit, "rules/c")
	if _, err := Parse([]byte(pins("v1.30.2", "darwin/arm64", "opengrep_osx_arm64", sum, good))); err != nil {
		t.Fatalf("Parse of a valid file: %v", err)
	}
	tests := []struct{ name, data, err string }{
		{"empty", "", "EOF"},
		{"not JSON", "{", "unexpected EOF"},
		{"trailing data", pins("v1.30.2", "darwin/arm64", "a", sum, good) + "{}", "data after the JSON object"},
		{"unknown field", `{"version": "v1", "sha265": ""}`, `json: unknown field "sha265"`},
		{"no version", pins("", "darwin/arm64", "a", sum, good), `invalid version ""`},
		{"version with a slash", pins("v1/x", "darwin/arm64", "a", sum, good), `invalid version "v1/x"`},
		{"no assets", `{"version": "v1"}`, "no assets"},
		{"platform without GOARCH", pins("v1", "darwin", "a", sum, good), `asset "darwin": the platform must be GOOS/GOARCH, or linux/GOARCH/musl`},
		{"unknown variant", pins("v1", "linux/amd64/glibc", "a", sum, good), `asset "linux/amd64/glibc": the platform must be GOOS/GOARCH, or linux/GOARCH/musl`},
		{"musl outside Linux", pins("v1", "darwin/arm64/musl", "a", sum, good), `asset "darwin/arm64/musl": the platform must be GOOS/GOARCH, or linux/GOARCH/musl`},
		{"upper-case platform", pins("v1", "Linux/amd64", "a", sum, good), `asset "Linux/amd64": the platform must be GOOS/GOARCH, or linux/GOARCH/musl`},
		{"asset name with a slash", pins("v1", "darwin/arm64", "../a", sum, good), `asset darwin/arm64: invalid name "../a"`},
		{"empty sha256", pins("v1", "darwin/arm64", "a", "", good), `asset darwin/arm64: sha256 "" is not 64 lowercase hex digits`},
		{"short sha256", pins("v1", "darwin/arm64", "a", sum[:16], good), `asset darwin/arm64: sha256 "f1aaa30b88959cb8" is not 64 lowercase hex digits`},
		{"upper-case sha256", pins("v1", "darwin/arm64", "a", strings.ToUpper(sum), good), "is not 64 lowercase hex digits"},
		{"rule set name with a dot", pins("v1", "darwin/arm64", "a", sum, ruleSet("a.b", "o/r", commit, "")), `invalid rule set name "a.b"`},
		{"reserved rule set name", pins("v1", "darwin/arm64", "a", sum, ruleSet("project", "o/r", commit, "")), `invalid rule set name "project"`},
		{"rule set pinned twice", pins("v1", "darwin/arm64", "a", sum, good+","+good), "rule set 0xdea is pinned twice"},
		{"repo without owner", pins("v1", "darwin/arm64", "a", sum, ruleSet("a", "r", commit, "")), `rule set a: repo "r" is not a GitHub owner/name`},
		{"repo with two slashes", pins("v1", "darwin/arm64", "a", sum, ruleSet("a", "o/r/x", commit, "")), `rule set a: repo "o/r/x" is not a GitHub owner/name`},
		{"short commit", pins("v1", "darwin/arm64", "a", sum, ruleSet("a", "o/r", commit[:12], "")), `rule set a: commit "f1d2b562b414" is not 40 lowercase hex digits`},
		{"path outside the repo", pins("v1", "darwin/arm64", "a", sum, ruleSet("a", "o/r", commit, "../x")), `rule set a: invalid path "../x"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Parse([]byte(tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.err) || p != nil {
				t.Errorf("Parse(%s) = %v, %v; want an error containing %q", tt.data, p, err, tt.err)
			}
		})
	}
}

func TestStamp(t *testing.T) {
	for _, tt := range []struct {
		r    RuleSet
		want string
	}{
		{RuleSet{Commit: "c", Path: "rules/c", Lang: "c"}, "c rules/c c"},
		{RuleSet{Commit: "c"}, "c  "},
		{RuleSet{Commit: "c", Lang: "go"}, "c  go"},
	} {
		if got := tt.r.Stamp(); got != tt.want {
			t.Errorf("%+v.Stamp() = %q, want %q", tt.r, got, tt.want)
		}
	}
}

func TestKeys(t *testing.T) {
	for _, tt := range []struct {
		goos, goarch string
		musl         bool
		want         []string
	}{
		{"darwin", "arm64", false, []string{"darwin/arm64"}},
		{"darwin", "arm64", true, []string{"darwin/arm64"}},
		{"windows", "amd64", false, []string{"windows/amd64"}},
		{"linux", "amd64", false, []string{"linux/amd64", "linux/amd64/musl"}},
		{"linux", "arm64", true, []string{"linux/arm64/musl", "linux/arm64"}},
	} {
		if got := Keys(tt.goos, tt.goarch, tt.musl); !slices.Equal(got, tt.want) {
			t.Errorf("Keys(%s, %s, %v) = %q, want %q", tt.goos, tt.goarch, tt.musl, got, tt.want)
		}
	}
}

func TestMusl(t *testing.T) {
	file := &fstest.MapFile{Data: []byte("ELF")}
	tests := []struct {
		name   string
		goarch string
		files  []string
		want   bool
	}{
		{"Alpine", "amd64", []string{"lib/ld-musl-x86_64.so.1"}, true},
		{"Alpine arm64", "arm64", []string{"lib/ld-musl-aarch64.so.1"}, true},
		{"glibc", "amd64", []string{"lib64/ld-linux-x86-64.so.2"}, false},
		{"glibc arm64", "arm64", []string{"lib/ld-linux-aarch64.so.1"}, false},
		{"Debian with the musl package", "amd64", []string{"lib/ld-musl-x86_64.so.1", "lib64/ld-linux-x86-64.so.2"}, false},
		{"Debian arm64 with the musl package", "arm64", []string{"lib/ld-musl-aarch64.so.1", "lib/ld-linux-aarch64.so.1"}, false},
		{"neither", "amd64", nil, false},
		{"the other architecture's loader", "arm64", []string{"lib/ld-musl-x86_64.so.1"}, false},
		{"no pinned musl build", "386", []string{"lib/ld-musl-i386.so.1"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := fstest.MapFS{}
			for _, f := range tt.files {
				root[f] = file
			}
			if got := Musl(root, tt.goarch); got != tt.want {
				t.Errorf("Musl(%q, %s) = %v, want %v", tt.files, tt.goarch, got, tt.want)
			}
		})
	}
}
