// Package rulesets holds the third-party rule sets that opengrep.json pins,
// embedded in every build. For each rule set, tools/fetch-opengrep packs
// <name>.tar.gz, a deterministic gzipped tar of the rule files and license
// files of the pinned git commit, and writes <name>.commit, the stamp of the
// pin it was packed from. Both are committed.
package rulesets

import (
	"embed"
	"strings"
)

//go:embed *.tar.gz *.commit
var files embed.FS

// Archives returns the rule set archives, keyed by rule set name.
func Archives() map[string][]byte {
	return read(".tar.gz")
}

// Stamps returns the stamp of each archive, keyed by rule set name: its pin's
// commit, path and lang, joined by spaces, empty ones included.
func Stamps() map[string]string {
	stamps := map[string]string{}
	for name, data := range read(".commit") {
		stamps[name] = string(data)
	}
	return stamps
}

// read returns the embedded files whose names end in ext, keyed by the rest
// of their names.
func read(ext string) map[string][]byte {
	byName := map[string][]byte{}
	entries, _ := files.ReadDir(".")
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ext); ok {
			byName[name], _ = files.ReadFile(e.Name())
		}
	}
	return byName
}
