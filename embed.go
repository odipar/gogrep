package gogrep

import (
	"embed"
	"io/fs"
)

// gogrep's own rule set ("gogrep"), its built-in suites and its pins. They are
// read-only; no package-level variable of this package is ever assigned.
var (
	//go:embed rules
	rulesFS embed.FS
	//go:embed suites/*.yaml
	suitesFS embed.FS
	//go:embed opengrep.json
	pinJSON []byte
)

// builtin is the source of gogrep's own files that every Engine New returns
// reads, so that they are parsed once per process.
var builtin = newSource(sub(rulesFS, "rules"), sub(suitesFS, "suites"), pinJSON)

// sub returns the subtree dir of fsys, which always exists in an embed.FS.
func sub(fsys fs.FS, dir string) fs.FS {
	s, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return s
}
