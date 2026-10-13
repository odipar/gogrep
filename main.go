// Command gogrep is a thin wrapper around the opengrep binary. It is
// implemented by package cmd/gogrep; this file only embeds the files at the
// module root that it needs.
package main

import (
	"embed"
	"io/fs"
	"os"

	"github.com/odipar/gogrep/cmd/gogrep"
)

// rulesDir is the repo's rules directory, embedded in every build as the
// "gogrep" rule set.
//
//go:embed rules
var rulesDir embed.FS

// suitesDir holds the suites shipped with gogrep, by file name without .yaml.
//
//go:embed suites/*.yaml
var suitesDir embed.FS

func main() {
	os.Exit(gogrep.Main(os.Args[1:], gogrep.Assets{
		Rules:  sub(rulesDir, "rules"),
		Suites: sub(suitesDir, "suites"),
	}))
}

// sub returns the subtree dir of fsys, which always exists in an embed.FS.
func sub(fsys fs.FS, dir string) fs.FS {
	s, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return s
}
