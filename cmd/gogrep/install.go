package main

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/odipar/gogrep"
)

// installUsage is the help text of gogrep install-opengrep.
const installUsage = `Usage:
  gogrep install-opengrep [--from FILE] [--base-url URL]

Installs the opengrep release that this gogrep pins into gogrep's cache, and
prints its path. The asset is downloaded from GitHub, or from
URL/<version>/<asset>, or copied from FILE, a copy of the release asset; it
is verified against the SHA-256 that gogrep pins. A gogrep with opengrep
built in installs that.

Exit codes: 0 installed, 1 download or verification failed, 2 usage error,
130 interrupted.
`

// installOpengrep implements gogrep install-opengrep and returns its exit
// code.
func (c *cli) installOpengrep(args []string) int {
	opts := &gogrep.InstallOptions{}
	for i := 0; i < len(args); i++ {
		name, val, hasVal := strings.Cut(args[i], "=")
		var field *string
		switch name {
		case "-h", "--help":
			io.WriteString(c.stdout, installUsage)
			return 0
		case "--from":
			field = &opts.From
		case "--base-url":
			field = &opts.BaseURL
		default:
			fmt.Fprintf(c.stderr, "gogrep: gogrep install-opengrep takes --from and --base-url, not %s\n", args[i])
			return 2
		}
		if !hasVal {
			if i+1 == len(args) {
				fmt.Fprintf(c.stderr, "gogrep: %s needs a value\n", name)
				return 2
			}
			i++
			val = args[i]
		}
		*field = val
	}
	if opts.From != "" {
		from, err := filepath.Abs(opts.From)
		if err != nil {
			fmt.Fprintf(c.stderr, "gogrep: %v\n", err)
			return 2
		}
		opts.From = from
	}

	ctx, stop := interruptContext()
	defer stop()
	info, err := c.eng.InstallOpengrep(ctx, opts)
	switch {
	case err != nil && ctx.Err() != nil:
		fmt.Fprintln(c.stderr, "gogrep: interrupted")
		return 130
	case err != nil:
		fmt.Fprintf(c.stderr, "gogrep: %v\n", err)
		return 1
	}
	fmt.Fprintln(c.stdout, info.Path)
	return 0
}
