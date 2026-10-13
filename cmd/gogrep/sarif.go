package main

import (
	"os"
	"slices"
	"strings"

	"github.com/odipar/gogrep/internal/sarif"
)

// sarifTargets reports where opengrep will write SARIF for args: the files it
// writes to, and whether SARIF goes to stdout.
func sarifTargets(args []string) (files []string, toStdout bool) {
	asked := slices.Contains(args, "--sarif")
	var output string
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch {
		case a == "-o" || a == "--output":
			output = next()
		case strings.HasPrefix(a, "--output="):
			output = strings.TrimPrefix(a, "--output=")
		case strings.HasPrefix(a, "-o") && !strings.HasPrefix(a, "--"):
			output = strings.TrimPrefix(strings.TrimPrefix(a, "-o"), "=")
		case a == "--sarif-output":
			files = append(files, next())
		case strings.HasPrefix(a, "--sarif-output="):
			files = append(files, strings.TrimPrefix(a, "--sarif-output="))
		}
	}
	if asked {
		if output == "" {
			toStdout = true
		} else {
			files = append(files, output)
		}
	}
	// Results posted to a URL never reach a local file.
	files = slices.DeleteFunc(files, func(f string) bool {
		return f == "" || strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://")
	})
	return files, toStdout
}

// writesNoResults reports whether args, before any "--", ask opengrep for
// something other than results, for which it writes no SARIF even with
// --sarif: help, its version, a check of rules (--validate, --test), the
// AST of a file, or a listing of languages or targets.
func writesNoResults(args []string) bool {
	for _, a := range args {
		switch {
		case a == "--":
			return false
		case a == "-h" || a == "--help" || strings.HasPrefix(a, "--help=") || a == "--version" ||
			a == "--validate" || a == "--test" || a == "--dump-ast" ||
			a == "--show-supported-languages" || a == "--x-ls" || a == "--x-ls-long":
			return true
		}
	}
	return false
}

// rebrandFile rewrites the SARIF file at path in place with sarif.Rebrand,
// and makes it readable by its owner only: opengrep creates it 0o644, and
// os.WriteFile keeps the mode of a file that exists. valid reports whether
// the file held the SARIF 2.1.0 log of one run that gogrep asks for.
func rebrandFile(path string) (valid bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	valid = sarif.Check(data) == nil
	out, err := sarif.Rebrand(data)
	if err != nil {
		return valid, err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return valid, err
	}
	return valid, os.Chmod(path, 0o600)
}
