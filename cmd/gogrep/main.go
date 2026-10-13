// Command gogrep scans source code with opengrep and gogrep's rule sets. It is
// a thin layer over package github.com/odipar/gogrep.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"

	"github.com/odipar/gogrep"
	"github.com/odipar/gogrep/internal/bundle"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// A cli is one run of gogrep, in the current directory.
type cli struct {
	stdout, stderr io.Writer
	dir            string // the current directory, where gogrep's project is
	eng            *gogrep.Engine
}

// newCLI returns a cli that writes to stdout and stderr, for the current
// directory.
func newCLI(stdout, stderr io.Writer) (*cli, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	bin, err := opengrepBinEnv()
	if err != nil {
		return nil, err
	}
	eng, err := gogrep.New(gogrep.Config{
		Opengrep:         bin,
		EmbeddedOpengrep: bundle.Binary(),
		AllowUnpinned:    true, // gogrep has always run any opengrep on $PATH
	})
	if err != nil {
		return nil, err
	}
	return &cli{stdout: stdout, stderr: stderr, dir: dir, eng: eng}, nil
}

// run runs gogrep with args and returns its exit code. `gogrep opengrep
// <args>` runs opengrep with args verbatim, gogrep's own flags included;
// `gogrep install-opengrep` takes none of them either.
func run(args []string, stdout, stderr io.Writer) int {
	c, err := newCLI(stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "gogrep: %v\n", err)
		return 2
	}
	if len(args) > 0 && args[0] == "opengrep" {
		return c.passThrough(args[1:])
	}
	if len(args) > 0 && args[0] == "install-opengrep" {
		return c.installOpengrep(args[1:])
	}
	args, sel, err := gogrepFlags(args)
	if err != nil {
		fmt.Fprintf(stderr, "gogrep: %v\n", err)
		return 2
	}
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "test":
		return c.runTest(args[1:], sel)
	case "rules":
		err = c.listRules(sel)
	case "suites":
		err = c.listSuites()
	default:
		return c.forward(args, sel)
	}
	if err != nil {
		fmt.Fprintf(stderr, "gogrep: %v\n", explain(err))
		return 2
	}
	return 0
}

// interruptContext returns a context that is done once gogrep receives one
// of its interrupts. A signal gogrep was started with ignored, as nohup
// does SIGHUP, stays ignored; given no signals at all, NotifyContext would
// catch every one.
func interruptContext() (context.Context, context.CancelFunc) {
	if sigs := slices.DeleteFunc(slices.Clone(interrupts), signal.Ignored); len(sigs) > 0 {
		return signal.NotifyContext(context.Background(), sigs...)
	}
	return context.Background(), func() {}
}

// opengrepBinEnv returns $OPENGREP_BIN, the opengrep that gogrep runs if
// set, made absolute when it is a path, as opengrep runs elsewhere than in
// the current directory: a name without a path separator is looked up in
// $PATH.
func opengrepBinEnv() (string, error) {
	p := os.Getenv("OPENGREP_BIN")
	if p == "" || !strings.ContainsAny(p, "/"+string(filepath.Separator)) && filepath.VolumeName(p) == "" {
		return p, nil
	}
	return filepath.Abs(p)
}
