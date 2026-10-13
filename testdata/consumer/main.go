// Command repogrep scans repositories that are already cloned, several at a
// time, with one gogrep suite, and prints each finding as a JSON line.
//
// Usage:
//
//	repogrep [-suite name] [-parallel n] [-trust-project] [-install] dir...
//
// Exit status: 0 no live findings, 1 live findings, 2 a scan failed,
// 130 interrupted.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"

	"github.com/odipar/gogrep"
)

// A record is one finding as repogrep prints it.
type record struct {
	Repo       string `json:"repo"`
	Rule       string `json:"rule"`
	Level      string `json:"level"`
	Path       string `json:"path"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Message    string `json:"message"`
	Suppressed bool   `json:"suppressed,omitempty"`
}

// An outcome is how one repository's scan went.
type outcome struct {
	repo string
	res  *gogrep.Result
	err  error
}

func main() { os.Exit(run()) }

func run() int {
	suite := flag.String("suite", gogrep.DefaultSuite, "gogrep query `suite` to run")
	parallel := flag.Int("parallel", 2, "repositories to scan at once; each scan needs about 300 MB")
	trust := flag.Bool("trust-project", false, "also run each repository's own opengrep/gogrep rules and suites")
	install := flag.Bool("install", false, "download the pinned opengrep if it is missing (uses the network)")
	flag.Parse()
	if flag.NArg() == 0 || *parallel < 1 {
		flag.Usage()
		return 2
	}

	// gogrep handles no signals itself. The first Ctrl-C or SIGTERM cancels
	// ctx; gogrep then kills the opengrep process trees it started, and
	// every Scan returns. Since opengrep runs in process groups of its own,
	// a terminal's Ctrl-C reaches only this process.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eng, err := gogrep.New(gogrep.Config{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "repogrep:", err)
		return 2
	}
	// Find (or install) and prepare opengrep once, before fanning out, so
	// that a missing opengrep is one error rather than one per repository.
	if *install {
		_, err = eng.InstallOpengrep(ctx, nil)
	} else {
		_, err = eng.Opengrep(ctx)
	}
	switch {
	case ctx.Err() != nil:
		return interrupted()
	case errors.Is(err, gogrep.ErrNoOpengrep):
		fmt.Fprintf(os.Stderr, "repogrep: %v\nrepogrep: run again with -install\n", err)
		return 2
	case err != nil:
		fmt.Fprintln(os.Stderr, "repogrep:", err)
		return 2
	}

	repos := flag.Args()
	outcomes := make([]outcome, len(repos))
	slots := make(chan struct{}, *parallel)
	jobs := max(runtime.NumCPU() / *parallel, 1) // opengrep workers per scan
	var wg sync.WaitGroup
	for i, repo := range repos {
		wg.Go(func() {
			outcomes[i] = scan(ctx, eng, slots, repo, &gogrep.ScanOptions{
				Selection:      gogrep.Selection{Suites: []string{*suite}},
				NoProjectRules: !*trust, // cloned code is untrusted by default
				Jobs:           jobs,
			})
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return interrupted()
	}

	enc := json.NewEncoder(os.Stdout)
	code := 0
	for _, o := range outcomes {
		res := o.res
		var exitErr *gogrep.ExitError
		switch {
		case o.err == nil:
		case errors.As(o.err, &exitErr) && exitErr.Result != nil:
			// opengrep failed part-way but wrote a valid SARIF log:
			// report what it found, and the failure.
			fmt.Fprintf(os.Stderr, "repogrep: %s: %v; results may be incomplete\n", o.repo, o.err)
			res, code = exitErr.Result, 2
		default:
			fmt.Fprintf(os.Stderr, "repogrep: %s: %v\n", o.repo, o.err)
			code = 2
			continue
		}
		for _, d := range res.Diagnostics {
			if d.Level == "error" {
				fmt.Fprintf(os.Stderr, "repogrep: %s: opengrep: %s: %s\n", o.repo, d.ID, d.Message)
			}
		}
		live := 0
		for _, f := range res.Findings {
			err := enc.Encode(record{
				Repo: o.repo, Rule: f.RuleID, Level: f.Level, Path: f.Path,
				Line: f.StartLine, Column: f.StartColumn, Message: f.Message,
				Suppressed: f.Suppressed,
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "repogrep:", err)
				return 2
			}
			if !f.Suppressed {
				live++
			}
		}
		fmt.Fprintf(os.Stderr, "repogrep: %s: %d findings, %d suppressed, from %d rules\n",
			o.repo, live, len(res.Findings)-live, res.Rules)
		if live > 0 && code == 0 {
			code = 1
		}
	}
	return code
}

// scan scans one repository as soon as a slot is free.
func scan(ctx context.Context, eng *gogrep.Engine, slots chan struct{}, repo string, opts *gogrep.ScanOptions) outcome {
	o := outcome{repo: repo}
	// gogrep takes absolute directories only: resolving our arguments
	// against our working directory is our business, not gogrep's.
	dir, err := filepath.Abs(repo)
	if err != nil {
		o.err = err
		return o
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-ctx.Done():
		o.err = ctx.Err()
		return o
	}
	o.res, o.err = eng.Scan(ctx, dir, opts)
	return o
}

func interrupted() int {
	fmt.Fprintln(os.Stderr, "repogrep: interrupted")
	return 130
}
