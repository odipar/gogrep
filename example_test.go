package gogrep_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/odipar/gogrep"
)

// Scan a cloned repository with the default suite, installing the pinned
// opengrep first if there is none.
func Example() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	eng, err := gogrep.New(gogrep.Config{})
	if err != nil {
		log.Fatal(err)
	}
	if _, err := eng.Opengrep(ctx); errors.Is(err, gogrep.ErrNoOpengrep) {
		_, err = eng.InstallOpengrep(ctx, nil) // downloads and verifies it
		if err != nil {
			log.Fatal(err)
		}
	} else if err != nil {
		log.Fatal(err)
	}

	res, err := eng.Scan(ctx, "/src/clone", &gogrep.ScanOptions{NoProjectRules: true})
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range res.Findings {
		if !f.Suppressed {
			fmt.Printf("%s:%d:%d: %s [%s]\n", f.Path, f.StartLine, f.StartColumn, f.Message, f.RuleID)
		}
	}
}

// A scan that opengrep could not complete may still have produced findings.
func ExampleEngine_Scan() {
	eng, err := gogrep.New(gogrep.Config{})
	if err != nil {
		log.Fatal(err)
	}
	res, err := eng.Scan(context.Background(), "/src/clone", &gogrep.ScanOptions{
		Selection: gogrep.Selection{Suites: []string{"security-extended"}},
		Jobs:      2,
	})
	var exitErr *gogrep.ExitError
	switch {
	case errors.Is(err, gogrep.ErrNoOpengrep):
		log.Fatalf("%v\nrun `gogrep install-opengrep`, or call Engine.InstallOpengrep", err)
	case errors.As(err, &exitErr) && exitErr.Result != nil:
		log.Printf("results may be incomplete: %v", err)
		res = exitErr.Result
	case err != nil:
		log.Fatal(err)
	}
	for _, d := range res.Diagnostics {
		log.Printf("opengrep: %s: %s", d.ID, d.Message)
	}
	fmt.Printf("%d findings from %d rules\n", len(res.Findings), res.Rules)
}

// List the rules of a project's own rule set. Rules runs no opengrep.
func ExampleEngine_Rules() {
	eng, err := gogrep.New(gogrep.Config{})
	if err != nil {
		log.Fatal(err)
	}
	dir, err := filepath.Abs(filepath.Join("testdata", "project"))
	if err != nil {
		log.Fatal(err)
	}
	rules, err := eng.Rules(dir, &gogrep.RulesOptions{Selection: gogrep.Selection{
		Suites:  []string{"all"},
		Filters: []gogrep.Filter{{Field: "ruleset", Values: []string{"project"}}},
	}})
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range rules {
		fmt.Println(r.ID, r.Fields["severity"][0])
	}
	// Output:
	// project.generic.todo-marker INFO
	// project.go.no-exec-command WARNING
	// project.go.no-exec-command-in-prod WARNING
}

// List the built-in suites.
func ExampleEngine_Suites() {
	eng, err := gogrep.New(gogrep.Config{})
	if err != nil {
		log.Fatal(err)
	}
	suites, err := eng.Suites("", nil)
	if err != nil {
		log.Fatal(err)
	}
	for _, s := range suites {
		if s.Default {
			fmt.Println(s.Name, "(default)")
		} else {
			fmt.Println(s.Name)
		}
	}
	// Output:
	// all
	// code-scanning (default)
	// security-and-quality
	// security-extended
}

// Validate finds malformed entries without loading any rules.
func ExampleSelection() {
	sel := gogrep.Selection{Rules: []string{"dangerous-exec-command", "/(/"}}
	err := sel.Validate()
	var se *gogrep.SelectionError
	if errors.As(err, &se) {
		fmt.Printf("%s %q: %v\n", se.Kind, se.Value, se.Err)
	}
	// Output:
	// rule "/(/": error parsing regexp: missing closing ): `(`
}

// Run a repository's rule test fixtures without writing into them, and
// print each test as it is done.
func ExampleEngine_Test() {
	eng, err := gogrep.New(gogrep.Config{})
	if err != nil {
		log.Fatal(err)
	}
	report, err := eng.Test(context.Background(), "/src/clone", &gogrep.TestOptions{
		ReadOnly: true,
		Progress: func(done, total int, r *gogrep.TestResult) {
			switch {
			case r == nil:
				fmt.Printf("Executing %d tests.\n", total)
			case r.Stage != "":
				fmt.Printf("[%d/%d] FAILED(%s) %s\n", done, total, r.Stage, r.Name)
			default:
				fmt.Printf("[%d/%d] PASSED %s\n", done, total, r.Name)
			}
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d passed, %d failed\n", report.Passed, len(report.Failed))
}

// Exit as the gogrep command does after a scan: with opengrep's code when
// it failed, 1 when there is no opengrep, and 2 for other errors.
func ExampleExitError() {
	eng, err := gogrep.New(gogrep.Config{})
	if err != nil {
		log.Fatal(err)
	}
	_, err = eng.Scan(context.Background(), "/src/clone", nil)
	var exitErr *gogrep.ExitError
	var integrity *gogrep.IntegrityError
	code := 0
	switch {
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode() // opengrep's own code, such as 7 for an invalid rule
	case errors.Is(err, gogrep.ErrNoOpengrep), errors.As(err, &integrity):
		code = 1
	case errors.Is(err, context.Canceled):
		code = 130
	case err != nil:
		code = 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
	}
	os.Exit(code)
}
