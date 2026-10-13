# Public Go API

Design for #5.

- **Issue:** #5. The request: *"i would like an api so that another cli tool that scans (git) repos locally (after cloning) can delegate to this gogrep api."*
- **Base:** `c309484` (main). Every `file:line` reference points at that commit.
- **First release with the API:** v0.4.0.
- **This document** is committed as `docs/design/library-api.md` (§9, step 0).
- **Evidence labels.** "Verified" means measured or reproduced against opengrep 1.30.2 on darwin/arm64 while preparing this design. "Inferred" means it follows from the code or documentation but was not run.

## 1. Summary, goals and non-goals

### 1.1 Summary

- **One public package at the module root.** `import "github.com/odipar/gogrep"` is `package gogrep`. It embeds gogrep's own `rules/`, `suites/*.yaml` and `opengrep.json`. The command moves to `cmd/gogrep`, which becomes `package main`.
- **One main type.** `*gogrep.Engine` comes from `New(Config)`.
  - It is safe for concurrent use.
  - Every method takes an absolute directory explicitly.
  - Every method that runs opengrep also takes a `context.Context`.
  - Methods: `Scan`, `Rules`, `Suites`, `Test`, `AcceptTests`, `Opengrep`, `InstallOpengrep`, `PruneCache`, and the Experimental `Command`.
- **Results are data.**
  - `Scan` returns the SARIF log (rebranded to `gogrep`) and typed `Finding`s, including `Suppressed` matches. It also returns diagnostics, the completion flag, the rule count and the tail of opengrep's stderr.
  - Findings are never errors.
  - gogrep still reads only opengrep's SARIF output.
- **The rule sets travel with the module.** The three pinned third-party archives (about 458 KB) are committed in `internal/rulesets` and embedded with no build tag. Every build and every `go get` therefore has the same 2,121 bundled rules.
- **The opengrep binary does not travel with the module.** It is 46–53 MB per platform. An engine finds it without network access, in this order:
  1. an explicit path;
  2. bytes the program embeds (gogrep's release builds do this);
  3. a SHA-256-verified copy in the cache;
  4. an `opengrep` on `PATH`, if it matches the pin or the caller allows unpinned binaries.

  `InstallOpengrep` is the only code that uses the network. It downloads the pinned asset and verifies it against the embedded `opengrep.json`.
- **First-run crash fix.** opengrep's 245 MB runtime is unpacked privately, then renamed atomically into the cache. Every opengrep child process is pointed at that copy. This fixes the verified SIGBUS crash of parallel cold runs.
- **No process-global state.** The library installs no signal handlers, never changes the working directory, never touches stdio, and never reads `OPENGREP_BIN` or `SEMGREP_RULES`. The two confirmed data races (`assets`, `bundle.sum`) disappear.
- **The command becomes a thin layer.** It may import only the public package, `internal/bundle` and `internal/sarif` from this module. Its behaviour stays identical except for the deliberate changes in §2.5.

### 1.2 Goals

| # | Goal | Met by |
|---|---|---|
| G1 | Scan a local directory with gogrep's selection (suite, rule ids, filters), including the directory's own `opengrep/gogrep` rules and suites | `Engine.Scan`, `Selection` |
| G2 | Results as data: SARIF bytes and typed findings | `Result`, `Finding`, `Diagnostic`, typed errors |
| G3 | List rules and suites; run and accept a repository's rule test fixtures | `Engine.Rules`, `Engine.Suites`, `Engine.Test`, `Engine.AcceptTests` |
| G4 | Many concurrent calls, each with its own directory and context, with no dependence on the working directory, signals, stdio or other globals | the `Engine` contract (§3.3, §3.4, §5) |
| G5 | The pinned opengrep and the rule sets without the release executable; offline by default; verified integrity | embedded archives; the lookup order and `InstallOpengrep` (§4) |
| G6 | The gogrep command is a thin layer over the same API, with identical behaviour | `cmd/gogrep` over `Engine` (§2.4, §2.5) |
| G7 | Keep the constraints | see below |

The constraints from G7:

- standard library plus `gopkg.in/yaml.v3` only;
- opengrep's output is consumed as SARIF only;
- owner-only files (0o600) and directories (0o700);
- macOS, Linux (glibc and musl) and Windows;
- stable rule ids `<set>.<dir>.<id>`.

### 1.3 Non-goals (v0.4)

- **Streaming findings.** opengrep writes one SARIF document when it exits, and its native JSON stream is ruled out, so a stream would be fake.
- **Parsing any opengrep output other than SARIF.** `Command` passes other output flags through for callers that want them, but the library never parses those outputs.
- **Git operations.** There is no cloning, fetching or checkout; the caller supplies directories.
- **Binaries in the Go module.** They would add 326 MiB per pin (§8.2).
- **An API for authoring rules or suites.**
- **Sandboxing.** Nothing beyond opengrep's own resource flags.
- **Overriding a repository's `.semgrepignore`** (§3.6).
- **Killing opengrep when the host itself is SIGKILLed.** Linux `Pdeathsig` is per OS thread; a Windows Job Object is a follow-up.
- **Changing the CLI's known argument-parsing quirks** (§2.5).
- **A v1 compatibility promise** (§8.1).

## 2. Package layout

### 2.1 Tree after the change

```
github.com/odipar/gogrep/              package gogrep: the public API
  doc.go embed.go engine.go selection.go list.go scan.go command.go
  test.go opengrep.go errors.go example_test.go *_test.go
  rules/              gogrep's own rule set "gogrep" (embedded)
  suites/*.yaml       built-in suites (embedded)
  opengrep.json       pins: opengrep version, assets, sha256, rule-set commits (embedded)
cmd/gogrep/                            package main: the gogrep command
  main.go flags.go forward.go list.go testcmd.go testreport.go install.go
  exit.go signals_unix.go signals_other.go *_test.go
internal/pin/         parse opengrep.json; platform keys; musl detection
internal/rulesets/    opengrep-rules, 0xdea, semgrep-go .tar.gz + .commit: TRACKED, embedded with no build tag
internal/bundle/      the opengrep binary only: -tags gogrep_bundled[,gogrep_musl]; bin/ stays gitignored;
                      imported only by cmd/gogrep
internal/opengrep/    resolve, verify, extract, download, runtime preparation, file locks,
                      the process runner (ctx, process tree, ETXTBSY retry), opengrep's environment
internal/rules/       unchanged, except Write takes its directory
internal/suite/       unchanged
internal/ruletest/    Discover(base, ...), Plan, Classify, Render, Diff; the runner returns results
internal/sarif/       the SARIF subset gogrep reads; findings; Rebrand
internal/fakeopengrep/ test helper: the test binary standing in for opengrep
tools/fetch-opengrep/ uses internal/pin and internal/opengrep's download
testdata/consumer/    separate module: the §6 example and the go-get consumer test (§7.4)
testdata/modzip/      separate module: builds gogrep's exact module zip (golang.org/x/mod)
```

**Decision: the module root is the library.**

- It gives the best import path.
- The root can embed its own `rules/`, `suites/` and `opengrep.json`. `go:embed` cannot reach `..`, which is the only reason `Assets` exists today, so that plumbing disappears.
- It follows the split of `golang.org/x/tools/go/analysis` and `golang.org/x/vuln/scan`: the library returns data, and the command owns flags, text and exit codes.
- **Costs:**
  - The install path becomes `go install github.com/odipar/gogrep/cmd/gogrep@latest`.
  - HEAD's exported `cmd/gogrep.Main` and `Assets` go away. They were never released: v0.3.0 has nothing importable.

**Decision: the CLI code lives directly in `cmd/gogrep` (`package main`), not in an `internal/cli` package.**

- Its tests keep the in-process `run(args, stdout, stderr)` entry point and the re-executed fake opengrep, and both work in a main package.
- An import test keeps the layer thin. `TestCLIUsesPublicAPI` runs `go list -f '{{join .Imports "\n"}}' ./cmd/gogrep` and fails if any `github.com/odipar/gogrep/...` import is anything other than the root package, `internal/bundle` or `internal/sarif` (for `Rebrand` and `Check`).
- It checks the direct, non-test imports. `go list -deps` would also list the library's own internal imports, so a test built on it could never pass.

**Decision: the opengrep binary never enters the library's import graph.**

- Only `cmd/gogrep` imports `internal/bundle`. The binary reaches an engine only as `Config.EmbeddedOpengrep []byte`.
- **This is what keeps `go mod vendor` safe for importers.**
  - `go mod vendor` resolves the `go:embed` patterns of every file in every package it vendors, whatever their build tags.
  - A tagged embed of a gitignored file in any package the library imports therefore breaks vendoring for every importer. This was reproduced with a minimal module pair: tidy and build passed, and vendor failed with `pattern bin/opengrep…: no matching files found`.
  - Renaming the tags does not fix that. Only keeping the tagged embed in a package that no package in a consumer's import graph imports does.
  - This is why the always-embedded archives get their own package, `internal/rulesets`, separate from `internal/bundle`.
- **Why the tags are renamed anyway.** `bundled` and `musl` become `gogrep_bundled` and `gogrep_musl` so that a tag set for other reasons in a GOFLAGS-wide build cannot switch on embeds whose files a `go install` does not have. Generic tags are easy to collide with; `-tags musl`, for example, is commonly set on Alpine for other cgo dependencies.
- **Consumers can embed opengrep themselves** through the same `Config.EmbeddedOpengrep` field.

### 2.2 What moves where

| Today | After |
|---|---|
| `main.go` (root, `package main`: embeds `rules/` and `suites/`, calls `gogrep.Main`) | Root `embed.go` (`package gogrep`) embeds `rules`, `suites/*.yaml` and `opengrep.json`; `cmd/gogrep/main.go` is `package main` |
| `cmd/gogrep/run.go`: `Main`, `Assets`, `var assets` | Removed (§5) |
| `run.go`: `run` (dispatch) | `cmd/gogrep/main.go` |
| `run.go`: `forward` | `cmd/gogrep/forward.go`, over `Engine.Command` |
| `run.go`: `execOpengrep`, `utf8Env` | `internal/opengrep` (`run.go`, `env.go`) |
| `run.go`: `opengrepBin`; `testcmd.go`: `testBin` | `internal/opengrep/resolve.go` behind `Engine.Opengrep`; the CLI keeps only the `$OPENGREP_BIN` mapping |
| `rulesargs.go`: `gogrepFlags` | `cmd/gogrep/flags.go`, producing a `gogrep.Selection` |
| `rulesargs.go`: `withRules`, the decision whether gogrep supplies rules | `cmd/gogrep/forward.go`. The injection itself is in root `command.go` |
| `rulesargs.go`: `selection.resolve`, `filter`, `union`, `ruleByID`, `allRules`, `dedupe` | Root `selection.go` |
| `rulesargs.go`: `loadEnv`, `loadSuite` | Root `engine.go`: built-in sets parsed once per process, the project set per call |
| `rulesargs.go`: `listRules`, `listSuites` | Data in root `list.go`; tables in `cmd/gogrep/list.go` |
| `sarif.go`: `rebrand` | `internal/sarif.Rebrand` (byte-identical output) |
| `sarif.go`: `sarifTargets`, `rebrandFile` | `cmd/gogrep/forward.go`; `rebrandFile` also chmods 0o600 |
| `testcmd.go`: `parseTestArgs`, `testUsage`, `runTest` | `cmd/gogrep/testcmd.go` |
| `testcmd.go`: `runFixtures` | Root `test.go` (`Engine.Test`) |
| `testcmd.go`: `execFixture`; `procgroup_*.go`: `killTree` | `internal/opengrep` (`run.go`, `procgroup_*.go`) |
| `procgroup_*.go`: `interrupts` | `cmd/gogrep/signals_*.go` |
| `internal/bundle`: `Path`, `extract` | `internal/opengrep/extract.go`, writing into `Config.CacheDir` |
| `internal/bundle`: `RuleSets`, `bin/rules/` | `internal/rulesets` (tracked, no build tag) |
| `internal/bundle/embed_*.go` with `.sha256` embeds (tags `bundled`, `musl`) | `internal/bundle`: `Binary()` only, tags `gogrep_bundled` and `gogrep_musl`; the checksum comes from `opengrep.json` |
| `internal/ruletest/report.go`: `verdict.print`, `tally.print`, `WarnUntested`, `commandLine` | `cmd/gogrep/testreport.go` (text formatting) |
| `internal/ruletest/sarif.go` | `internal/sarif` |
| `ruletest.Discover(root, paths)` | `ruletest.Discover(base, root, paths)` |
| `rules.Write(rules)` | `rules.Write(dir, rules)` |
| `tools/fetch-opengrep`: pin parsing and downloading | `internal/pin`, `internal/opengrep.Download` |

### 2.3 How rules, suites and pins reach the library

```go
// embed.go
package gogrep

import "embed"

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
```

- **The third-party sets.** `internal/rulesets` embeds `*.tar.gz` and `*.commit` with no build tag.
- **The pins.** `opengrep.json` is parsed by `internal/pin.Parse` inside a `sync.OnceValues`. The result is immutable.
- **What `go get` delivers.** About 0.6 MB: today's 156,675-byte module zip plus the 457,862 bytes of archives.
- **Rule count.** Every build reports the same 2,121 bundled rules that `gogrep rules --suite all` reports from the repository root today (verified; `rules/` holds only `README.md`).

### 2.4 The CLI as a thin layer

`cmd/gogrep/main.go`:

```go
// Command gogrep scans source code with opengrep and gogrep's rule sets. It is
// a thin layer over package github.com/odipar/gogrep.
package main

import "os"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
```

`run` builds one engine per invocation. It takes `dir` from `os.Getwd()`.

```go
eng, err := gogrep.New(gogrep.Config{
	Opengrep:         opengrepBinEnv(),  // $OPENGREP_BIN, made absolute when it contains a separator
	EmbeddedOpengrep: bundle.Binary(),   // nil without -tags gogrep_bundled
	AllowUnpinned:    true,              // as today: any opengrep on PATH runs
})
```

How each subcommand maps onto the API:

| CLI | Public API call | CLI-only work |
|---|---|---|
| `gogrep scan …` | `eng.Command(ctx, dir, &CommandOptions{Selection: sel or nil}, args...)`, then `Cmd.Run()` | `withRules` decision; `signal.NotifyContext`; stdin; rebranding SARIF to stdout and to `-o`/`--output`/`--sarif-output` files (chmod 0o600); the no-SARIF check; exit codes |
| any other first argument that is not a gogrep subcommand (`gogrep --version`, `gogrep lsp`, …) | `eng.Command(ctx, dir, &CommandOptions{Foreground: true}, args...)` | `signal.Ignore(SIGINT, SIGTERM)`, `os.Stdin`, SARIF rebranding, as today |
| `gogrep opengrep …` | `eng.Command(ctx, dir, &CommandOptions{Foreground: true}, args...)` | `signal.Ignore`, `os.Stdin`, streams passed straight through, exit code verbatim, no rebranding |
| `gogrep rules` | `eng.Rules(dir, &RulesOptions{Selection: sel})` | tabwriter table; `N rules` (or `1 rule`) on stderr |
| `gogrep suites` | `eng.Suites(dir, nil)` | Table: `(default)`, and `-` when `Err` is set |
| `gogrep test [run]` | `eng.Test(ctx, dir, &TestOptions{…, Progress: printer})` | `Executing N tests.`, status lines, diffs, `$ (cd … && …)` lines, summary, untested warning, `gogrep: interrupted` |
| `gogrep test accept` | `eng.AcceptTests(dir, paths)` | `Accepted X` and its errors |
| `gogrep install-opengrep [--from F] [--base-url U]` (new) | `eng.InstallOpengrep(ctx, &InstallOptions{From: F, BaseURL: U})` | Prints the installed path |

**What stays in the CLI.** These are command concerns, so they stay there:

- `$OPENGREP_BIN` and the working directory.
- Flag syntax.
- The `withRules` decision: `-c`, `-f`, `--config`, `--config=`, `-e`, `--pattern`, `--pattern=` and `$SEMGREP_RULES` mean the user names rules; `--suite`, `--rule` and `--config bundled` mean gogrep supplies them, and the `bundled` pair is removed.
- Explicit-but-empty selections. In the library the zero `Selection` means the default suite. So `--suite=` or `--rule=` given with no value is detected in the CLI, which prints today's `the --suite/--rule/--gogrep-* selection matches no rules` (exit 2) for `scan`, `rules` and `test`.
- All message texts and hints.
- Signal handling and the exit codes of §3.7.

The `scan` path, as a sketch. It was type-checked with `go vet` against a stub of §3.2.

```go
// forward runs `gogrep scan …` in a process group of its own: Ctrl-C reaches
// gogrep, which cancels ctx, and Run kills opengrep's whole tree.
func (c *cli) forward(ctx context.Context, args []string, sel selection) int {
	args, inject := withRules(args, sel) // --config/-c/-f/-e/--pattern, $SEMGREP_RULES; drops --config bundled
	opts := &gogrep.CommandOptions{}
	if inject {
		if sel.explicit && len(sel.Suites) == 0 && len(sel.Rules) == 0 {
			fmt.Fprintln(c.stderr, "gogrep: the --suite/--rule/--gogrep-* selection matches no rules")
			return 2 // --suite= or --rule= given with no value, as today
		}
		opts.Selection = &sel.Selection
	}
	cmd, err := c.eng.Command(ctx, c.dir, opts, args...)
	if err != nil {
		fmt.Fprintf(c.stderr, "gogrep: %v\n", c.explain(err))
		var integrity *gogrep.IntegrityError
		if errors.Is(err, gogrep.ErrNoOpengrep) || errors.As(err, &integrity) {
			return 1
		}
		return 2 // a selection or setup error
	}
	files, toStdout := sarifTargets(args)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = c.stdout, c.stderr
	if toStdout {
		cmd.Stdout = &out
	}
	if !terminalStdin() { // a background process group must not read the terminal
		cmd.Stdin = os.Stdin
	}
	err = cmd.Run()
	var exitErr *gogrep.ExitError
	switch {
	case ctx.Err() != nil:
		fmt.Fprintln(c.stderr, "gogrep: interrupted")
		return 130
	case errors.As(err, &exitErr):
	case err != nil:
		fmt.Fprintf(c.stderr, "gogrep: %v\n", err)
		return 1
	}
	code, noSARIF := 0, false
	if exitErr != nil {
		code = exitErr.Code
	}
	if toStdout {
		data := out.Bytes()
		noSARIF = sarif.Check(data) != nil // SARIF 2.1.0 with one run
		if b, err := sarif.Rebrand(data); err == nil {
			data = append(b, '\n')
		}
		c.stdout.Write(data)
	}
	for _, f := range files {
		// rebrandFile checks and rewrites the file in place, then chmods it 0o600.
		if err := rebrandFile(f); err != nil {
			noSARIF = true
			if !errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(c.stderr, "gogrep: rewriting SARIF %s: %v\n", f, err)
			}
		}
	}
	if code == 0 && noSARIF {
		fmt.Fprintln(c.stderr, "gogrep: opengrep exited 0 but wrote no SARIF")
		return 2
	}
	return code
}
```

Why `gogrep scan` uses `Command` and not `Scan`:

- The CLI accepts every opengrep flag (`--json`, `--error`, `-o`, `--config auto`, …) and keeps opengrep's own exit code. `Scan` exists for library callers who want data.
- `Command` and `Scan` share one internal builder for rule injection, the environment, the working directory and process handling.

**The test report.** `cmd/gogrep/testreport.go` renders today's text byte for byte from `TestResult`s:

- `[i/n] PASSED|LEARNED|FAILED(STAGE) name`, then `Cannot find expected.txt.`, the diff and the indented details.
- The `--show-opengrep-output` lines: `  $ (cd <Name> && <Command>)`, then the stderr lines quoted with `> `.
- The summary and the untested warning.

`cd` uses `TestResult.Name`, the fixture's slash path relative to the project directory. That is exactly what today's relative `Fixture.Dir` prints, so the line can still be pasted where `gogrep test` ran (rule-test-fixtures.md §5.3). `commandLine` moves to the CLI. The 12-line `quoted` helper is copied, because `ruletest.Classify` keeps its own copy.

### 2.5 CLI behaviour: unchanged, except these deliberate changes

Every other behaviour, including all golden files and the injected argv apart from item 7, stays byte-identical. Each change is its own commit with a test (§9) and is listed in the v0.4.0 release notes.

1. **Install and build path.**
   - Install with `go install github.com/odipar/gogrep/cmd/gogrep@latest`, and build `./cmd/gogrep`.
   - The old path builds only v0.3.x and older. Release executables are unaffected.
2. **Build tags.**
   - `bundled` becomes `gogrep_bundled` and `musl` becomes `gogrep_musl`.
   - `-tags bundled` now fails to compile with an error that names `gogrep_bundled` (`internal/bundle/oldtag.go`).
   - `-tags gogrep_bundled` now compiles on platforms without a pinned binary (freebsd, linux/386, windows/arm64), and the result embeds no binary. Today these builds fail with `undefined: binary`.
3. **Plain builds have the rule sets.**
   - `go install` builds contain the 2,121 bundled rules, so `gogrep scan .` runs `code-scanning` instead of handing opengrep a scan with no rules.
   - The hint `; this gogrep build has no bundled rule sets` (`internal/ruletest/ref.go:95`) and the error `this gogrep build has no bundled rules` can no longer occur.
4. **Interrupting `gogrep scan`.**
   - **Before:** opengrep shared gogrep's process group while gogrep ignored SIGINT and SIGTERM (`run.go:115`). An interrupted scan exited 0 with no SARIF and no message (reproduced twice).
   - **Now:** opengrep runs in a process group of its own, as it already does under `gogrep test`. SIGINT and SIGTERM (plus SIGHUP and SIGQUIT on Unix) make gogrep kill the tree, print `gogrep: interrupted` and exit 130.
   - **Stdin:** opengrep's stdin is the null device when gogrep's stdin is a terminal, because a background process group that reads the terminal is stopped by SIGTTIN. Pipes and files are still passed on. The check is for a character device (`os.ModeCharDevice`), which the standard library tells without per-OS ioctls; the null device is one too and reads the same, so only an unusual stdin such as `/dev/zero` also becomes the null device.
   - **Known limit:** under `stty tostop`, a background group that writes to the terminal is stopped as well. Ctrl-C still ends the scan.
5. **Exit 0 without SARIF is now an error.** A forwarded command that asked for SARIF and exited 0 without a valid SARIF 2.1.0 log (to stdout, or in an `-o`/`--sarif-output` file) exits 2 with `gogrep: opengrep exited 0 but wrote no SARIF`. Before, gogrep exited 0.
6. **SARIF files are 0o600.** SARIF files gogrep rewrites (`-o`, `--output`, `--sarif-output`) end with mode 0o600. opengrep creates them 0o644, and `os.WriteFile` keeps an existing file's mode (`sarif.go:66`; observed).
7. **`--disable-version-check` on injected scans.** Scans that gogrep supplies rules to also get `--disable-version-check`, so `$OPENGREP_ENABLE_VERSION_CHECK` can no longer turn on a network request. Scans with the user's own `--config` stay verbatim.
8. **New opengrep lookup and `gogrep install-opengrep`.**
   - The lookup is `$OPENGREP_BIN`, then the embedded binary, then the **verified cache**, then `PATH` (any version, as before).
   - `gogrep install-opengrep [--from FILE] [--base-url URL]` fills the cache. Before, `install-opengrep` was passed to opengrep, which rejects it.
   - An unbundled gogrep that finds no opengrep now prints the not-installed message of §4.2 instead of `exec: "opengrep": executable file not found in $PATH`. The exit code is still 1.
9. **opengrep's runtime moves under gogrep's cache** on Linux and macOS (§4.6).
   - Every opengrep that gogrep starts, including `gogrep opengrep …`, gets `XDG_CACHE_HOME=<cache>/gogrep/runtime-<sha16>`.
   - After upgrading, the first run unpacks once (about 8 s, 245 MB).
   - Parallel `gogrep` processes on a cold machine no longer crash: 2 of 4 died with SIGBUS in each of three trials before.
10. **`gogrep test` is hermetic.** It runs opengrep with every `SEMGREP_*` and `OPENGREP_*` variable removed, and with a log file of its own per opengrep process. It therefore no longer overwrites `~/.opengrep/semgrep.log`. Its output is unchanged.

**Still the same:**

- `gogrep opengrep …` and the other forwarded commands keep the caller's process group, `signal.Ignore`, `os.Stdin`, verbatim arguments and opengrep's exit code. Their environment gains only item 9's `XDG_CACHE_HOME`.
- `gogrep scan` keeps writing `~/.opengrep/semgrep.log`, because `Command` does not set a log file.

**Known quirks, kept unchanged:**

- `gogrepFlags` does not stop at `--`.
- An unrecognised first argument goes to opengrep.
- `gogrep rules` ignores extra arguments.
- `--sarif` is recognised only as that exact token.

## 3. The API

### 3.1 At a glance

```go
eng, err := gogrep.New(gogrep.Config{})
if _, err := eng.Opengrep(ctx); errors.Is(err, gogrep.ErrNoOpengrep) {
	_, err = eng.InstallOpengrep(ctx, nil) // the only network access; verified against opengrep.json
}
res, err := eng.Scan(ctx, "/abs/clone", &gogrep.ScanOptions{
	Selection:      gogrep.Selection{Suites: []string{"security-extended"}},
	NoProjectRules: true, // an untrusted clone
	Jobs:           2,
})
for _, f := range res.Findings {
	fmt.Println(f.RuleID, f.Path, f.StartLine, f.Level, f.Suppressed)
}
```

### 3.2 Complete exported surface

The listing below is the whole exported surface. It was type-checked with `go vet` against a stub, and the §6 example compiles against that stub. It uses `context`, `errors`, `io`, `log/slog`, `net/http` and `time`.

```go
// Package gogrep scans source trees with opengrep and gogrep's pinned rule
// sets, selected with CodeQL-style query suites under stable rule ids, and
// returns the results as SARIF and as typed findings. The gogrep command is
// a thin layer over it.
//
// The package documentation covers how opengrep is obtained, the offline
// guarantee, concurrency and memory, cancellation, untrusted repositories,
// the files gogrep writes, what it reads from the process, stability and
// licensing.
package gogrep

// ===================================================================== paths

// DefaultSuite is the suite that Scan, Rules and Command run when a
// Selection names no suites and no rules.
const DefaultSuite = "code-scanning"

// Slash paths, relative to a project directory, of what gogrep reads there.
const (
	ProjectRulesDir  = "opengrep/gogrep/rules"      // the "project" rule set
	ProjectTestsDir  = "opengrep/gogrep/rules/test" // rule test fixtures; never loaded as rules
	ProjectSuitesDir = "opengrep/gogrep/suites"     // project suites; they shadow built-in ones
)

// ==================================================================== engine

// A Config configures an Engine. The zero Config is ready to use: opengrep is
// the pinned build from the cache (or a verified one on PATH), files go under
// the user cache directory, opengrep gets the process environment, and
// nothing is logged. Fields added later will default to the old behaviour.
type Config struct {
	// Opengrep is the opengrep executable to run: an absolute path, or a
	// name without a path separator that is looked up in the process's
	// PATH when first needed. It is used whatever its version;
	// OpengrepInfo.Pinned reports whether it is the pinned build. New
	// rejects a relative path that contains a separator. Empty means: find
	// opengrep as Engine.Opengrep describes. The package never reads
	// $OPENGREP_BIN; the gogrep command passes it here.
	Opengrep string

	// EmbeddedOpengrep is an opengrep executable compiled into the program,
	// for example with go:embed. Its SHA-256 must be the pinned one for the
	// running GOOS/GOARCH (glibc or musl on Linux); otherwise Opengrep
	// returns an *IntegrityError. It is written once to CacheDir. gogrep's
	// release builds set it.
	EmbeddedOpengrep []byte

	// AllowUnpinned lets the engine run an opengrep found on PATH whose
	// SHA-256 is not the pinned one. Findings then depend on that
	// opengrep's version. The gogrep command sets it, as it has always run
	// any opengrep on PATH.
	AllowUnpinned bool

	// CacheDir is where gogrep keeps the opengrep executable, opengrep's
	// unpacked runtime, rule selections, locks and per-run logs. It must be
	// absolute. Empty means filepath.Join(os.UserCacheDir(), "gogrep"),
	// resolved in New and shared with the gogrep command; if
	// os.UserCacheDir fails, the operations that need the cache return
	// that error. Directories are created 0o700 and files 0o600 (0o700 for
	// the executable).
	CacheDir string

	// Env is the environment opengrep runs in, as in exec.Cmd.Env. nil
	// means os.Environ() as of New. Scan and Test remove every SEMGREP_*
	// and OPENGREP_* variable from it and set SEMGREP_LOG_FILE to a file of
	// their own; Command does neither. All add LC_ALL=C.UTF-8 unless Env
	// itself selects a UTF-8 locale (PYTHONUTF8=1 on Windows), since
	// opengrep crashes on non-ASCII rules otherwise, and on Linux and macOS
	// set XDG_CACHE_HOME to the runtime directory in CacheDir. opengrep
	// runs git, which it finds through Env's PATH.
	Env []string

	// Logger receives gogrep's own records at Debug and Info level: which
	// opengrep it found, extraction, downloads, runtime preparation, lock
	// waits and each opengrep command line. nil discards them. The package
	// never changes slog's default logger, and opengrep's own output never
	// goes to Logger.
	Logger *slog.Logger
}

// An Engine scans directories, lists rules and suites, and runs rule test
// fixtures.
//
// An Engine is safe for concurrent use by multiple goroutines. No method
// reads or changes the process's working directory, signal dispositions or
// standard streams, and none reads environment variables beyond the
// defaults Config documents. Every directory argument must be absolute.
// Methods that run opengrep take a context: when it is done, they kill the
// opengrep processes they started, with every process those started, and
// return an error that wraps ctx.Err().
type Engine struct{ /* unexported */ }

// New returns an Engine for cfg. It runs nothing and reads no file: opengrep
// is found, and gogrep's built-in rule sets are parsed (about 0.13 s, once
// per process), when first needed. It returns an error only for an invalid
// cfg, such as a relative CacheDir or a relative Opengrep path.
func New(cfg Config) (*Engine, error)

// ================================================================== opengrep

// OpengrepInfo describes the opengrep executable an Engine runs.
type OpengrepInfo struct {
	Path    string // absolute path of the executable
	Source  string // "config", "embedded", "cache" or "path"
	SHA256  string // hex SHA-256 of the executable
	Pinned  bool   // SHA256 is the pinned asset's for this platform
	Version string // the pinned version, such as "v1.30.2", when Pinned; "" otherwise
}

// Opengrep finds the opengrep executable and prepares it to run, without
// using the network. It tries, in order: Config.Opengrep;
// Config.EmbeddedOpengrep, written to CacheDir; the pinned executable in
// CacheDir; opengrep on PATH, if its SHA-256 is the pinned one or
// Config.AllowUnpinned is set. A checksum is computed once per process for
// each path, size and modification time. The first time an executable is
// used with a CacheDir, Opengrep unpacks opengrep's runtime (about 245 MB
// and 8 s) privately and publishes it there, so that concurrent opengrep
// processes never start from a half-written runtime.
//
// Scan, Test and Command call Opengrep; call it yourself to fail early.
// When no opengrep is found, it returns an error that wraps ErrNoOpengrep
// and names the pinned version, platform, asset, checksum, cache path and
// remedies.
func (e *Engine) Opengrep(ctx context.Context) (*OpengrepInfo, error)

// InstallOptions configure Engine.InstallOpengrep; nil means the zero
// InstallOptions, which download the pinned asset for this platform from
// GitHub.
type InstallOptions struct {
	// From is a local copy of the pinned release asset to install instead
	// of downloading it, for machines without network access: an absolute
	// path. It is verified exactly like a download.
	From string

	// BaseURL is where assets are downloaded from, as
	// <BaseURL>/<version>/<asset>. Empty means
	// https://github.com/opengrep/opengrep/releases/download. A mirror must
	// serve identical bytes, since they are checked against the pin.
	BaseURL string

	// Client makes the download. nil means http.DefaultClient, whose
	// transport honours HTTPS_PROXY and NO_PROXY.
	Client *http.Client

	// Platform picks the build for the running GOOS/GOARCH: "GOOS/GOARCH",
	// or "linux/amd64/musl" and "linux/arm64/musl" for musl libc. Empty
	// means the build the engine detects. Another GOOS/GOARCH is an error.
	Platform string
}

// InstallOpengrep makes the pinned opengrep available in CacheDir, prepares
// its runtime, and returns what Opengrep then returns. With
// Config.EmbeddedOpengrep set, it only extracts that. Otherwise, unless
// CacheDir already holds a verified copy, it copies From or downloads the
// asset (at most 256 MiB, retried up to 3 times on network errors and 5xx
// responses). The bytes are hashed as they stream into a temporary file and
// compared with the SHA-256 in this module's opengrep.json before the file
// is made executable and renamed into place, so a partial or altered file is
// never run; a mismatch is an *IntegrityError. Concurrent installs, in one
// process or several, never expose a partial file.
//
// InstallOpengrep is the only method that uses the network, and only when it
// must download. Config.Opengrep, if set, still takes precedence over the
// installed copy.
func (e *Engine) InstallOpengrep(ctx context.Context, opts *InstallOptions) (*OpengrepInfo, error)

// PruneOptions configure Engine.PruneCache; nil means the zero PruneOptions.
type PruneOptions struct {
	// MaxAge is how long an entry that no run has used is kept. Zero means
	// 30 days.
	MaxAge time.Duration
}

// PruneCache removes from CacheDir what no run has used for MaxAge: rule
// selections, and the executables and runtimes of opengrep builds other
// than this version's pins. It also removes temporaries left by crashed
// runs once they are a day old. The current pins' executables and runtimes
// are kept. A run marks what it uses before starting opengrep, at most once
// a day per process. PruneCache never runs by itself, and it touches
// nothing outside CacheDir, opengrep's default runtime directory included.
func (e *Engine) PruneCache(opts *PruneOptions) error

// ================================================================= selection

// A Selection picks rules as the gogrep command's --suite, --rule and
// --gogrep-* flags do: the union of what Suites and Rules select, narrowed
// by every Filter. With no Suites and no Rules, Scan, Rules and Command
// start from DefaultSuite, and Test from every rule; the zero Selection is
// therefore each method's default.
type Selection struct {
	// Suites are suite names or suite files. A name is looked up as
	// <dir>/opengrep/gogrep/suites/<name>.yaml or .yml, unless project
	// rules are off, which shadows a built-in suite of that name; then
	// among the built-in suites. An entry that contains a slash or
	// backslash, or ends in .yaml or .yml, is a suite file: absolute, or
	// relative to the project directory. A suite's import: entries resolve
	// the same way.
	Suites []string

	// Rules are rule ids: a qualified id such as
	// "opengrep-rules.go.lang.security.audit.dangerous-exec-command", the
	// part of one after a dot ("dangerous-exec-command"), or a /regular
	// expression/ matched against qualified ids.
	Rules []string

	// Filters narrow the union: a rule is kept only if every Filter keeps
	// it. The gogrep command adds one Filter per --gogrep-* flag, so a
	// flag's comma-separated values are alternatives and repeated flags all
	// apply.
	Filters []Filter
}

// A Filter keeps the rules whose field Field has a value that matches one of
// Values, ignoring case; a value written /like this/ is a regular
// expression. A field with several values, such as languages or cwe,
// matches if any of them does. A Filter with no Values keeps no rule. The
// fields are those of Rule.Fields: id, ruleset, path, severity, message,
// languages, and every scalar metadata field such as category or
// confidence, also as metadata.<name>.
type Filter struct {
	Field  string
	Values []string
}

// Validate reports the first malformed entry of s, such as an invalid
// regular expression or a Filter without a Field, as a *SelectionError. It
// loads no rules, so it checks neither that suites exist nor that rules
// match; the methods that take a Selection do.
func (s Selection) Validate() error

// ================================================================== listings

// A Rule is one rule an Engine can run. It is the caller's copy.
type Rule struct {
	ID     string              // stable qualified id <set>.<dir>.<id>
	Set    string              // "opengrep-rules", "0xdea", "semgrep-go", "gogrep" or "project"
	Path   string              // the rule file, a slash path within its set
	Fields map[string][]string // the values Filters and suites match on (see Filter)
}

// RulesOptions configure Engine.Rules; nil means the zero RulesOptions.
type RulesOptions struct {
	Selection
	NoProjectRules bool // as in ScanOptions
}

// Rules returns the rules opts selects, sorted by ID: the rules that a Scan
// of dir with the same options runs. dir is the absolute project directory
// whose opengrep/gogrep rules and suites take part, or "" for none (a
// relative suite file is then an error). Rules runs no opengrep.
func (e *Engine) Rules(dir string, opts *RulesOptions) ([]Rule, error)

// A Suite is one suite that Selection.Suites can name.
type Suite struct {
	Name        string
	Source      string // "built-in", or "project" for one in ProjectSuitesDir, which shadows a built-in suite of that name
	Description string
	Default     bool  // Name is DefaultSuite
	Rules       int   // how many rules it selects; -1 when Err is set
	Err         error // why it cannot select rules, such as an unknown rule set
}

// SuitesOptions configure Engine.Suites; nil means the zero SuitesOptions.
type SuitesOptions struct {
	NoProjectRules bool // list only built-in suites, and count without project rules
}

// Suites returns the built-in suites and those of the project in dir ("" for
// none), sorted by name. A suite file that cannot be read or parsed is an
// error; one that parses but cannot select rules has Err set.
func (e *Engine) Suites(dir string, opts *SuitesOptions) ([]Suite, error)

// ================================================================== scanning

// ScanOptions configure Engine.Scan; nil means the zero ScanOptions, which
// scans the whole directory with DefaultSuite, project rules included.
type ScanOptions struct {
	// Selection picks the rules; its zero value selects DefaultSuite.
	Selection

	// NoProjectRules ignores what the directory keeps under opengrep/gogrep:
	// its rules do not load (the "project" set is empty), its suites
	// neither resolve nor shadow built-in ones, and its rule test fixtures
	// are scanned like any other file. Set it for repositories you do not
	// trust; see "Untrusted repositories" in the package documentation.
	NoProjectRules bool

	// Targets are the files and directories to scan, relative to the
	// directory and inside it (filepath.IsLocal). They are passed after
	// "--". Empty means ".".
	Targets []string

	// Jobs is opengrep's -j, the number of files it analyses at once. Zero
	// keeps opengrep's default of one per CPU; lower it when several scans
	// run at once.
	Jobs int

	// RuleTimeout limits each rule on each file (--timeout, rounded up to
	// whole seconds); a negative value means no limit (--timeout 0).
	// MaxMemoryMB limits the memory for analysing one file (--max-memory,
	// MiB). MaxTargetBytes skips larger files (--max-target-bytes). Zero
	// keeps opengrep's default for each; a negative Jobs, MaxMemoryMB or
	// MaxTargetBytes is an error.
	RuleTimeout    time.Duration
	MaxMemoryMB    int
	MaxTargetBytes int64

	// Stderr, if not nil, receives a live copy of opengrep's stderr, written
	// from another goroutine. Result.Stderr and the errors keep its last 64
	// KiB either way.
	Stderr io.Writer
}

// Scan runs the rules opts selects on dir, an absolute directory, and returns
// what opengrep found. opengrep runs in dir on "." (or opts.Targets), so
// .semgrepignore, git's file list and result paths behave exactly as
// `gogrep scan .` run there. Its stdin is the null device, it gets --sarif
// and --disable-version-check, and its environment is described under
// Config.Env. Scan writes nothing into dir.
//
// Findings are data, not errors: Scan returns a nil error whenever opengrep
// exits 0 with a valid SARIF log, whatever it found. Otherwise it returns a
// nil *Result and one of: a *SelectionError or ErrNoRules for a bad
// selection; an error wrapping ErrNoOpengrep, or an *IntegrityError, when no
// usable opengrep is found; an *ExitError when opengrep exits non-zero; an
// *OutputError, which is ErrNoSARIF, when it exits 0 without a valid log; or
// an error wrapping ctx.Err().
func (e *Engine) Scan(ctx context.Context, dir string, opts *ScanOptions) (*Result, error)

// A Result is what one scan found.
type Result struct {
	// SARIF is opengrep's SARIF 2.1.0 log with runs[].tool.driver.name set
	// to "gogrep", encoded as `gogrep scan --sarif` prints it (sorted keys;
	// <, > and & escaped) and otherwise unchanged. Its result URIs are
	// relative to the scanned directory, and driver.rules lists the whole
	// selection.
	SARIF []byte

	// Findings are the log's results, suppressed ones included, sorted by
	// Path, StartLine, StartColumn, EndLine, EndColumn, RuleID and
	// Fingerprint.
	Findings []Finding

	// Diagnostics are the problems opengrep reported about its run and
	// survived (SARIF's toolExecutionNotifications), such as a file it could
	// not parse or a rule that timed out on a file.
	Diagnostics []Diagnostic

	Complete bool   // the log's invocations[0].executionSuccessful
	Rules    int    // the number of rules selected
	Stderr   []byte // the last 64 KiB of opengrep's stderr
}

// A Finding is one match of a rule.
type Finding struct {
	RuleID string // stable qualified id <set>.<dir>.<id>

	// Level is "error", "warning" or "note": the result's level, else its
	// rule's defaultConfiguration.level in the log, else SARIF's default
	// "warning". (opengrep 1.30.2 sets no level on results.)
	Level string

	Message string // the rule's message, metavariables filled in

	// Path is the file, a slash path relative to the scanned directory: the
	// result's URI exactly as opengrep wrote it, with a leading "./"
	// removed and, on Windows, backslashes turned into slashes. It is never
	// percent-decoded: opengrep writes "b c%41.go" raw.
	Path string

	// The match's region: 1-based lines and byte columns, as opengrep
	// reports them; EndColumn is exclusive. A result without a location
	// has an empty Path and a zero region.
	StartLine, StartColumn, EndLine, EndColumn int

	Snippet     string // the source lines of the match, as opengrep includes them
	Fingerprint string // fingerprints["matchBasedId/v1"]

	// Suppressed reports that a nosemgrep comment in the code suppresses
	// the match (SARIF suppressions of kind inSource). opengrep keeps such
	// results in its log; whether they count is the caller's choice.
	Suppressed bool
}

// A Diagnostic is something opengrep reported about its run rather than
// about the code.
type Diagnostic struct {
	Level   string // "error", "warning", "note" or "none"; SARIF's default is "warning"
	ID      string // the notification descriptor's id, such as "SemgrepError"
	Message string
}

// ================================================================== commands

// CommandOptions configure Engine.Command; nil means the zero
// CommandOptions, which run args verbatim in a process group of their own.
//
// Experimental: Command exists for the gogrep command's pass-through of
// every opengrep flag. It may change in any minor release; use Scan.
type CommandOptions struct {
	// Selection, if not nil, gives a "scan" command gogrep's rules: right
	// after "scan", Command inserts
	//
	//	--config <selection file> --no-rewrite-rule-ids --disable-version-check --exclude=opengrep/gogrep/rules/test
	//
	// (the --exclude only without NoProjectRules). The zero Selection
	// selects DefaultSuite. It is an error when args[0] is not "scan". With
	// a nil Selection, args go to opengrep verbatim; gogrep consults none of
	// opengrep's flags or environment variables, such as SEMGREP_RULES, to
	// decide.
	Selection *Selection

	// NoProjectRules is as in ScanOptions.
	NoProjectRules bool

	// Foreground keeps opengrep in the caller's process group, so a
	// terminal's Ctrl-C reaches it directly, and makes a done ctx kill only
	// the process Run started. Otherwise opengrep leads a process group of
	// its own (on Windows, its process tree), which a done ctx kills whole;
	// such a group is stopped if it reads the terminal, so do not give it a
	// terminal as Stdin.
	Foreground bool
}

// A Cmd is an opengrep command that Command prepared. Its fields may be
// changed before Run, as with exec.Cmd. A Cmd cannot be reused, and is not
// safe for concurrent use.
type Cmd struct {
	Path string   // the opengrep executable, absolute
	Args []string // the command line, starting with Path, gogrep's own arguments included
	Dir  string   // the directory opengrep runs in
	Env  []string // opengrep's environment

	// Stdin, Stdout and Stderr are opengrep's standard streams, as in
	// exec.Cmd; nil means the null device.
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	// contains unexported fields
}

// Command prepares opengrep to run with args (without the executable) in
// dir, an absolute directory. It finds and prepares opengrep as Opengrep
// does and, with a Selection, writes the selection's rule file, so it fails
// as they do. ctx bounds the run.
func (e *Engine) Command(ctx context.Context, dir string, opts *CommandOptions, args ...string) (*Cmd, error)

// Run starts the command and waits for it. It returns nil when opengrep
// exits 0; an *ExitError, with nil Stderr and Result, when it exits
// non-zero; an error wrapping ErrNoOpengrep when it cannot start; and an
// error wrapping ctx.Err() when ctx ended it. Run reads nothing opengrep
// writes: interpreting its output, SARIF included, is up to the caller.
func (c *Cmd) Run() error

// ================================================================ rule tests

// A Stage is where a rule test failed.
type Stage string

const (
	StageSetup  Stage = "SETUP"  // the fixture is malformed
	StageRule   Stage = "RULE"   // rule.ref names no rule, or opengrep rejects the rule
	StageRun    Stage = "RUN"    // opengrep failed, or its output cannot be trusted
	StageResult Stage = "RESULT" // expected.txt is missing or differs
)

// TestOptions configure Engine.Test; nil means the zero TestOptions, which
// run every fixture and write results into the fixtures, as `gogrep test`
// does.
type TestOptions struct {
	// Selection keeps only fixtures whose rule it selects. Unlike Scan, the
	// zero Selection selects every rule (no default suite), and Filters
	// alone narrow every rule. Fixtures that fail at SETUP or RULE always
	// run, so a typo cannot hide a test.
	Selection

	// Paths select fixtures: those below each path and the one containing
	// it. A relative path is relative to the project directory; every path
	// must lie inside its ProjectTestsDir and select a test. Empty means
	// every fixture.
	Paths []string

	// Jobs is how many opengrep processes run at once, each with -j 1: 0
	// means one per CPU, -N one per CPU less N, and always at least 1.
	Jobs int

	Learn     bool // a test that fails at RESULT writes its results as expected.txt and counts as learned
	KeepSARIF bool // keep each fixture's raw opengrep output as actual.sarif

	// ReadOnly writes and removes nothing in the fixtures: no actual.txt,
	// expected.txt or actual.sarif. Learn and KeepSARIF must be false. Use
	// it for the fixtures of a clone you do not want changed.
	ReadOnly bool

	// Progress, if not nil, is called on Test's goroutine: once with done 0
	// and a nil r when the tests are planned and opengrep is found, then
	// once per test, in fixture order, as soon as it and every test before
	// it are done.
	Progress func(done, total int, r *TestResult)
}

// A TestResult is how one fixture's test went.
type TestResult struct {
	Name            string   // the fixture, a slash path relative to the project directory
	Dir             string   // the fixture directory, absolute
	RuleID          string   // the qualified id rule.ref resolved to; "" at SETUP, or at RULE when it names no rule
	Stage           Stage    // where the test failed; "" when it passed or was learned
	Learned         bool     // the results became expected.txt (Learn)
	MissingExpected bool     // the fixture has no expected.txt
	Diff            string   // unified diff from expected.txt to the results; "" when they are equal
	Details         []string // why the test failed, if not for its results
	Command         []string // the opengrep command line, executable first, run in Dir; nil when opengrep did not run
	Stderr          []byte   // opengrep's stderr
	FileErrors      []error  // fixture files that could not be written or removed
}

// A TestReport is the outcome of Engine.Test.
type TestReport struct {
	Results []*TestResult // the reported tests, in order: all of them unless ctx ended the run
	Passed  int           // learned tests included
	Learned int
	Failed  []string // names of the tests that failed, sorted

	// Untested are the ids of project rules that no fixture's rule.ref
	// names, sorted. It is set only for a complete run of every fixture
	// with the zero Selection.
	Untested []string
}

// Test runs the rule test fixtures under ProjectTestsDir of dir, an absolute
// project directory, each in its own opengrep process, as `gogrep test`
// does. It always loads the project's rules, which the fixtures exist to
// test. Unless opts.ReadOnly is set, it writes actual.txt, expected.txt
// (Learn) and actual.sarif (KeepSARIF) into fixtures, 0o600 via a temporary
// file and rename, and removes stale ones. So do not run two Tests, or a
// Test and AcceptTests, on one directory at once, unless every Test is
// ReadOnly. A failing test is a result, not an error.
//
// Test returns an error wrapping ErrNoTestRoot when dir has no
// ProjectTestsDir; an error for a path that does not exist, lies outside it
// or selects no test; a *SelectionError or ErrNoRules; an error when no test
// matches the selection; and an error wrapping ErrNoOpengrep when a test
// needs opengrep and none is found (tests that fail at SETUP or RULE need
// none). When ctx is done, Test starts no more opengrep processes, kills the
// running ones, writes no files for their tests, and returns the tests
// reported so far with an error wrapping ctx.Err().
func (e *Engine) Test(ctx context.Context, dir string, opts *TestOptions) (*TestReport, error)

// An Acceptance is one fixture whose actual.txt AcceptTests tried to make its
// expected.txt.
type Acceptance struct {
	Name string // the fixture, a slash path relative to the project directory
	Err  error  // why actual.txt could not become expected.txt; nil when it did
}

// AcceptTests renames the actual.txt of each fixture that paths select
// (every fixture when paths is empty) to expected.txt, mode 0o600. paths are
// as in TestOptions. Fixtures without actual.txt, and fixtures that fail at
// SETUP, are skipped. It returns one Acceptance per fixture it tried, in
// order; its error is set only when the fixtures cannot be discovered.
func (e *Engine) AcceptTests(dir string, paths []string) ([]Acceptance, error)

// ==================================================================== errors

var (
	// ErrNoOpengrep is wrapped by every error that leaves an Engine without
	// an opengrep to run: none was found, the one configured is not a
	// regular file, it could not be extracted, or it could not be started.
	// InstallOpengrep fixes the first case. For Config.Opengrep the error's
	// text is exec.LookPath's or os.Stat's, unchanged ("exec: …").
	ErrNoOpengrep = errors.New("no usable opengrep")

	// ErrNoRules reports a selection that picks no rules. A
	// *SelectionError wraps it for a Rules entry that matches no rule.
	ErrNoRules = errors.New("the selection matches no rules")

	// ErrUnknownSuite is wrapped by the *SelectionError for a suite name
	// that is neither a project suite nor a built-in one, also when a suite
	// imports it.
	ErrUnknownSuite = errors.New("unknown suite")

	// ErrNoSARIF is what every *OutputError is: opengrep exited 0 without
	// the valid SARIF 2.1.0 log of one run asked of it, as when its
	// processes are killed behind its launcher's back.
	ErrNoSARIF = errors.New("opengrep exited 0 but wrote no SARIF")

	// ErrNoTestRoot is wrapped by Test and AcceptTests when the project has
	// no ProjectTestsDir.
	ErrNoTestRoot = errors.New("no rule test directory")
)

// An ExitError reports that opengrep exited with a non-zero code. gogrep
// never passes --error, so findings alone never cause one. opengrep's codes
// include 2 (fatal error), 4 (invalid pattern), 5 (invalid YAML), 7 (invalid
// rule or missing config) and 8 (unknown language).
type ExitError struct {
	Code   int     // -1 when a signal ended opengrep
	Stderr []byte  // the last 64 KiB of opengrep's stderr; nil from Cmd.Run
	Result *Result // what opengrep wrote, when it is a valid SARIF log; nil from Cmd.Run
}

func (e *ExitError) Error() string // "opengrep exited with code 7" and, if any, ": " and Stderr's last non-empty line
func (e *ExitError) ExitCode() int // e.Code

// An OutputError reports that opengrep exited 0 without a usable SARIF log.
type OutputError struct {
	Err    error  // why the output is not a SARIF 2.1.0 log of one run
	Stderr []byte // the last 64 KiB of opengrep's stderr
}

func (e *OutputError) Error() string        // ErrNoSARIF's text, ": " and Err's
func (e *OutputError) Unwrap() error        // e.Err
func (e *OutputError) Is(target error) bool // target == ErrNoSARIF

// A SelectionError reports a Selection entry that is malformed, names an
// unknown suite, cannot be read, or matches no rule.
type SelectionError struct {
	Kind  string // "suite", "rule" or "filter"
	Value string // the suite name or file, the rule entry, or the filter's Field, as given
	Err   error  // ErrUnknownSuite, ErrNoRules, a regexp error, or a suite file's read or parse error
}

func (e *SelectionError) Error() string // `unknown suite "web"`, `rule use-of-md6 matches no rule`, `rule /(/: error parsing regexp: …`, `filter languages: …`, or a suite file's error
func (e *SelectionError) Unwrap() error // e.Err

// An IntegrityError reports an opengrep executable whose SHA-256 is not the
// pinned one where gogrep requires it to be: Config.EmbeddedOpengrep, a
// downloaded asset, or InstallOptions.From. A cached executable that fails
// verification is treated as absent, never run, and replaced by the next
// InstallOpengrep.
type IntegrityError struct {
	Path string // the file or URL concerned; "embedded" for Config.EmbeddedOpengrep
	Want string // the pinned SHA-256, hex
	Got  string // the SHA-256 of the bytes, hex
}

func (e *IntegrityError) Error() string // "<path>: SHA-256 <got>, want the pinned <want>"
```

**Conventions behind the surface:**

- **Options.** Every options struct's zero value is the default, and a nil options pointer means the zero value, so fields can be added compatibly. Contexts are never inside option structs.
- **Boolean fields name the non-default behaviour:** `NoProjectRules`, `ReadOnly`, `Foreground`, `AllowUnpinned`.
- **Return types are concrete.** There are no exported interfaces and no third-party types.
- **No positional parameter will ever be added.** This avoids gosec's breaking changes to `NewAnalyzer`.
- **`Rules` and `Suites` take no context:** they never run opengrep, and their file work is bounded.
- **No mutable package-level state is exported.**

### 3.3 Concurrency guarantees

These go into the package documentation.

- **One Engine, many goroutines.** An `Engine` is safe for concurrent use, and every method may run on any number of goroutines at once. Create one per process and share it.
- **Shared parsed rules.**
  - The built-in rule sets are parsed once per process (`sync.OnceValues`, about 0.13 s for 2,121 rules) and shared read-only.
  - `rules.Write`, `suite.Select` and `suite.Narrow` never mutate parsed rules (`rules.Write` makes shallow copies, `rules.go:219-226`).
  - The `project` set is parsed per call, in a set of its own, so id-clash resolution stays per set (`rules.go:98`), and each call sees the directory's rules as they are at that moment.
- **What each call writes.**
  - `Scan`, `Rules`, `Suites` and `Command` never write into `dir`. Scans of the same directory may run concurrently.
  - `Test` (without `ReadOnly`) and `AcceptTests` write fixture files. Two of them on one directory are as unsafe as two `gogrep test` processes are today.
- **Callbacks and writers.**
  - `Progress` runs on the goroutine that called `Test`.
  - `ScanOptions.Stderr` is written from an internal goroutine, so a writer shared between concurrent scans must be safe for concurrent use.
  - `Logger`'s handler may be called concurrently, as `slog` requires anyway.
- **Process-wide internal state.** There are three tables, guarded by a mutex and keyed by everything they depend on. They only avoid repeated work and never change a result:
  - the parsed built-in rule sets;
  - verified checksums, keyed by path, size and modification time;
  - prepared runtimes, keyed by executable hash and `CacheDir`.
- **Sharing a cache.** Several Engines and several processes may share one `CacheDir` (§4.7).
- **No concurrency limit inside the engine.**
  - Each scan peaks at about 250–360 MB resident for the whole opengrep process tree (measured: 254 MB with `-j 4`, 356 MB with `-j 8`).
  - Callers that scan N directories bound N themselves and set `Jobs` so that N × Jobs is about the CPU count (§6).
  - `Test` defaults to one process per CPU, as `gogrep test` does.

### 3.4 Context and cancellation

- **Every opengrep process runs under `exec.CommandContext`.**
  - **Unix:** `Setpgid`, and `Cancel` sends SIGKILL to the whole group. opengrep's launcher does not pass a kill on to `opengrep-cli` and `opengrep-core` (`procgroup_unix.go`).
  - **Windows:** `taskkill /T /F /PID`, falling back to `Process.Kill`.
  - **`Foreground`:** the process stays in the caller's group, and only it is killed.
  - `WaitDelay` is 1 s, so a grandchild that holds a pipe open cannot block the return.
  - Exit codes after cancellation are ignored, because a killed Windows process exits 1.
- **What each method returns when ctx is done:**
  - `Scan` and `Cmd.Run` return an error for which `errors.Is(err, context.Canceled)` (or `DeadlineExceeded`) holds, and no `Result`.
  - `Test` returns the tests reported so far plus that error, and writes no files for unfinished tests.
- **Waits honour ctx too.** Lock waits poll every 100 ms, and downloads and runtime preparation stop with ctx. A cancelled unpack removes its private directory and publishes nothing.
- **Signals belong to the caller.** The library never imports `os/signal`. Because opengrep runs in its own process group, a terminal's Ctrl-C reaches only the host program, which cancels the context. The CLI (`signal.NotifyContext`) and §6 show the pattern.
- **A timeout is a ctx deadline.** No internal queue exists, so a deadline bounds exactly the opengrep run plus preparation.
- **Limit.** If the host dies without cancelling (SIGKILL, or an uncaught signal), running opengrep groups finish their scan, as they do under `gogrep test` today. This is documented.

### 3.5 What each call runs and returns

| | `Scan` | `Test` | `Command` |
|---|---|---|---|
| opengrep's working directory | `dir` | each fixture directory (absolute) | `dir` |
| Arguments gogrep adds | `scan --config <selection> --no-rewrite-rule-ids --disable-version-check [--exclude=opengrep/gogrep/rules/test] --sarif [-j N] [--timeout S] [--max-memory M] [--max-target-bytes B] -- <targets>` | `scan --config <rule> --no-rewrite-rule-ids --sarif --disable-version-check --timeout 0 -j 1 -- ./<samples>` (unchanged) | with a `Selection`: `--config <selection> --no-rewrite-rule-ids --disable-version-check [--exclude=…]` right after `scan`; nothing otherwise |
| Environment | `Env`, minus `SEMGREP_*` and `OPENGREP_*`; plus the locale fix, `SEMGREP_LOG_FILE` (a file of its own per opengrep process, removed afterwards) and `XDG_CACHE_HOME` (Linux and macOS) | same as `Scan` | `Env` plus the locale fix and `XDG_CACHE_HOME` |
| stdin | null device | null device | `Cmd.Stdin` |
| Process group | own, killed as a tree | own, killed as a tree | own, or the caller's with `Foreground` |
| What gogrep reads | stdout (SARIF, in memory) and a 64 KiB stderr tail | stdout and stderr | nothing |
| Returns | `*Result` | `*TestReport` | the caller's streams and files |

**SARIF is the only opengrep output the library reads.** `internal/sarif` decodes this subset:

- `version` must be `2.1.0`, and there must be exactly one run. Otherwise the result is an `*OutputError`.
- `runs[0].tool.driver.rules[].{id, defaultConfiguration.level}`.
- `results[]`:
  - `{ruleId, level, message.text, fingerprints, suppressions}`;
  - `locations[0].physicalLocation.artifactLocation.uri`;
  - `locations[0].physicalLocation.region.{startLine, startColumn, endLine, endColumn, snippet.text}`.
- `invocations[0].{executionSuccessful, toolExecutionNotifications[].{level, descriptor.id, message.text}}`.

Verified against opengrep 1.30.2:

- Results carry no `level`.
- `driver.rules[].defaultConfiguration.level` is set: `error` for severities ERROR, CRITICAL and HIGH, `warning` for WARNING and MEDIUM, `note` for INFO and LOW. Rules of severity INVENTORY and EXPERIMENT are left out of `driver.rules` and report nothing.
- `invocations[0].executionSuccessful` is `true` even when opengrep exits 2, 7 or 8 after error notifications (every recording in `internal/ruletest/testdata/sarif`), so `Complete` says little beyond the exit code.
- A `// nosemgrep` match stays in the log with `suppressions: [{kind: inSource}]`.
- `snippet.text` holds the matched source line.
- URIs are written raw. The repository already pins this down: `internal/ruletest/table_test.go` has the case "uris made relative and clean, never decoded", and rule-test-fixtures.md §4.3 says "Never percent-decode".

**No `owenrumney/go-sarif`.** It would break the dependency rule (testify, gojsonschema, uuid), and it would tie gogrep's API to another project's major version; trivy pins v2 and osv-scanner v3. Callers who want a full object model can load `Result.SARIF` with any library.

### 3.6 Project rules and suites; untrusted repositories

**Default: on, matching the CLI and the issue.** A directory's `opengrep/gogrep/rules` form the `project` rule set (skipping `test/` in any letter case), and every built-in suite includes it (`rules: [gogrep, project]`). Its `opengrep/gogrep/suites/*.y{a,}ml` add suites, and a project suite replaces a built-in suite of the same name.

**`NoProjectRules`** is available on `ScanOptions`, `RulesOptions`, `SuitesOptions` and `CommandOptions`, per call, so one Engine scans repositories of both trust levels without re-parsing the built-in sets. Under it:

- the `project` set exists but is empty, so the built-in suites that name it still work;
- project suites neither resolve nor shadow, including through `import:`;
- the injected `--exclude=opengrep/gogrep/rules/test` is dropped, so a repository cannot hide code in its fixture directory;
- caller-supplied suite files still resolve relative to `dir`, because the caller chose them.

`Test` always loads project rules, since testing them is its purpose. Its documentation recommends `ReadOnly` for clones.

The package documentation's section "Untrusted repositories" is this table:

| What the repository controls | Effect | Control |
|---|---|---|
| `opengrep/gogrep/rules/` | Adds rules that run. opengrep rules are patterns and cannot run code, but they can add noise or cost CPU (`pattern-regex`). | `NoProjectRules`; `RuleTimeout`, `MaxMemoryMB` and a ctx deadline bound the cost |
| A project rule file that is a symlink | Project files are read with `os.DirFS`, which follows a symlinked file (`fs.WalkDir` never enters a symlinked directory: `TestFromFSSkipsSymlinkedDir`). A repository can therefore make gogrep read a file outside it as rule YAML, and that file's content may appear in parse errors. The CLI relies on this so that projects can share rules. | `NoProjectRules` |
| `opengrep/gogrep/suites/` | A project `code-scanning.yaml` replaces the default suite and can select nothing | `NoProjectRules` |
| `opengrep/gogrep/rules/test/` | Excluded from scans by the injected `--exclude` | Under `NoProjectRules` it is scanned like any other directory |
| `nosemgrep` comments | Mark matches as suppressed | They stay in `Findings` with `Suppressed: true`; the caller decides |
| `.semgrepignore`, `.gitignore` | Hide files from the scan; opengrep reads `.semgrepignore` from its working directory, which is `dir` | Not overridable in v0.4. opengrep's only switch, `--x-ignore-semgrepignore-files`, is internal and also drops its default ignores (verified). Consumers can report the file's presence. |
| `.git/config` | opengrep runs `git ls-files` and `git ls-remote --get-url` in `dir` (seen in its log), and git honours the repository's configuration | Scan only directories whose `.git` your own `git clone` created; a clone never copies the remote's configuration |
| Symlinks in the scanned tree | opengrep does not follow file or directory symlinks while walking, in git and non-git directories (verified) | Built in |
| Large or many files | Memory and time | `MaxTargetBytes`, `RuleTimeout`, `MaxMemoryMB`, ctx |

### 3.7 Errors and the CLI's exit codes

**Library errors are written for library callers.**

- They carry no `gogrep:` prefix and no flag names.
- Paths appear as the caller gave them. A suite file's `*fs.PathError` has its `Path` set back to the name given, so the message reads `open x.yaml: no such file or directory` as it does today.

**The CLI rebuilds today's exact messages** with `errors.Is` and `errors.As`:

- A `*SelectionError` of `Kind` `"rule"`:
  - wrapping `ErrNoRules`: `--rule X matches no rule; list them with: gogrep rules --suite all`;
  - otherwise: `--rule X: <err>`.
- A `*SelectionError` of `Kind` `"filter"` is checked at flag parsing with `Selection{Filters: …}.Validate()`. It becomes `--gogrep-lang: <err>` (likewise for `--gogrep-category` and `--gogrep-ruleset`).
- `errors.Is(err, ErrUnknownSuite)`: append `; list them with: gogrep suites`. Wrapping only ever adds prefixes, so imports keep today's text: `suite a: unknown suite "b"; list them with: gogrep suites`.
- A bare `ErrNoRules` becomes `the --suite/--rule/--gogrep-* selection matches no rules`.
- `ErrNoTestRoot` becomes `no opengrep/gogrep/rules/test directory here; run gogrep test from the project root`.

| Condition | Library | `scan` and forwarded commands | `opengrep` | `rules`, `suites` | `test` | `test accept` | `install-opengrep` |
|---|---|---|---|---|---|---|---|
| Bad flag or usage | (CLI) | 2 | — | 2 | 2 | 2 | 2 |
| `*SelectionError`, `ErrNoRules`, unreadable project rules or suites, setup errors (writing the selection) | error | 2 | — | 2 | 2 | 2 | — |
| `ErrNoTestRoot`, a path that selects nothing, no test matches | error | — | — | — | 2 | 2 | — |
| `ErrNoOpengrep`, `*IntegrityError` | error | **1** | **1** | — | **2** | — | 1 |
| `*ExitError` | error | opengrep's code (it has already written its stderr) | opengrep's code | — | that test fails at RUN or RULE | — | — |
| `ErrNoSARIF` (CLI check for forwarded commands; `*OutputError` from `Scan`) | error | **2** (new) | — | — | that test fails at RUN | — | — |
| Download or verification failure | error | — | — | — | — | — | 1 |
| ctx cancelled by a signal | wraps `ctx.Err()` | **130**, `gogrep: interrupted` (new) | verbatim (foreground) | — | 130, `gogrep: interrupted` | — | 130 |
| A test failed | `TestReport.Failed` | — | — | — | 1 | — | — |
| A fixture file could not be written or removed | `TestResult.FileErrors` | — | — | — | 2 | — | — |
| `Acceptance.Err` | per fixture | — | — | — | — | 2 | — |

## 4. Obtaining opengrep and the rule sets

### 4.1 Rule sets: in the module, always

| Archive | Size | Contents | License |
|---|---|---|---|
| `opengrep-rules.tar.gz` | 428,511 B | 1,934 tar entries: 1,933 rule files plus `LICENSE` | LGPL-2.1 with the Commons Clause |
| `0xdea.tar.gz` | 22,564 B | rule files plus `LICENSE` | MIT |
| `semgrep-go.tar.gz` | 6,787 B | rule files plus `LICENSE` | MIT |

- **Where they live.**
  - They are committed to `internal/rulesets/` with their `.commit` stamps and embedded with no build tag. Together they hold 2,121 rules.
  - `.gitattributes` marks them `binary`.
  - `tools/fetch-opengrep` writes them there with its existing deterministic packing: only rule YAML plus licence files, with the commit checked by `git rev-parse`.
  - The committed archives were packed afresh by that tool (tar entries 0o600). The archives in `internal/bundle/bin/rules` of older checkouts, packed before the tool switched to 0o600, differ only in that mode: the same entries, in the same order, with the same SHA-256 each (checked).
  - Each re-pin adds about 458 KB to the history.
  - Every file name is valid in a module, and none collide under case folding (checked).
- **Why archives, not a YAML tree.** A plain YAML tree would mean 2,000+ files cluttering search and language statistics, and gogrep would scan its own copies.
- **gogrep's own set and the built-in suites.** The `gogrep` set (`rules/`) and the built-in suites are embedded by the root package (§2.3). The `project` set comes from `dir` (§3.6).
- **Integrity.** The archives are module content, so `go.sum` and the checksum database vouch for them.
- **CI keeps them faithful to `opengrep.json`.**
  - On every push, each stamp must match its pin.
  - When `opengrep.json` or `tools/` change, and weekly, `go run ./tools/fetch-opengrep -check-rules` re-fetches into a temporary directory and compares the decompressed listing (names plus SHA-256 of each entry).
  - It never compares `.tar.gz` bytes, because `compress/flate` promises no byte stability across Go releases.
- **Licensing.**
  - `NOTICE.md` changes from "Release builds … also contain" to "The gogrep module and every build contain the rule sets below; release builds also contain the opengrep binary."
  - `doc.go` and the README name the Commons Clause on opengrep-rules: it grants no right to sell a product or service whose value derives entirely or substantially from those rules.

### 4.2 Finding the executable, in order

No step uses the network.

| # | Source | Accepted when | `Source` | The CLI |
|---|---|---|---|---|
| 1 | `Config.Opengrep` | Always, as given; it must resolve to a regular file. A bare name is looked up in the process's `PATH`. | `config` | `$OPENGREP_BIN`, made absolute when it contains a separator |
| 2 | `Config.EmbeddedOpengrep` | Its SHA-256 is the pin for the running GOOS/GOARCH (either Linux variant), else `*IntegrityError`. It is written to `<CacheDir>/opengrep-<sha16>/opengrep[.exe]` (0o700, temporary file then rename) when that file is missing or fails verification. | `embedded` | `bundle.Binary()` in `gogrep_bundled` builds |
| 3 | `<CacheDir>/opengrep-<sha16>/opengrep[.exe]` for this platform's pin (on Linux the detected variant first, then the other) | Its SHA-256 is the pin. A mismatching file is treated as absent and never run. | `cache` | same |
| 4 | `exec.LookPath("opengrep")` | Its SHA-256 is the pin, or `AllowUnpinned` is set | `path` | `AllowUnpinned: true` |
| 5 | none | An error wrapping `ErrNoOpengrep` | — | exit 1 (`scan`, forwarded, `opengrep`) or 2 (`test`) |

- **Checksums.** Each is computed once per process for each path, size and modification time, which takes about 50 ms for 47 MB.
- **Shared layout.** Steps 2 and 3 use today's `bundle.Path` layout under the default `CacheDir`, so a release gogrep and a library consumer share one copy.
  - Running any bundled gogrep once (for example `gogrep opengrep --version`) fills the library's cache with no download code involved.
  - Unlike today, an existing file is reused only after a hash check, not a size check.
- **No environment variables.** The library reads none for this. The `PATH` lookup uses the process's `PATH`, as `exec.LookPath` does; git, started by opengrep, uses `Env`'s.
- **The not-found error** names the version, platform, asset, checksum prefix, cache path and remedies. For example:

  > no usable opengrep: v1.30.2 for darwin/arm64 (asset opengrep_osx_arm64, sha256 f1aaa30b88959cb8…) is not in /Users/u/Library/Caches/gogrep/opengrep-f1aaa30b88959cb8, and no opengrep on PATH has that SHA-256; install it with Engine.InstallOpengrep or `gogrep install-opengrep`, or set Config.Opengrep

  `gogrep install-opengrep` is a valid remedy for library callers too, because it fills the same default cache.
- **Explicit paths keep their `os/exec` text.** `exec: "/x/opengrep": stat …` still satisfies the CLI's `gogrep: exec: ` tests (`TestTestOpengrepBin`, `TestRunScan`).
- **Platforms without a pin** (freebsd, linux/386, windows/arm64) work through `Config.Opengrep` or `AllowUnpinned`.

### 4.3 Offline behaviour

- **Only `InstallOpengrep`, and the CLI's `gogrep install-opengrep`, open network connections.**
- **`Rules`, `Suites`, `AcceptTests`, `Selection.Validate` and `PruneCache` never run opengrep.**
- **`Scan`, `Test` and injected `Command` scans pass `--disable-version-check`.** `Scan` and `Test` also strip `OPENGREP_ENABLE_VERSION_CHECK`. The rule configuration is a local file and the targets are local. opengrep has no metrics flag (checked in `opengrep scan --help`).
- **`Command` without a `Selection` passes the user's arguments through,** so `gogrep scan --config auto` still fetches rules from the internet when a user asks for it. This is unchanged and documented in the README.
- **There is no auto-install option.** A consumer that wants one writes `if errors.Is(err, gogrep.ErrNoOpengrep) { _, err = eng.InstallOpengrep(ctx, nil) }`, as in §3.1.

### 4.4 `InstallOpengrep`: verified download

**Source.**

- `<BaseURL>/<version>/<asset>`, by default `https://github.com/opengrep/opengrep/releases/download/v1.30.2/<asset>`. It answers with a 302 to `release-assets.githubusercontent.com`.
- GitHub's published digests for all 7 assets match `opengrep.json` (verified).
- **Chain of trust:** the Go checksum database vouches for gogrep's module source, and the embedded `opengrep.json` pins each asset's SHA-256. The cosign `.sig` and `.cert` files are therefore not needed.

**Steps.**

1. **Pick the asset.**
   - The asset is `GOOS/GOARCH`, or on Linux the detected or `Platform` variant.
   - musl is chosen only when musl's loader exists (`/lib/ld-musl-x86_64.so.1`, `/lib/ld-musl-aarch64.so.1`) and glibc's does not (`/lib64/ld-linux-x86-64.so.2`, `/lib/ld-linux-aarch64.so.1`).
   - glibc's loader takes precedence because Debian's `musl` package installs the musl loader beside it.
   - Detection reads through an `fs.StatFS`, so it is unit-tested with `fstest.MapFS`.
2. **Return early** if the cache holds a verified copy (no network).
3. **Take a lock and re-check.** The lock is `<CacheDir>/locks/install-<sha16>.lock` (best effort, §4.7).
4. **Stream the bytes.** `From`, or a `GET` made with `http.NewRequestWithContext`, streams through `io.LimitReader` (256 MiB) into `os.CreateTemp(<CacheDir>/opengrep-<sha16>, ".download-*")`, and is hashed on the way. Network errors and 5xx responses are retried up to 3 times, after 1 s, 2 s and 4 s, honouring ctx.
5. **Verify.** On a mismatch the temporary file is removed and an `*IntegrityError` is returned. Otherwise the file is chmodded 0o700 and renamed into place. If the rename fails but a file is now there that verifies, another process won the race, and that counts as success. The temporary file is removed on every path.
6. **Prepare the runtime** (§4.6).

**Shared code.** `tools/fetch-opengrep` reuses steps 4 and 5 (`internal/opengrep.Download`), so a single implementation does the downloading and verification.

**Prototype.** A standard-library prototype of this flow was tested: 6 concurrent cold processes downloaded from a local HTTP server, then scanned. All exited 0 and left no temporary files.

**Air-gapped machines:**

- `InstallOptions.From` or `gogrep install-opengrep --from FILE`, verified like a download;
- `BaseURL`, pointing at a mirror;
- running a bundled gogrep release once;
- copying `<CacheDir>/opengrep-<sha16>/` from another machine;
- `Config.Opengrep`.

### 4.5 Integrity summary

- **Every byte that becomes the cached executable is hashed as it streams:** downloads, `From` files and embedded extraction. The file is renamed into place only on a match.
- **Executables are re-verified once per process** (path, size, modification time). Today `bundle.Path` reuses a file whose size alone matches (`bundle.go:31`).
- **`Config.Opengrep` is the caller's choice.** It is hashed only to report `Pinned` and to key its runtime.
- **The rule archives are module content,** covered by `go.sum`.

### 4.6 First run: preparing opengrep's runtime

**The problem (verified with v1.30.2).**

- opengrep is a Nuitka onefile build. Its first run of any command, even `--version`, unpacks about 245 MB into `{CACHE_DIR}/opengrep/v1.30.2`.
  - On POSIX, `{CACHE_DIR}` is `$XDG_CACHE_HOME`, else `$HOME/.cache`, on macOS too.
  - On Windows it is `CSIDL_LOCAL_APPDATA`, which no environment variable redirects.
- A cold run takes 8.3 s. Every later start CRC-checks every file (0.96–1.05 s warm) and rewrites any mismatching file in place.
- In 3 trials of 4 parallel cold runs, 2 of the 4 exited 138 (SIGBUS) every time. 8 parallel warm runs all succeeded.
- Today only `ruletest.Runner.Run` serialises the first run, and only within one call (`ruletest/run.go:76-99`). This affects the current CLI too: a tool that starts several `gogrep scan` processes on a fresh CI runner crashes about half of them.

**The fix on Linux and macOS: publish a complete runtime atomically.**

1. **Key.** The key is `k = sha256[:16]` of the executable. For a pinned executable it comes from the pin; for any other executable it is computed once per process, so unpinned and explicit executables are covered too. Let `R = <CacheDir>/runtime-<k>`.
2. **Warm case.** If `R` is a directory, the runtime is ready. This costs one `stat`, so warm runs and the CLI get no slower.
3. **Serialise.** Otherwise, take the in-process per-key mutex and re-check, then take the best-effort lock `<CacheDir>/locks/runtime-<k>.lock` and re-check again.
4. **Private directory.** `T = os.MkdirTemp(CacheDir, ".runtime-*")` (0o700), on the same file system as `R`.
5. **Unpack.** Run `<exe> --version` with `XDG_CACHE_HOME=T`, `SEMGREP_LOG_FILE=T/log` and the engine's other environment. It runs in its own process group, under ctx and a 5-minute limit.
6. **Publish.** On exit 0, remove `T/log` and `os.Rename(T, R)`. If the rename fails because `R` now exists, another process published first, so `RemoveAll(T)`.
7. **Point every opengrep child at it.** Every opengrep child of `Scan`, `Test` and `Command` gets `XDG_CACHE_HOME=R`, and finds `R/opengrep/<version>/` already complete.

**Why it works.**

- `R` appears only after the unpacking process exited 0.
- Renaming a directory within one file system is atomic.
- A published runtime is therefore always complete, and no start has to repair it in place.
- This is the private-unpack-and-rename mechanism the research tested. Afterwards the shared runtime started warm (1.0 s) and 8 parallel runs succeeded. With it, all 6 concurrent cold processes of the prototype succeeded.

**Why the lock exists.** Correctness does not depend on it. Without it, N cold processes each unpack, which took 35–44 s per process in parallel instead of 8 s alone.

**On failure.** If `--version` fails, or `CacheDir` cannot be written:

- nothing is published;
- the run proceeds without the redirect, exactly as today;
- `Logger` records why;
- the real run then reports any real error.

A cancelled preparation returns the ctx error.

**Windows.**

- The location cannot be redirected, so a marker `<CacheDir>/runtime-<k>.ready` is used instead.
- If it exists, the runtime is ready (one `stat`).
- Otherwise, under the same mutex and lock, gogrep runs `<exe> --version` alone, which unpacks in place, then creates the marker. Other gogrep processes wait on the lock.
- **Limits, documented:**
  - Windows behaviour is unverified; a CI step checks it (§7.5).
  - A stale marker left after a user deletes `%LOCALAPPDATA%\opengrep` brings back today's behaviour.
  - opengrep processes started by other programs are not covered.

**Not covered on any OS.** If someone damages a published runtime, opengrep's in-place repair can again race. This is documented.

**Consequences.**

- `ruletest`'s per-call first-run gate is removed, and `TestRunFirstAlone` moves to `internal/opengrep`.
- On POSIX, the runtime moves from `~/.cache/opengrep` into gogrep's cache, which is CLI change 9. The old copy is left alone (open question 3).

### 4.7 Cross-process safety

**Correctness never depends on a lock.**

- **Executable, runtime and selections:** hash-keyed paths, written by temporary file (or directory) and rename. The loser of a race checks that the winner's file exists and verifies.
- **`rules.Write`** gains `extract`'s rename fallback. If the rename fails and the target exists, the content is identical by construction. This fixes a likely failure on Windows when renaming over a configuration that a running opengrep holds open; the failure is inferred, not observed.
- **Signed code on macOS** is always replaced with a new file and never overwritten in place, because the kernel caches code signatures per file.

**Locks only avoid duplicate work** (downloads, unpacks). They use the standard library only:

- **darwin, dragonfly, freebsd, linux, netbsd, openbsd:** `syscall.Flock(LOCK_EX|LOCK_NB)`.
- **Windows:** `LockFileEx` through `syscall.NewLazyDLL("kernel32.dll")` with `LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY`.
- **Elsewhere:** no lock.

Locks are polled every 100 ms, so ctx can cancel the wait. The OS releases them when a process dies, so no stale lock can block anyone. Where locking fails (for example on some network file systems), gogrep logs it and continues with in-process serialisation only.

### 4.8 Cache layout and permissions

| Path under `CacheDir` | Mode | Written by | Removed |
|---|---|---|---|
| `.` | 0o700 | everything below | — |
| `opengrep-<sha16>/opengrep[.exe]` | directory and file 0o700 | extraction, `InstallOpengrep` | `PruneCache`, if not a current pin and unused for `MaxAge` |
| `runtime-<sha16>/opengrep/<version>/` (Linux, macOS) | directory 0o700; opengrep's own modes inside | runtime preparation | same rule |
| `runtime-<sha16>.ready` (Windows) | 0o600 | runtime preparation | same rule |
| `selections/<sha16>.yaml` | 0o600 | `rules.Write`, content-addressed (unchanged, so printed `--show-opengrep-output` lines can still be rerun); modification time refreshed on reuse | `PruneCache`, after `MaxAge` unused |
| `logs/opengrep-*.log` | 0o600, created before opengrep opens it | `Scan`, `Test`, runtime preparation (`SEMGREP_LOG_FILE`) | when that opengrep process ends |
| `locks/{install,runtime}-<sha16>.lock` | 0o600 | §4.7 | kept (empty) |
| `.runtime-*/`, `opengrep-<sha16>/.download-*`, `opengrep-<sha16>/.opengrep-*`, `selections/.tmp-*` | 0o700 / 0o600 | in-flight temporaries | on every path; `PruneCache` after a day |

`CacheDir` defaults to `os.UserCacheDir()/gogrep`:

- macOS: `~/Library/Caches/gogrep`;
- Linux: `$XDG_CACHE_HOME/gogrep`, else `~/.cache/gogrep`;
- Windows: `%LocalAppData%\gogrep`.

**Selection churn is now bounded.** It used to grow without limit: one machine had 114 files totalling 18 MB, a `--suite all` selection is 3.3 MB, and every cloned repository with its own rules adds one. `PruneCache` now bounds it.

### 4.9 Platform notes

- **Linux.**
  - Running a just-written executable can fail with `ETXTBSY` while another goroutine forks ([golang/go#22315](https://github.com/golang/go/issues/22315)). The runner rebuilds the `exec.Cmd` and retries the start up to 5 times, with backoff from 20 ms. Retrying is safe because `exec.Cmd.Start` starts no I/O goroutine before the process exists.
  - musl detection: §4.4.
- **macOS.**
  - The darwin assets are ad-hoc signed, which is enough on Apple Silicon.
  - Files written by Go's `net/http` and `os` carry no `com.apple.quarantine` (observed), so Gatekeeper is not involved.
  - A host app that sets `LSFileQuarantineEnabled` would quarantine the file, and Gatekeeper would then block the un-notarised binary. This is documented. The library never strips the attribute, and `Config.Opengrep` is the workaround.
- **Windows.**
  - Assets end in `.exe`.
  - A rename onto an executable in use fails, and the "exists and verifies" fallback covers it.
  - Cancellation uses `taskkill /T /F`, and locks use `LockFileEx`.
  - No Mark-of-the-Web is expected on files Go writes. This is unverified; CI runs windows-latest.

## 5. Removing process-global state

Every item from the code audit, and how it is resolved:

| # | Global state today | Where | Resolution |
|---|---|---|---|
| 1 | `var assets` written by `Main`: a confirmed data race, and a zero `Assets{}` panics | `run.go:29,34`; read at `rulesargs.go:263,306,349` | Removed. The root package embeds read-only `embed.FS` values; no package variable is assigned. |
| 2 | `bundle.sum = strings.TrimSpace(sum)` on every `Path()`: a confirmed race; `sum[:16]` panics if the file is empty | `bundle.go:23-24` | The `.sha256` embeds are gone. The checksum comes from `opengrep.json` through `internal/pin`, parsed once and validated as 64 hex digits. |
| 3 | Relative `projectRulesDir`, `projectTestsDir`, `projectSuitesDir` | `rulesargs.go:25-29` | Exported slash constants, always joined to an absolute `dir`. A relative `dir` is rejected. |
| 4 | Project rule set via `os.Stat` and `os.DirFS` of the working directory | `rulesargs.go:267-268` | `os.DirFS(filepath.Join(dir, ProjectRulesDir))`, skipped under `NoProjectRules` |
| 5 | Project suite lookup; `listSuites` reads `projectSuitesDir` | `rulesargs.go:302,355` | Joined to `dir`; skipped under `NoProjectRules` |
| 6 | `--suite` paths and `import:` read relative to the working directory | `rulesargs.go:294-299` | Relative to `dir` unless absolute. The CLI passes `dir = os.Getwd()`, so its behaviour and messages are identical (§3.7). |
| 7 | Injected `--exclude=opengrep/gogrep/rules/test` | `rulesargs.go:144` | Same string, relative to opengrep's working directory, which is now always `dir`. It matched with an absolute target and another working directory too (verified). Dropped under `NoProjectRules`. |
| 8 | `ruletest.Discover` reads, stats, uses `DirFS`, `filepath.Abs` and `Lstat` relative to the working directory | `discover.go:55,70,77,181,188,199,216-222` | `Discover(base, root, paths)`: relative paths join `base`; `linkedRel` compares against `base` |
| 9 | `Fixture.Name` and `Fixture.Dir` relative; the fixture's `cmd.Dir` is resolved at fork time | `discover.go:30,236`; `testcmd.go:210` | `Name` is a slash path relative to `base` (the same strings as today); `Dir` is absolute. The `$ (cd …)` line prints `Name`. |
| 10 | Fixture writes and `expected.txt` reads through the relative `f.Dir` | `files.go:17-77`; `report.go:46` | Absolute `Dir`; `TestOptions.ReadOnly` disables every write |
| 11 | `testBin`: `LookPath` plus `Abs` of a relative `$OPENGREP_BIN` | `testcmd.go:188-203` | The CLI makes `$OPENGREP_BIN` absolute when it contains a separator. The library rejects a relative path in `New`. The regular-file check moves to `internal/opengrep`. |
| 12 | `rebrandFile` resolves relative `-o` and `--sarif-output` | `sarif.go:58,66` | CLI only, relative to the user's working directory by design; now also chmods 0o600 |
| 13 | The scan's `exec.Command` has no `cmd.Dir`, so opengrep inherits the working directory (`.semgrepignore`, git, URIs) | `run.go:109` | `cmd.Dir = dir` always; `Scan` uses target `.`, which reproduces `gogrep scan .` run in `dir` (verified) |
| 14 | Error wording that assumes the working directory ("here", "from the project root") | `testcmd.go:27`; `discover.go:71` | The library wraps `ErrNoTestRoot` with `ProjectTestsDir`; the CLI keeps its exact text |
| 15 | `os.Getenv("OPENGREP_BIN")` | `run.go:150` | CLI only, passed as `Config.Opengrep` |
| 16 | `os.Getenv("SEMGREP_RULES")` | `rulesargs.go:102` | CLI only, in the `withRules` decision. `Scan` and `Test` strip it; `Command` passes `Env` as is. |
| 17 | `utf8Env` reads `LC_ALL`, `LC_CTYPE` and `LANG` via `os.Getenv`, not from the slice it extends | `run.go:135-136` | `utf8Env(env)` reads the slice it extends; the last value wins, as `os/exec` deduplicates |
| 18 | The whole host environment goes to opengrep, so `SEMGREP_*` and `OPENGREP_*` leak in | `run.go:111`; `testcmd.go:210` | `Config.Env` (nil: `os.Environ()` as of `New`); `Scan` and `Test` strip both prefixes |
| 19 | `exec.LookPath("opengrep")` | `run.go:159` | Lookup step 4 (§4.2), documented; also a bare `Config.Opengrep` |
| 20 | Scans lack `--disable-version-check` | `run.go` | `Scan`, `Test` and injected `Command` scans pass it |
| 21 | `os.UserCacheDir` hard-wired | `bundle.go:19`; `rules.go:236` | `Config.CacheDir`, defaulted once in `New`; `rules.Write(dir, …)` and extraction take explicit directories |
| 22 | opengrep's runtime in `~/.cache/opengrep`, unpacked in place; parallel cold starts crash | inside opengrep | `<CacheDir>/runtime-<k>`, published atomically, plus `XDG_CACHE_HOME` (§4.6) |
| 23 | `~/.opengrep/semgrep.log` (0o644), overwritten by concurrent runs | inside opengrep | `Scan`, `Test` and preparation: a 0o600 `SEMGREP_LOG_FILE` per opengrep process, removed afterwards; `HOME` is then untouched (verified). `Command`: unchanged. |
| 24 | `Main` passes `os.Stdout` and `os.Stderr` | `run.go:35` | Only `cmd/gogrep` touches stdio; the library writes only to writers the caller supplies |
| 25 | `cmd.Stdin = os.Stdin` | `run.go:110` | `Scan` and `Test`: the null device. `Cmd.Stdin` is nil unless set; the CLI sets it (§2.5 item 4). |
| 26 | `ruletest` prints CLI text itself | `ruletest/run.go:64,117,122-131`; `report.go`; `files.go:80,84` | `ruletest` returns results; all text moves to `cmd/gogrep/testreport.go` |
| 27 | `signal.Ignore(SIGINT, SIGTERM)` before every scan: permanent for the process, and inherited as SIG_IGN by every later child (probe-verified) | `run.go:115` | Gone from the library. The CLI calls it only for foreground pass-through commands. After a library scan, a host's later `git clone` starts with default dispositions. |
| 28 | `signal.NotifyContext` during `test` is process-wide | `testcmd.go:172-176` | CLI only, now also for `scan`, keeping the filter that leaves signals ignored at start ignored |
| 29 | The scan path has no context, process group, tree kill or `WaitDelay` | `run.go:103-126` | One runner in `internal/opengrep`: `CommandContext`, tree kill, `WaitDelay` 1 s, ETXTBSY retry, no inherited stdio |
| 30 | `os.Exit` | `main.go:26` | Only in `cmd/gogrep/main.go` and `tools/` |
| 31 | `bundle.Path` reuses an extraction whose size matches | `bundle.go:31` | SHA-256 verified once per process per path, size and modification time |
| 32 | `rules.Write` has no rename fallback and never cleans up | `rules.go:216-262` | Fallback, modification-time refresh, `PruneCache` |
| 33 | First-run serialisation only within one `Runner.Run` | `ruletest/run.go:76-99` | Process-wide and cross-process runtime preparation (§4.6); the gate is removed |
| 34 | An interrupted scan exits 0 with no SARIF, treated as success | `run.go:87-94` | `Scan` returns `*OutputError` or the ctx error. The CLI exits 130 on a signal, and 2 for exit 0 without requested SARIF. |
| 35 | `-o` SARIF files stay 0o644 | `sarif.go:66` | chmod 0o600 after rewriting |
| 36 | `judge` always writes into the scanned tree | `report.go:52-78`; `files.go:65-87` | `TestOptions.ReadOnly` |
| 37 | SARIF on stdout buffered whole | `run.go:80` | Kept: opengrep writes one document, and `Result.SARIF` is bytes by design. Most of its size is `driver.rules`. |
| 38 | No `-j` on scans, so concurrent callers oversubscribe | `run.go` | `ScanOptions.Jobs` plus the memory guidance (§3.3) |
| 39 | `-tags bundled` fails to compile on unpinned platforms | `bundle.go:16,23` | `embed_other.go` declares an empty binary |
| 40 | Argument-parsing quirks | `rulesargs.go:54-86`; `run.go:60-61` | Kept unchanged in the CLI. The library has no argv parsing, apart from `Command` checking `args[0] == "scan"`. |
| 41 | Read-only globals: `interrupts`, `bundle.binary`, `ruleArchives` | `procgroup_*.go:12-16`; `internal/bundle` | Fine as read-only data; `interrupts` moves to the CLI and the archives to `internal/rulesets` |
| 42 | Tests depend on `t.Chdir`, `t.Setenv`, and `repoDir` from `os.Getwd` | test files | Root and `internal/*` tests use absolute `t.TempDir()` directories, `Config.Env` and `t.Parallel()`. Only the CLI's own tests keep `t.Chdir` and `t.Setenv`, because the CLI's contract is the working directory and the environment. |

**Result.**

- **What the library reads from the process:**
  - `PATH`, through `exec.LookPath`;
  - `os.Environ()` (when `Env` is nil) and `os.UserCacheDir()` (when `CacheDir` is empty), once each, in `New`;
  - `HTTPS_PROXY` and `NO_PROXY`, only inside `InstallOpengrep`'s default client.
- **What it writes:** only under `CacheDir`, plus fixture files under `dir` from `Test` (unless `ReadOnly`) and `AcceptTests`.
- **What it never does:** change directory, install a signal handler, or touch a standard stream.

## 6. Worked example: a consumer CLI

`repogrep` clones nothing itself. It scans N already-cloned repository directories concurrently with one suite, prints each finding as a JSON line, and handles Ctrl-C. It uses only the standard library and `github.com/odipar/gogrep`, needs Go ≥ 1.25 for `sync.WaitGroup.Go`, and compiles against the §3.2 surface: it was checked with `go vet` for darwin, linux and windows against a stub. It is the program the external-consumer CI job builds (§7.4).

```go
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
```

What the example shows:

- **Concurrency is the caller's.** One `Engine` serves every goroutine. A slot channel bounds the concurrent opengrep processes, and `Jobs` divides the CPUs between them.
- **Cancellation is the caller's.** `NotifyContext` cancels `ctx`; gogrep kills the process trees, queued scans never start, and no opengrep outlives the program.
- **Preparation comes first.** `Opengrep` or `InstallOpengrep` runs once before the fan-out, so a missing opengrep fails fast and the runtime is prepared once.
- **Trust is explicit.** Repositories' own rules and suites are ignored unless `-trust-project` is given. `nosemgrep` matches are reported but marked, and they do not count.
- **Partial results are usable.** A non-zero opengrep exit that still produced a valid log yields its findings through `ExitError.Result`.

## 7. Testing and documentation

### 7.1 Unit tests (no opengrep needed; run everywhere, also under `-race`)

**Fake opengrep.** `internal/fakeopengrep.Main` is today's fake (`run_test.go:19-60`), moved. Each package's `TestMain` re-executes the test binary as the fake when `GOGREP_TEST_FAKE_OPENGREP=1`. Root tests set that through `Config.Env` and point `Config.Opengrep` at `os.Executable()`. Since `Scan` strips only `SEMGREP_*` and `OPENGREP_*`, no `t.Setenv` is needed and the tests can run in parallel, which itself shows that the library has no globals.

The fake's modes:

- print argv, working directory and selected environment variables into the SARIF `properties`;
- exit with a given code;
- wait;
- spawn a grandchild;
- replay a recorded SARIF file;
- exit 0 with empty stdout;
- unpack slowly into `$XDG_CACHE_HOME/opengrep/<version>/`, recording overlapping runs with `O_EXCL` files;
- answer `--version` with exit 0 at once.

**Root package.** All tests use `t.Parallel()`, `CacheDir: t.TempDir()` and an explicit `Env`, and never `t.Chdir` or `t.Setenv`.

- **Selection.**
  - Default suite for Scan and Rules versus every rule for Test.
  - Union and dedupe.
  - Filters ANDed and their values ORed, like the CLI's repeated flags.
  - A Filter with no Values keeps nothing.
  - Suite files and imports relative to `dir`, with `PathError` names shown as given.
  - `SelectionError` fields and texts; `Validate`.
- **Project handling.**
  - `test/` is skipped in any letter case.
  - A project `code-scanning.yaml` shadows the built-in one.
  - `NoProjectRules` hides both, keeps an empty `project` set, and drops the `--exclude`.
  - `dir == ""` for `Rules` and `Suites`.
  - A relative `dir` is rejected.
- **Scan.**
  - Exact argv per option, `cmd.Dir == dir`, `--` before targets, `Targets` validation.
  - Stdin is empty.
  - `SEMGREP_*` and `OPENGREP_*` stripped; `SEMGREP_LOG_FILE` set and removed; the locale fix computed from the slice; `XDG_CACHE_HOME` set.
  - Exit 0 with empty stdout gives an `*OutputError` that is `ErrNoSARIF`.
  - Exit 2 with valid SARIF gives an `*ExitError` with `Result`; with garbage output, without.
  - The 64 KiB stderr tail.
- **Findings,** decoded from `internal/ruletest/testdata/sarif/*.json` plus new recordings made with opengrep 1.30.2:
  - a `nosemgrep` match (`Suppressed`);
  - the level fallback;
  - a raw `b c%41.go` URI, never decoded;
  - the sort order;
  - rebranding byte-identical to the old `rebrand`.
- **Command.**
  - Injection with and without `NoProjectRules`; an error for non-`scan` args with a Selection; verbatim args without one.
  - `Foreground`.
  - The `Cmd` fields are honoured when changed before `Run`.
- **Cancellation (Unix).** The fake spawns a grandchild and waits. After cancelling, the call returns within `WaitDelay` + 1 s with `errors.Is(err, context.Canceled)`, and `kill(pid, 0)` reports ESRCH for both processes. This is today's `TestExecFixtureKillsTree` technique; on Windows, `tasklist` is used by PID.
- **`TestNoProcessState`.** After `Scan`, `Cmd.Run` and `Test` against the fake:
  - `signal.Ignored(os.Interrupt)` and `signal.Ignored(syscall.SIGTERM)` are false;
  - `os.Getwd()` and `os.Environ()` are unchanged;
  - a probe child started afterwards does not start with SIGINT ignored (the research's sigprobe technique).
- **Resolution order (§4.2),** row by row with temporary caches. `internal/opengrep` takes pins as values, so tests inject a fake asset and its hash.
  - An embedded mismatch gives an `*IntegrityError`.
  - A corrupted cached file is treated as absent and never executed.
  - A `PATH` binary with the wrong hash is rejected unless `AllowUnpinned`.
  - A relative `Opengrep` is refused by `New`.
  - The `ErrNoOpengrep` text, and the unchanged `exec: ` text for an explicit missing path.
- **`InstallOpengrep`** against `httptest.Server`:
  - a good hash, a 302 redirect, a bad hash that leaves nothing behind;
  - the 256 MiB cap, retries on 503, ctx cancelled mid-download;
  - `From`, `Platform`;
  - six re-executed test processes installing into one cold cache, which leave one 0o700 file and no temporaries.
- **Runtime preparation,** with the fake's slow unpack:
  - a private directory and a rename;
  - a second call costs one `stat`;
  - two re-executed processes never overlap;
  - a failed `--version` publishes nothing and the run proceeds;
  - a cancelled unpack leaves no `.runtime-*`;
  - the Windows marker path on windows-latest.
- **musl detection** (`internal/pin`) with `fstest.MapFS`: musl only, glibc only, both, neither.
- **`PruneCache`:** removal by age and by pin; current entries kept; temporaries older than a day removed.

**`internal/*`.**

- `rules.Write(dir, …)` gets its first direct tests: content addressing, 0o600 and 0o700 modes, the rename fallback, modification-time refresh, and concurrent writers under `-race`.
- `ruletest` tests drop `t.Chdir` and gain `t.Parallel`. `TestDiscoverLinkedPaths` passes a symlinked base, and runner tests assert structured results.
- A new `ReadOnly` test hashes the fixture tree (names, sizes, modification times) before and after.
- `internal/sarif`: the decode tests move from `ruletest`; first tests of `Rebrand` and `Check`.

**`cmd/gogrep`.**

- Every existing test and golden file stays byte-identical, with two deliberate exceptions:
  - `TestRunScan`'s injected argv gains `--disable-version-check`;
  - `checkGolden` no longer strips the "no bundled rule sets" hint.
- The tests keep `t.Chdir` and `t.Setenv`.
- New tests, one per §2.5 change:
  - SIGINT during a fake `scan` gives 130 and `gogrep: interrupted`, and the fake's grandchild is gone;
  - exit 0 without SARIF gives 2;
  - `-o` ends 0o600;
  - `--suite=` still prints the "matches no rules" message;
  - `install-opengrep --from` with a wrong file gives 1 and an `IntegrityError` message;
  - `TestCLIUsesPublicAPI`.

### 7.2 Integration tests against the real opengrep

- **Gate.** `requireOpengrep` resolves through `eng.Opengrep(ctx)` with `EmbeddedOpengrep: bundle.Binary()` (a test-only import), runs `--version`, and skips unless it equals the pin. It is also skipped under `-short`. A test file's import of `internal/bundle` never reaches consumers, because `go mod vendor` and `go mod tidy` consider only the tests of the main module; the consumer job (§7.4) checks this.
- **Root package.**
  - A `Scan` of a temporary copy of `testdata/project`, from a working directory elsewhere, matches `testdata/golden/scan-findings.json` (findings, diagnostics and rule count; `-update` supported).
  - With `NoProjectRules`, the `project.*` findings disappear and the fixture directory is scanned.
  - A shadowing project suite is honoured only without `NoProjectRules`.
  - `.semgrepignore` is honoured (today's `TestScanSkipsFixtures`, through `Scan`).
  - A `// nosemgrep` sample yields `Suppressed: true`.
  - `Test` on the copy passes every fixture, with structured results.
  - 8 concurrent `Scan`s of 8 copies each return only their own paths.
- **CLI.** The existing golden tests stay: `TestTestCommitted`, `TestTestMissingExpected`, `TestTestRegression`, `TestTestBroken` (with `-j 1` and `-j 8` giving identical output), `TestTestSelection`, `TestScanSkipsFixtures` and `TestOpengrepVersion`.
- **Cold runtime (CI, all three OSes).** Four concurrent `gogrep scan --sarif .` processes, with `HOME`, `XDG_CACHE_HOME` and `LocalAppData` pointing at an empty temporary directory, all exit 0 with SARIF. Before the change, 2 of 4 died with SIGBUS.

### 7.3 Race tests

`go test -race -short ./...` and `go test -race -short -tags gogrep_bundled ./...` run on ubuntu and macos (the race detector needs cgo on Windows). They cover:

- concurrent `Rules`, `Suites`, `Scan` (fake), `Command` (fake) and `Test` (fake) on one Engine, and on two Engines sharing one `CacheDir`;
- 8 goroutines extracting one embedded binary. This is the old `bundle.sum` race, now a regression test with an injected pin.
- two concurrent CLI `run` calls. This is the old `assets` race.

### 7.4 External-consumer test (proves `go get` works)

Two separate modules, each with its own `go.mod` and therefore excluded from gogrep's module zip and from `./...`:

- **`testdata/modzip`** depends on `golang.org/x/mod`. It builds the exact module zip of HEAD with `zip.CreateFromVCS`, plus the `.info` and `.mod` files, in a `file://` GOPROXY tree, and prints the pseudo-version. It is a module of its own because the consumer's `go.mod` cannot resolve gogrep before the zip exists.
- **`testdata/consumer`** holds §6's `repogrep` and `consumer_test.go`.

The CI job runs on ubuntu, macos and windows:

1. `cd testdata/modzip && go run . -repo ../.. -out "$RUNNER_TEMP/proxy"` prints `$V`.
2. Copy `testdata/consumer` to a temporary directory. With `GOPROXY=file://$RUNNER_TEMP/proxy,https://proxy.golang.org`, `GONOSUMDB=github.com/odipar/gogrep` and a scratch `GOMODCACHE`, run `go get github.com/odipar/gogrep@$V`.
3. `go vet ./... && go build ./...`.
4. `go mod tidy && go mod tidy -diff`.
5. `go mod vendor && go build -mod=vendor ./...`. This is the step that catches an unsatisfiable `go:embed` in the library's import graph.
6. `go build -tags bundled,musl ./...`. The consumer's own tags must not matter.
7. `GOGREP_TEST_ASSET=<the asset fetched by tools/fetch-opengrep> GOFLAGS=-mod=vendor go test ./...`. With `-mod=vendor` the test needs no network. It checks:
   - `Rules("", &RulesOptions{Selection: Selection{Suites: []string{"all"}}})` returns 2,121 rules, and `Suites("", nil)` lists `code-scanning` with `Default` set, both without opengrep;
   - `InstallOpengrep(ctx, &InstallOptions{From: asset})` into a temporary `CacheDir`;
   - a `Scan` of a temporary directory holding `http.Get("http://example.com/")` in `main.go`, with the default suite, finds `opengrep-rules.problem-based-packs.insecure-transport.go-stdlib.http-request` at `main.go`, and the same line with `// nosemgrep` yields `Suppressed: true` (both verified with opengrep 1.30.2);
   - `PruneCache`.

After each `v*` tag, a release smoke job runs `go get github.com/odipar/gogrep@$TAG` through `proxy.golang.org` in the same module.

### 7.5 CI changes

| Workflow | Change |
|---|---|
| `test.yml` (ubuntu, macos, windows) | `go run ./tools/fetch-opengrep`<br>`go vet ./... && go vet -tags gogrep_bundled ./...`<br>`go test -tags gogrep_bundled ./...`, and `go test -short ./...` unbundled<br>build `./cmd/gogrep` and run the example fixtures in `testdata/project`<br>the rule-set stamp check<br>cross-builds: `GOOS=freebsd GOARCH=amd64` and `GOOS=linux GOARCH=386` with `-tags gogrep_bundled` must compile; `-tags bundled` must fail naming `gogrep_bundled`<br>the cold-runtime step (§7.2), which on Windows also checks §4.6's marker path |
| new `race` (ubuntu, macos) | §7.3 |
| new `consumer` (ubuntu, macos, windows) | §7.4 |
| new `musl` (ubuntu, container `golang:1.26-alpine`, with `apk add git`) | `go test -short ./...`; the consumer smoke test with `InstallOpengrep` downloading the musl asset (exercising detection), then a `Scan`. musl is untested today. |
| new `rulesets.yml` (on changes to `opengrep.json` or `tools/`, and weekly) | `go run ./tools/fetch-opengrep -check-rules` (§4.1) |
| new `gorelease` (advisory, never failing) | `go run golang.org/x/exp/cmd/gorelease@<pinned> -base=<last tag>` |
| `release.yml`, `gogrep.yml` | Build `./cmd/gogrep` with `-tags gogrep_bundled`, plus `gogrep_musl` for the musl variants. The release loop maps the variant `musl` to the tag `gogrep_musl`. |

### 7.6 Documentation

**`doc.go`** (pkg.go.dev), with `# Headings` and `[Engine.Scan]`-style links. Its sections:

- Overview, with a 10-line example.
- Obtaining opengrep: §4.2, `[Engine.InstallOpengrep]`, air-gapped routes, macOS quarantine.
- The offline guarantee.
- Rule sets, suites and stable rule ids.
- Project rules and untrusted repositories: the §3.6 table.
- Concurrency and memory (§3.3).
- Cancellation and signals, including what happens when the host is SIGKILLed.
- Files written and their permissions (§4.8).
- What is read from the process (§5, Result).
- Errors and exit codes.
- Stability (§8.1).
- Licensing: LGPL-2.1 for gogrep and opengrep; what Go's static linking means for distributors; the Commons Clause on opengrep-rules; NOTICE.md.

**`example_test.go`** (`package gogrep_test`):

- `Example` (New, Opengrep or InstallOpengrep, Scan, print findings) and `ExampleEngine_Scan` (`errors.As` on `*ExitError`, partial results, `ErrNoOpengrep`). They have no `// Output:` line because they need opengrep, but they compile and pkg.go.dev shows them.
- `ExampleEngine_Rules` runs with `// Output:`. It lists the project rules of `testdata/project` with `Suites: ["all"]` and `Filters: [{ruleset, [project]}]`, needs no opengrep, and prints:

  ```
  project.generic.todo-marker INFO
  project.go.no-exec-command WARNING
  project.go.no-exec-command-in-prod WARNING
  ```
- `ExampleSelection` (`Validate` of a bad regular expression) and `ExampleEngine_Suites` run with output.
- `ExampleEngine_Test` (Progress printing, `ReadOnly`) and `ExampleExitError` (the exit-code mapping) compile only.

**Other files.**

- **`README.md`.**
  - A new section, "Use as a Go library": `go get`, the §3.1 snippet, getting opengrep (`InstallOpengrep`, `From`, `gogrep install-opengrep`), offline use, concurrency and memory, untrusted repositories, stability, licensing, and a pkg.go.dev link.
  - "Install" gains `go install github.com/odipar/gogrep/cmd/gogrep@latest && gogrep install-opengrep`.
  - "Building" uses `-tags gogrep_bundled` and `./cmd/gogrep`.
  - The sentence saying plain builds have no bundled rules (line 484) is replaced.
- **`suites/README.md` and `rules/README.md`:** `project` means "of the scanned directory".
- **`NOTICE.md`:** as in §4.1.
- **`docs/design/rule-test-fixtures.md`:** a layout note pointing at this document.

## 8. Compatibility, versioning, alternatives and open questions

### 8.1 Compatibility and versioning

**First release.** The first release with the API is **v0.4.0**. The stability statement goes into `doc.go` and the README:

> gogrep's Go API is new in v0.4.0 and is v0: a minor release (v0.x.0) may change it, and its release notes list every change under "API changes"; a patch release never does. Anything deprecated keeps working, marked `// Deprecated:`, for at least one minor release. Identifiers marked "Experimental:" (Command, CommandOptions, Cmd) may change in any minor release. New options are added only as fields whose zero value keeps the old behaviour; no exported function gains parameters. Re-pinning opengrep or a rule set happens only in minor releases and can change findings; rule ids stay stable.

**Stable across all v0 releases:**

- qualified rule ids;
- SARIF `tool.driver.name` = `gogrep`;
- the meaning of `Finding` fields;
- the CLI's flags, outputs and exit codes, apart from §2.5.

**Pins.** Each gogrep version pins one opengrep build and three rule commits, so consumers pin their gogrep version. `OpengrepInfo` reports what actually runs.

**Go version.** `go.mod` moves from `go 1.26.2` to `go 1.26.0` plus `toolchain go1.26.2`. Importers are no longer forced onto a patch release, and gogrep's own CI keeps 1.26.2. Nothing here needs more than 1.25 (`WaitGroup.Go`).

**Dependencies** stay the standard library plus `gopkg.in/yaml.v3`. Importers may upgrade yaml.v3 through MVS; the risk is low because it is frozen.

**v1** follows once the delegating CLI from #5 has used the API for about two minor releases without needing a breaking change.

### 8.2 Alternatives considered

**API shape:**

- **`exec.Cmd`-style only** (`gogrep.Command(ctx, "scan", …)`, like `x/vuln/scan`). Rejected as the main API: everything is strings, callers parse SARIF, and there are no typed listings. It survives as the Experimental `Command` that the CLI needs.
- **Returning a raw `*exec.Cmd` from `Command`.** Rejected:
  - a caller could overwrite `Cancel` or `SysProcAttr` and lose the tree kill;
  - it gets no ETXTBSY retry;
  - the engine could not clean up per-run files.
- **Package-level functions with functional options.** Rejected:
  - engine-level state (parsed sets, cache, binary) would become hidden globals or be repeated on every call;
  - engine-level and per-call settings would mix;
  - `Scan`, `Rules` and `Test` share `Selection`, which points to a struct.
- **`NoProjectRules` on `Config`.** Rejected: a consumer scanning repositories of both trust levels would need two Engines. It is per call.
- **A concurrency semaphore (`MaxJobs`) and a `Timeout` field.** Rejected for v0.4: the caller bounds concurrency (§6) and time (a ctx deadline), and the CLI's `-j` would need workarounds. If `MaxJobs` is added later, its zero value means unlimited.

**Package path:**

- **Library at `github.com/odipar/gogrep/gogrep`, with the root staying `main`.** Rejected: `rules/` and `suites/` would have to move under it to be embeddable, and the path stutters.
- **An extra `internal/cli` package.** Rejected: it gains no isolation, because the import test already restricts the command, and the CLI's tests work in `package main`.
- **Exporting `cmd/gogrep`.** Rejected: `cmd/` is for main packages.

**Distribution:**

- **Binaries in the main module.** Rejected: 341,797,240 bytes (326 MiB) per pin for every consumer of every version, 65% of the 500 MiB zip cap. Git history would pass GitHub's 1 GB guidance after about 3 pins, and the 53 MB Windows binary triggers GitHub's 50 MiB warning.
- **Per-platform modules, or a go-embed-python-style companion module.** Deferred:
  - Go has no optional dependencies;
  - `tidy` and `vendor` fetch all 7 assets;
  - musl needs a custom tag;
  - every pin needs new tags.
  
  `Config.EmbeddedOpengrep` already lets a consumer embed opengrep itself.
- **Git LFS.** Rejected: the proxy serves pointer files ([golang/go#47241](https://github.com/golang/go/issues/47241)).
- **`go:generate`.** Rejected: it never runs for dependencies.
- **`PATH`-only.** Rejected: no pinning, so findings drift. It remains available through `AllowUnpinned`.
- **An auto-install option.** Rejected: it blurs "offline by default", and the explicit two-line fallback does the same.
- **A tagged binary embed in the same package as the always-embedded archives.** Rejected: it breaks `go mod vendor` for every importer (reproduced).

**First-run fix:**

- **A lock plus a lone `--version` warm-up on every OS.** Rejected for POSIX:
  - it adds about 1 s to every process (warm starts measured at 0.96–1.05 s);
  - a partial runtime from an interrupted plain opengrep run still gets repaired in place, which can SIGBUS.
  
  It is kept only where nothing else works, on Windows, behind a marker.
- **Merging unpacked entries into opengrep's shared `~/.cache/opengrep` and treating "the version directory exists" as "prepared".** Rejected: a partial runtime would count as ready, and concurrent repairs in place could still crash. The research tested renaming a whole private directory, which is what §4.6 does.
- **Keeping `ruletest`'s per-call first-alone gate.** Rejected: it does not cover scans, other calls or other processes.

**Rule configurations and results:**

- **Per-call temporary rule configurations.** Rejected: printed `--show-opengrep-output` command lines could no longer be rerun, which rule-test-fixtures.md §5.3 promises. Content addressing plus `PruneCache` instead.
- **Percent-decoding SARIF URIs.** Rejected: opengrep writes them raw, and decoding would corrupt paths that contain `%`.
- **The `go-sarif` dependency or its types; streaming; a global logger or `SetLogger`** (osv-scanner, trivy). Rejected for the reasons in §1.3 and §3.5.
- **`os/signal` inside the library**, as today's `scan` and `test` paths use it. Rejected: it hijacks the host's signals and leaves SIG_IGN to every later child of the host.

**Untrusted repositories:**

- **Reading project files through `os.Root` with size limits.** Rejected for v0.4: it would change the CLI for projects that symlink shared rules from outside the repository. `NoProjectRules` is the trust switch.
- **An option to ignore a repository's `.semgrepignore`.** A follow-up, once opengrep has a supported switch.

**Follow-up:** Windows Job Objects with `KILL_ON_JOB_CLOSE` (standard library, through `syscall.NewLazyDLL`), so that opengrep dies with a SIGKILLed host.

### 8.3 Open questions (each with its recommended default)

**Resolved (2026-10-13):** the maintainer chose the recommended default for all three questions below, and the package layout of §2 (the module root is the library; the command is `cmd/gogrep`, `package main`).

1. **Should project rules and suites stay on by default in the library?**
   - **Recommended: yes.** `NoProjectRules` opts out per call, for parity with the CLI and because #5 lists them. The documentation and §6 show `NoProjectRules` for clones.
   - The alternative is an opt-in `TrustProject` field. It is safer for scanning services but differs from the CLI.
2. **What does LGPL-2.1 mean for importers?**
   - Go links statically, so a consumer who distributes binaries containing gogrep takes on LGPL-2.1 relinking obligations.
   - **Recommended: keep LGPL-2.1 and document the obligations** in `doc.go` and the README.
   - Adding a static-linking exception would make adoption in closed-source tools easier. That is the copyright holder's decision.
3. **What happens to opengrep's old default runtime?** After upgrading, `~/.cache/opengrep/v1.30.2` (245 MB) is no longer used by gogrep on Linux and macOS.
   - **Recommended: leave it,** because a standalone opengrep may use it. The v0.4.0 release notes say it can be deleted, and `PruneCache` never touches it.

## 9. Implementation plan

**Rules for every step:**

- **One commit per step.** Each commit leaves `go vet ./...`, `go vet -tags gogrep_bundled ./...`, `go test ./...` and `go test -tags gogrep_bundled ./...` green on ubuntu, macos and windows.
- **The bundled tag.** Step 1 renames it. From then on, `-tags gogrep_bundled` is the bundled gate, and `-tags bundled` fails on purpose with a message naming the new tag; CI asserts that failure.
- **Golden files.** CLI golden files change only where a step says so.
- **Commit messages** end with the `Co-Authored-By` trailer.
- **Staging.** Steps 10–17 build the API in `internal/engine` under its final names, receiving the embedded files through an internal parameter. Step 18 is then mostly a move.

| # | Commit | Files | Verification |
|---|---|---|---|
| 0 | Add the public Go API design | `docs/design/library-api.md` | It renders; its links resolve |
| 1 | Rename the build tags to `gogrep_bundled`/`gogrep_musl`; compile bundled builds everywhere | `internal/bundle/embed_*.go`, `none.go`, `embed_rules.go`; new `embed_other.go` (empty `binary` and `sum`), new `oldtag.go` (`//go:build bundled && !gogrep_bundled`, an undefined identifier naming `gogrep_bundled`); `.github/workflows/{test,release,gogrep}.yml` (the release maps variant `musl` to `gogrep_musl`); README "Building" | Both vet tag sets pass. `GOOS=freebsd GOARCH=amd64` and `GOOS=linux GOARCH=386 go build -tags gogrep_bundled .` compile (they failed before). `go build -tags bundled .` fails naming `gogrep_bundled`. A `workflow_dispatch` release dry run builds all 7 targets. |
| 2 | Track the rule-set archives and embed them in every build | new `internal/rulesets/{rulesets.go,*.tar.gz,*.commit}`; `tools/fetch-opengrep/{main,rules}.go` write there; `internal/bundle` drops `embed_rules.go` and `RuleSets`; `cmd/gogrep/rulesargs.go` (`loadEnv` reads `rulesets`; the "no bundled rules" branches go); `internal/ruletest/ref.go` (hint removed) and its test; `cmd/gogrep/testcmd_test.go` (`checkGolden` stripping removed); `.gitattributes`; `NOTICE.md`; README; `test.yml` stamp check | Unbundled `go test ./...` runs the goldens with bundled rules and gets the same output as a bundled run. From the repository root, `go run . rules --suite all` prints `2121 rules`. `git ls-files internal/rulesets` lists the 6 archive and stamp files (about 458 KB) beside `rulesets.go` and its test. `go run ./tools/fetch-opengrep` leaves `git status` clean. The stamp check fails on a deliberately edited stamp. |
| 3 | `internal/pin` and verified extraction of the embedded binary | new `internal/pin` and tests (platform keys, musl detection with `fstest.MapFS`); new `internal/opengrep/{extract,verify}.go` and tests; `internal/bundle`: `Binary()` only, `sum` and the `.sha256` embeds removed; `main.go` passes `opengrep.json` in `Assets.Pins`; `cmd/gogrep/run.go` extracts through `internal/opengrep`; `tools/fetch-opengrep` uses `internal/pin` and stops writing `.sha256` files | `go test -race -tags gogrep_bundled ./...`, with 8 goroutines extracting one injected binary (the old `bundle.sum` race) clean. A bundled test checks `sha256(bundle.Binary())` against the pin. The extraction path is unchanged (`opengrep-<sha16>`). An invalid pin is an error, not a panic. |
| 4 | One context-aware opengrep runner; `gogrep test` uses it | new `internal/opengrep/{run,env,procgroup_unix,procgroup_windows,procgroup_other}.go` and tests (tree kill, `WaitDelay`, ETXTBSY retry through an injected start function, `utf8Env` reading its slice, prefix stripping); `cmd/gogrep/testcmd.go` (`execFixture` uses it); `cmd/gogrep/procgroup_*.go` shrink to `signals_{unix,other}.go` | `TestExecFixtureKillsTree` moves and passes. `TestTestOpengrepBin` passes. Goldens are unchanged. |
| 5 | Scans in their own process group; the CLI catches signals; SARIF checks | `cmd/gogrep/run.go` (`scan` through the runner, own group, `NotifyContext`, 130; other forwards and `opengrep` foreground with `signal.Ignore`; the stdin rule), `sarif.go` (chmod 0o600; exit 0 without requested SARIF gives 2), `rulesargs.go` (injected `--disable-version-check`); tests | `TestRunScan`'s argv gains `--disable-version-check`. New: SIGINT during a fake scan gives 130, `gogrep: interrupted`, and the grandchild is gone; `-o` ends 0o600; exit 0 with empty stdout gives 2; a probe child started after an in-process scan does not start with SIGINT ignored. `TestRunOpengrep*` unchanged. |
| 6 | `rules.Write` takes its directory | `internal/rules/rules.go` and new `rules_test.go` cases; callers pass `<UserCacheDir>/gogrep/selections` | Direct tests: content addressing, modes, rename fallback, modification-time refresh, concurrent writers under `-race` |
| 7 | `ruletest.Discover` with an explicit project directory | `internal/ruletest/{discover,files,report,run}.go` and tests (no `t.Chdir`, `t.Parallel`; the `$ (cd …)` line prints `Name`); `cmd/gogrep/testcmd.go` passes `os.Getwd()` | All discover tests pass, including a symlinked base. CLI goldens are byte-identical. `TestTestOpengrepBin` still finds an absolute binary in the printed command. |
| 8 | The `ruletest` runner returns results; the CLI formats them; `ReadOnly` | `internal/ruletest/{run,report,files}.go` (results through a callback, `Accept` returns per-fixture results, `ReadOnly`, no printing); new `cmd/gogrep/testreport.go` (status lines, diffs, details, show-output with `commandLine`/`quoted`, tally, untested warning, interrupt message) | Goldens `pass`, `broken`, `selection` and `exec-command-*` are byte-identical, and `-j 1` equals `-j 8`. The `ReadOnly` tree-hash test passes. `TestTestTerminalSignals` and `TestTestUntestedWarning` pass. |
| 9 | `internal/sarif`: decoding, findings, rebranding | new `internal/sarif` and tests; `internal/ruletest/sarif.go` moves there; `cmd/gogrep/sarif.go` uses `sarif.Rebrand`/`Check`; new recordings `internal/sarif/testdata/{suppressed,levels,raw-uri}.json` made with opengrep 1.30.2, each with its `.exit` file as in `internal/ruletest/testdata/sarif` | Every recorded log decodes. `Rebrand` is byte-identical to the old function on every recording. Findings tests cover the level fallback, `Suppressed`, the raw `b c%41.go` path and the sort order. |
| 10 | `internal/engine`: `Config`, `New`, `Selection`, `Rules`, `Suites` | new `internal/engine/{engine,selection,list,errors}.go` and tests (parallel, absolute temporary directories, `NoProjectRules`, `dir == ""`, relative `dir` rejected, suite paths relative to `dir`); `New(cfg, files)` takes the root's embedded files as `engine.Files` until step 18; `internal/engine/staging.go` (`SelectionFile`, `PlanTests`) lets the CLI's scan and test paths reach the engine until steps 13 and 15 remove it; `cmd/gogrep/rulesargs.go` (`rules`, `suites` and the rule environments of scan and test go through the engine; `var assets` removed: `run` takes the files) | `TestRunRulesAndSuites` unchanged. `TestSelectionFilter` and `TestLoadEnvSkipsProjectTests` move with the functions they test into `internal/engine`, keeping their cases; the new `TestGogrepFlags` checks the flags' half of the old `TestSelectionFilter`. Two concurrent `run` calls (the old `assets` race) are clean under `-race`. |
| 11 | `Engine.Opengrep`: the lookup order | `internal/engine/opengrep.go`; `internal/opengrep/resolve.go` (`Finder`) and tests; `cmd/gogrep` maps `$OPENGREP_BIN` and `bundle.Binary()` into `Config` (`opengrepBin`, `testBin` and `extractOpengrep` removed; `TestExtractOpengrep`'s cases move to `internal/engine`) | §4.2 precedence tests row by row. `TestTestOpengrepBin` (relative, missing giving `gogrep: exec: `, `.`) and `TestRunScan` "no opengrep" unchanged. |
| 12 | Prepare opengrep's runtime once; per-process logs; a hermetic `Test` environment | new `internal/opengrep/{runtime,lock,lock_unix,lock_windows,lock_other}.go` and tests; every opengrep child gets `XDG_CACHE_HOME` (POSIX); `Test` strips `SEMGREP_*`/`OPENGREP_*` and sets `SEMGREP_LOG_FILE`; `ruletest`'s first-run gate and `TestRunFirstAlone` removed (the test moves to `internal/opengrep`); `internal/engine/staging.go` gains `OpengrepEnv` and `TestExec` for the CLI until steps 13 and 15; the CLI's fake opengrep answers the preparation's `--version` (it has a log file) at once, and each test that uses it gets a cache of its own; `test.yml` runs the cold-runtime step before the tests, so that Windows's runtime is cold too | Fake-unpack tests: private directory and rename, a warm call is a `stat`, two processes never overlap, a failed `--version` publishes nothing, cancellation cleans up. CI's cold-runtime step: 4 concurrent `gogrep scan` runs exit 0 on all three OSes. Goldens unchanged. |
| 13 | `Engine.Command`; the CLI's scan, forwards and pass-through use it | `internal/engine/command.go` and tests (injection, `NoProjectRules`, `Foreground`, verbatim args, `Cmd` fields); `ExitError` without `Result`, which step 14 adds; `internal/opengrep.StartError`, so that `Cmd.Run` can wrap `ErrNoOpengrep`; new `internal/fakeopengrep` (the CLI's fake, moved, reporting its working directory and chosen variables too), used by the engine's and the CLI's tests; `cmd/gogrep/forward.go` (the `withRules` decision stays; `SelectionFile` and `OpengrepEnv` leave `staging.go`) | `TestRunScan`, `TestWithRules` (argv read from `Cmd.Args`) and `TestRunOpengrep*` pass unchanged from step 5 |
| 14 | `Engine.Scan` with typed findings; `ExitError`, `OutputError` | `internal/engine/scan.go` and tests; `testdata/golden/scan-findings.json`; `Command` and `Scan` share `ruleArgs` (rule injection) and `Scan` and the staged `TestExec` share `runHermetic` (environment, log file, process group); `internal/fakeopengrep` replays a SARIF file (`GOGREP_TEST_FAKE_SARIF`) and writes N bytes of stderr (`GOGREP_TEST_FAKE_STDERR`) | §7.1 Scan tests with the fake. §7.2 integration golden (the findings without their fingerprints, which may depend on the platform; the test checks that each has one of its own). 8 concurrent scans of 8 copies. `TestNoProcessState` compares signal dispositions and a probe child with those before the calls, so it also passes in a process started with SIGINT ignored. |
| 15 | `Engine.Test` and `Engine.AcceptTests`; `gogrep test` uses them | `internal/engine/test.go` and tests; `internal/engine/staging.go` removed; `cmd/gogrep/testcmd.go` and `testreport.go` (which formats `TestResult`s). `TestResult.RuleID` is also set when opengrep rejects the resolved rule (stage RULE), as that rule is known; it is "" only at SETUP or when rule.ref names no rule. The CLI maps `--suite=`/`--rule=` without a value to a `Filter` without values, which keeps no rule, so `Test` reports discovery errors before the empty selection, as before | All test goldens byte-identical. `ReadOnly`, `Progress` order, cancellation. `TestTestOpengrepBin`'s "unresolved references need no binary" still holds. |
| 16 | `Engine.InstallOpengrep` and `gogrep install-opengrep` | `internal/engine/install.go`; `internal/opengrep/download.go` and tests (§7.1 `httptest` cases, the 6-process cold install); `cmd/gogrep/install.go`; `tools/fetch-opengrep` uses `opengrep.Download`; README. `opengrep.Download` is a struct (`URL`, `From`, `Client`, `SHA256`) whose `Fetch(ctx, path)` does §4.4 steps 4 and 5; `opengrep.Install(ctx, dir, d, log)` adds steps 2 and 3 for the cache. `InstallOptions.From` must be absolute (the CLI makes `--from` absolute), and `BaseURL` must be an http or https URL, so that a typo is not retried for 7 s. `gogrep install-opengrep` is dispatched before gogrep's own flags are parsed, as `gogrep opengrep` is, and takes only `--from`, `--base-url` and `-h` | Unit tests. The CLI test with a wrong `--from` file gives 1. In CI's unbundled leg, `gogrep install-opengrep --from <fetched asset>` and then the integration tests run against the installed copy. |
| 17 | `Engine.PruneCache` | `internal/engine/prune.go` and tests | Removal by age and pin; current entries kept; temporaries older than a day removed |
| 18 | The module root becomes the gogrep library; the command becomes `package main` | `git mv internal/engine/*.go .` (`package gogrep`; `New(cfg)` uses the root embeds); new `embed.go`; `main.go` and `Assets` deleted; `cmd/gogrep` becomes `package main` with `main.go`; new `cmd/gogrep/imports_test.go` (`TestCLIUsesPublicAPI`); `go.mod` (`go 1.26.0`, `toolchain go1.26.2`); workflows build `./cmd/gogrep`; README install path | Every CLI test and golden passes. `TestCLIUsesPublicAPI` passes. `go doc github.com/odipar/gogrep` shows exactly §3.2. `go list -deps .` contains no `internal/bundle`. `go build -tags gogrep_bundled -o gogrep ./cmd/gogrep && (cd testdata/project && ../../gogrep test)` prints `All … tests passed.` |
| 19 | Package documentation, examples, README library section | `doc.go`, `example_test.go`, `README.md`, `suites/README.md`, `rules/README.md`, `NOTICE.md`, layout note in `docs/design/rule-test-fixtures.md` | `go test -run Example .`, with `ExampleEngine_Rules`'s output holding. `go doc -all` reviewed. README links resolve. |
| 20 | CI: race, consumer module, Alpine musl, rule-set checks, gorelease | `.github/workflows/test.yml` (race, consumer and musl jobs), new `.github/workflows/rulesets.yml`; new `testdata/modzip/**` and `testdata/consumer/**`; `tools/fetch-opengrep -check-rules` | Every job is green on the PR, including `go mod vendor && go build -mod=vendor` and `-tags bundled,musl` in the consumer, and musl auto-detection in `golang:1.26-alpine` |

After step 20, tag **v0.4.0**. The release notes list:

- "API changes": the new package;
- the new `go install` path and build tags;
- every item of §2.5;
- the licensing notes.
