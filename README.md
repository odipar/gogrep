# gogrep

gogrep is a single executable that wraps [opengrep](https://github.com/opengrep/opengrep)
for offline static analysis. Each release build embeds a pinned opengrep
binary and pinned rule sets (about 2,100 rules), so scans need no internet
access. On top of opengrep, gogrep adds query suites modelled on
[CodeQL's](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/creating-codeql-query-suites)
for choosing which rules run, and reports SARIF results under the name
`gogrep`. The same scans are available to Go programs as a
[library](#use-as-a-go-library).

## Install

Download the executable for your platform from the
[latest release](https://github.com/odipar/gogrep/releases/latest) and check
it against `checksums.txt`:

| File | Platform |
|---|---|
| `gogrep_darwin_arm64`, `gogrep_darwin_amd64` | macOS (Apple Silicon, Intel) |
| `gogrep_linux_amd64`, `gogrep_linux_arm64` | Linux with glibc (Ubuntu, Debian, Fedora, ...) |
| `gogrep_linux_amd64_musl`, `gogrep_linux_arm64_musl` | Alpine and other musl Linux |
| `gogrep_windows_amd64.exe` | Windows |

```sh
chmod +x gogrep_darwin_arm64 && mv gogrep_darwin_arm64 /usr/local/bin/gogrep
```

The executables are not signed. On macOS, a copy downloaded with a browser
needs `xattr -d com.apple.quarantine gogrep` before it will run.

With Go 1.26 or later, build gogrep without opengrep and then download the
opengrep it pins:

```sh
go install github.com/odipar/gogrep/cmd/gogrep@latest && gogrep install-opengrep
```

`gogrep install-opengrep` downloads the opengrep release that
gogrep pins from GitHub into gogrep's cache, checking its SHA-256 against
[opengrep.json](opengrep.json). Without network access, fetch the release
asset (such as `opengrep_osx_arm64` or `opengrep_manylinux_x86`) elsewhere
and run `gogrep install-opengrep --from <file>`, or point `--base-url` at a
mirror of the release assets. gogrep runs the opengrep it finds first:
`$OPENGREP_BIN`, the one built into a release executable, the verified copy
in its cache, or `opengrep` on your `PATH`.

## Usage

All examples run from the root of the project being scanned. gogrep accepts
every `opengrep scan` option (`--json`, `--sarif -o results.sarif`,
`--error`, ...) and passes it through.

### 1. Run one custom rule

Put your own rules in `opengrep/gogrep/rules/`. gogrep loads them as the
`project` rule set:

```yaml
# opengrep/gogrep/rules/go/no-exec-command.yaml
rules:
  - id: no-exec-command
    languages: [go]
    severity: WARNING
    message: Avoid running external commands with exec.Command
    pattern: exec.Command(...)
    metadata:
      category: security
      confidence: HIGH
```

Run just that rule with `--rule`, giving its full id or any ending of it.
gogrep ids are `<rule set>.<directory>.<rule id>`:

```console
$ gogrep scan --rule no-exec-command .
...
    ❯❱ project.go.no-exec-command
          Avoid running external commands with exec.Command

           48┆ cmd := exec.Command(bin, args...)
...
Ran 1 rule on 17 files: 2 findings.
```

`--rule` works the same for bundled rules, e.g.
`--rule dangerous-exec-command`. A `/regex/` selects every rule whose id
matches, e.g. `--rule '/sql-injection/'`. To check which rules a selection
picks without scanning:

```console
$ gogrep rules --rule no-exec-command
ID                          SEVERITY  CATEGORY  CONFIDENCE  LANGUAGES
project.go.no-exec-command  WARNING   security  HIGH        go
1 rule
```

### 2. Run the default suite

With no `--suite`, `--rule` or `--config`, gogrep runs the `code-scanning`
suite. It holds the high-signal security rules (those marked as likely
vulnerabilities with HIGH or MEDIUM confidence), plus all of your own rules:

```console
$ gogrep scan .
Ran 59 rules on 31 files: 2 findings.
```

opengrep only runs the rules that apply to the languages in your project, so
"Ran" counts fewer rules than the suite holds. Choose another built-in suite
with `--suite`, and list them all with their rule counts:

```console
$ gogrep suites
SUITE                    SOURCE    RULES  DESCRIPTION
all                      built-in  2122   Every bundled, gogrep and project rule
code-scanning (default)  built-in  555    High-signal security rules (likely vulnerabilities); gogrep's default
rule-lint                built-in  45     Rule-quality checks for opengrep rule files; gogrep lint runs it
security-and-quality     built-in  2119   Security plus correctness, best-practice, performance and maintainability rules
security-extended        built-in  1613   All security rules, including lower-confidence and audit rules
```

### 3. Run a custom suite

A suite is a YAML file that adds rule sets (`rules`, `import`) and then
filters them on their metadata (`include`, `exclude`). Put project suites in
`opengrep/gogrep/suites/`:

```yaml
# opengrep/gogrep/suites/go-security.yaml
- description: Go security rules, without audit rules
- rules: [bundled, project]   # the pinned rule sets plus your own rules
- include:                    # keep only rules matching all of these keys
    languages: go
    category: security
- exclude:                    # then drop low-confidence rules...
    confidence: LOW
- exclude:                    # ...and every audit rule (a /regex/ on the id)
    id: /\.audit\./
```

Run it by name. A path to a suite file also works:

```console
$ gogrep scan --suite go-security .
Ran 23 rules on 17 files: 2 findings.
```

Suites follow CodeQL's semantics:

- **The first filter sets the default.** After an `include`, only matching
  rules are kept. After an `exclude`, all rules except the matching ones are
  kept.
- **Later filters override earlier ones.**
- **Keys inside one filter must all match.** Separate filters are
  alternatives.
- **Values** can be a list (any value matches) or a `/regex/`.

Filters can match `id`, `severity`, `languages` and any rule metadata, such
as `category`, `subcategory`, `confidence`, `impact`, `cwe`, `owasp` and
`technology`. `import: <suite>` builds on another suite. A project suite
named like a built-in one (e.g. `code-scanning.yaml`) replaces it, so a
project can change its default. See [suites/README.md](suites/README.md) for
the full format.

### 4. Run all rules

```console
$ gogrep scan --suite all .
Ran 492 rules on 31 files: 8 findings.
```

`--gogrep-lang`, `--gogrep-category` and `--gogrep-ruleset` narrow any
selection, e.g. `gogrep scan --suite all --gogrep-lang go .`.

### 5. Test custom rules

`gogrep test` runs regression tests for your rules, modelled on CodeQL's
`codeql test run`. Each test is a fixture: a directory under
`opengrep/gogrep/rules/test/` with a `rule.ref` that names one rule, code
samples, and an `expected.txt` that lists what the rule reports on them.

```
opengrep/gogrep/rules/
├── go/
│   └── no-exec-command.yaml        # rule: project.go.no-exec-command
└── test/                           # fixtures, never loaded as rules
    └── go/                         # namespace, mirrors rules/go/
        └── exec-command/           # fixture: one test
            ├── rule.ref            # the rule under test
            ├── expected.txt        # what it reports (commit it)
            ├── actual.txt          # written when that differs (ignore it)
            ├── sample.go           # every other file is a code sample,
            ├── safe.go
            └── sub/runner_test.go  # subdirectories included
```

Take a variant of the rule from [1. Run one custom rule](#1-run-one-custom-rule)
whose message names the command it finds:

```yaml
# opengrep/gogrep/rules/go/no-exec-command.yaml
rules:
  - id: no-exec-command
    languages: [go]
    severity: WARNING
    message: Avoid running $CMD with exec.Command
    pattern: exec.Command($CMD, ...)
    metadata:
      category: security
      subcategory: [audit]
      confidence: HIGH
      likelihood: LOW
      impact: HIGH
      technology: [go]
```

`opengrep/gogrep/rules/test/go/exec-command/rule.ref` names it. Blank lines
and lines starting with `#` are ignored:

```
# Tests project.go.no-exec-command (resolved within namespace "go").
no-exec-command
```

Next to it go the code samples. `sample.go` has two calls the rule should
flag:

```go
package sample

import "os/exec"

func run(name string) {
	exec.Command(name, "-v")
	_ = exec.Command("ls")
}
```

`sub/runner_test.go` has a third. A scan skips this file (opengrep ignores
`*_test.go` and `test/` by default), but a fixture scans every sample:

```go
package sub

import "os/exec"

func TestRun() { exec.Command("go", "test") }
```

`safe.go` has nothing the rule should flag:

```go
package safe

import "os"

func ok() { os.Getenv("HOME") }
```

Run `gogrep test` from the project root. With no `expected.txt` yet, the
test fails and shows what the rule reports:

```console
$ gogrep test
Executing 1 tests.
[1/1] FAILED(RESULT) opengrep/gogrep/rules/test/go/exec-command
Cannot find expected.txt.
--- expected
+++ actual
@@ -0,0 +1,3 @@
+| sample.go:6:2:6:26 | Avoid running name with exec.Command |
+| sample.go:7:6:7:24 | Avoid running "ls" with exec.Command |
+| sub/runner_test.go:5:18:5:44 | Avoid running "go" with exec.Command |
0 tests passed; 1 tests failed:
  FAILED: opengrep/gogrep/rules/test/go/exec-command
```

The results are also in `actual.txt`. If they are right, `gogrep test accept`
makes them the new `expected.txt`. Commit that file:

```console
$ gogrep test accept
Accepted opengrep/gogrep/rules/test/go/exec-command
$ gogrep test
Executing 1 tests.
[1/1] PASSED opengrep/gogrep/rules/test/go/exec-command
All 1 tests passed.
```

From then on, any change in what the rule reports fails the test. Narrowing
the pattern to `exec.Command($CMD)` loses two matches:

```console
$ gogrep test
Executing 1 tests.
[1/1] FAILED(RESULT) opengrep/gogrep/rules/test/go/exec-command
--- expected
+++ actual
@@ -1,3 +1,1 @@
-| sample.go:6:2:6:26 | Avoid running name with exec.Command |
 | sample.go:7:6:7:24 | Avoid running "ls" with exec.Command |
-| sub/runner_test.go:5:18:5:44 | Avoid running "go" with exec.Command |
0 tests passed; 1 tests failed:
  FAILED: opengrep/gogrep/rules/test/go/exec-command
$ echo $?
1
```

If the change is intended, run `gogrep test accept`, or `gogrep test --learn`,
which writes `expected.txt` right away and prints the diff under `LEARNED`.
Review the change to `expected.txt` like code. `accept` promotes every
`actual.txt` under the paths it is given, whichever run wrote it, and a run
removes `actual.txt` only from the fixtures it includes; so after a run
limited to some paths, give `accept` the same paths.

**How `rule.ref` finds its rule.** gogrep looks the reference up in three
ways, which together must find exactly one rule:

1. a full rule id, such as `project.go.no-exec-command`. This is also how to
   test a bundled or `gogrep` rule, e.g.
   `opengrep-rules.go.lang.security.audit.dangerous-exec-command`;
2. `project.<namespace>.<reference>`, where the namespace is the fixture's
   path below `test/` with `.` for `/` (`go` above);
3. `project.<reference>`.

Unlike `--rule`, a reference never matches just the end of an id, so
renaming or moving a rule cannot make a fixture test a different one. A
reference that matches no rule, or several, fails at `RULE`. Here the same
`rule.ref` sits in `test/misc/exec/`:

```console
$ gogrep test
Executing 2 tests.
[1/2] PASSED opengrep/gogrep/rules/test/go/exec-command
[2/2] FAILED(RULE) opengrep/gogrep/rules/test/misc/exec
  rule reference "no-exec-command" matches no rule; did you mean project.go.no-exec-command?; list candidates with: gogrep rules --rule '/no-exec-command/'
1 tests passed; 1 tests failed:
  FAILED: opengrep/gogrep/rules/test/misc/exec
```

`gogrep rules --rule <reference>` shows the full ids:

```console
$ gogrep rules --rule no-exec-command
ID                          SEVERITY  CATEGORY  CONFIDENCE  LANGUAGES
project.go.no-exec-command  WARNING   -         -           go
1 rule
```

**The `expected.txt` format.** Each result is a row
`| <path>:<startLine>:<startColumn>:<endLine>:<endColumn> | <message> |`, and
the file is the same on macOS, Linux and Windows as long as git checks the
samples out byte for byte (see the line endings tip below):

- The path is relative to the fixture and uses `/`.
- Positions are what opengrep reports, as in `gogrep scan --sarif`: they
  start at 1, the end column is exclusive, and columns count UTF-8 bytes,
  not characters.
- The message has its metavariables filled in.
- Rows are sorted by path, position and message. Duplicates are kept.
- In a cell, `\`, `|`, newline, carriage return and tab are written as `\\`,
  `\|`, `\n`, `\r` and `\t`, and other control characters as `\u00XX`.
- An empty file means the rule reports nothing on the samples.

opengrep's warnings about the samples, such as a syntax error, are recorded
too: the results then come under `#select` and the warnings under
`diagnostics`. With an added `sub/broken.go` that does not parse:

```
#select
| sample.go:6:2:6:26 | Avoid running name with exec.Command |
| sample.go:7:6:7:24 | Avoid running "ls" with exec.Command |
| sub/broken.go:6:2:6:19 | Avoid running "a" with exec.Command |
| sub/broken.go:8:2:8:19 | Avoid running "b" with exec.Command |
| sub/runner_test.go:5:18:5:44 | Avoid running "go" with exec.Command |
diagnostics
| warning | Syntax error | Syntax error at line sub/broken.go:7:\n `:=` was unexpected |
```

**Failures** name the stage that failed:

| Stage | Meaning |
|---|---|
| `SETUP` | The fixture is malformed, e.g. it has no samples, its `rule.ref` is empty, or it has a misspelt `expected.text`. gogrep does not follow symlinks, so a symlink to a directory anywhere under `opengrep/gogrep/rules/test/` (outside a fixture) fails at `SETUP` too, rather than silently skipping the fixtures behind it. Inside a fixture, any symlink fails. |
| `RULE` | `rule.ref` matches no rule or several, or opengrep rejects the rule. |
| `RUN` | opengrep failed, or its output cannot be trusted. |
| `RESULT` | `expected.txt` is missing or differs. |

**Options.** A path selects the fixtures in or below a directory, or the
fixture that holds a file, e.g. `gogrep test opengrep/gogrep/rules/test/go`:

```console
$ gogrep test --help
Usage:
  gogrep test [run] [flags] [path...]   run rule test fixtures
  gogrep test accept [path...]          make each actual.txt the new expected.txt

Paths default to opengrep/gogrep/rules/test and must lie inside it.

Flags (run):
  --learn                  write expected.txt for tests whose results differ
  -j, --threads N          opengrep processes at once (default and 0: CPU count;
                           -N: CPU count minus N)
  --keep-sarif             keep each fixture's raw SARIF as actual.sarif
  --show-opengrep-output   print each fixture's opengrep command and stderr
  --rule, --suite, --gogrep-lang, --gogrep-category, --gogrep-ruleset
                           run only fixtures whose rule is selected

opengrep's own test runner: gogrep opengrep test ...
Exit codes: 0 all passed, 1 a test failed, 2 usage or setup error, 130 interrupted.
```

Finding no tests exits 2, and so does a path that selects none, so a
misconfigured CI job cannot pass without testing anything. After a run of every fixture, gogrep warns on stderr about
`project` rules that no fixture tests:

```
gogrep: warning: 1 project rule has no test fixture:
  project.go.no-os-exit
```

**Tips:**

- **Go projects:** add `opengrep/gogrep/rules/test/go.mod` holding
  `module fixtures`. Samples are often deliberately bad code, and the nested
  module keeps them out of `go build ./...`, `go vet ./...` and
  `go test ./...`.
- **Line endings:** add `opengrep/gogrep/rules/test/.gitattributes` holding
  `* -text`, so git checks samples and expected files out byte for byte on
  every OS. Rules with `pattern-regex` need it: Git for Windows checks text
  files out with CRLF by default, and a regex match that runs to the end of
  a line then includes the carriage return, which changes its end column
  and its message. Structural patterns (checked for Go, YAML and generic
  rules) report the same for CRLF and LF samples.
- **`.gitignore`** the files gogrep writes into fixtures:
  ```
  **/opengrep/gogrep/rules/test/**/actual.txt
  **/opengrep/gogrep/rules/test/**/actual.sarif
  ```
- **Give every fixture a sample the rule flags.** opengrep silently skips a
  sample whose file extension does not fit the rule's languages, so an empty
  `expected.txt` on its own proves nothing.
- **A rule's `paths:` filters see paths relative to the fixture.**
  `exclude: ["*_test.go"]` works on samples as in a scan; a rule with
  `include: ["src/**"]` needs its samples under `<fixture>/src/`.
- **Every sample is scanned,** including those a scan skips: `*_test.go`,
  `vendor/` and `test/` (opengrep's default ignores), and paths that
  `.semgrepignore` or `.gitignore` ignore.

**In CI,** [install](#install) gogrep and run it from the project root:

```yaml
      - name: Test custom rules
        run: gogrep test
```

Each opengrep process needs up to about 265 MB of memory; on a small runner,
`-j 2` runs only two at once.

`gogrep test` replaces opengrep's own `test` command, which gogrep used to
pass through. That annotation-based runner is still available as
`gogrep opengrep test --config <dir> <tests>`.

### 6. Lint custom rules

Suite filters select rules by their metadata, so a rule that lacks a field
a filter asks for, or has a misspelt value, silently drops out of suites
such as the one in [3. Run a custom suite](#3-run-a-custom-suite).
`gogrep lint` finds such mistakes, and others, in your rule files. Take a
rule with no metadata at all:

```yaml
# opengrep/gogrep/rules/go/no-os-exit.yaml
rules:
  - id: no-os-exit
    languages: [go]
    severity: WARNING
    message: Return an error instead of calling os.Exit
    pattern: os.Exit(...)
```

Run `gogrep lint` from the project root. It checks every rule file in
`opengrep/gogrep/rules/`, here this one and the rule from
[5. Test custom rules](#5-test-custom-rules), but never the rule test
fixtures under `test/`, whose samples may be YAML:

```console
$ gogrep lint
opengrep/gogrep/rules/go/no-os-exit.yaml:2:5: opengrep-rules.yaml.semgrep.metadata-category (INFO): This Semgrep rule is missing a valid 'category' field in the 'metadata'. 'category' must be one of 'security', 'correctness', 'best-practice', 'performance', 'maintainability', or 'portability'.
opengrep/gogrep/rules/go/no-os-exit.yaml:2:5: opengrep-rules.yaml.semgrep.metadata-technology (INFO): This Semgrep rule is missing a 'technology' field in the 'metadata'. Consider adding a list of technologies based on the rule's associated library or framework, or another piece of relevant information.
2 problems in 1 of 2 rule files.
$ echo $?
1
```

Each problem is a line `<path>:<line>:<column>: <check> (<severity>): <message>`,
sorted by path, position and check; the summary goes to stderr. The rule
from [1. Run one custom rule](#1-run-one-custom-rule), a security rule with
only `category` and `confidence`, would get four: `metadata-subcategory`,
`metadata-likelihood`, `metadata-impact` and `metadata-technology`. Give
`no-os-exit` the two fields it lacks:

```yaml
    metadata:
      category: best-practice
      technology: [go]
```

```console
$ gogrep lint
No problems in 2 rule files.
```

**Options.** Paths, relative to the current directory, name other rule
files and directories to lint, e.g. `gogrep lint rules/`; a path among the
rule test fixtures is an error. `--suite NAME` lints with another suite, and
`--sarif` writes the problems to stdout as a SARIF log, without the summary.
`gogrep lint` takes no other flags and passes none to opengrep. Exit codes:
0 no problems, 1 problems found, 2 usage or setup error, such as no paths
and no `opengrep/gogrep/rules/`.

**The checks** are the 45 rule-quality rules of opengrep-rules
(`opengrep-rules.yaml.semgrep.*`), which make up the built-in suite
`rule-lint`; `gogrep rules --suite rule-lint` lists them. They look for:

- **Metadata:** `category` (security, correctness, best-practice,
  performance, maintainability or portability) and `technology` on every
  rule; on a security rule, `subcategory` (vuln, audit or secure default),
  `confidence`, `likelihood` and `impact` (LOW, MEDIUM or HIGH); `cwe` in
  the form `CWE-000: Title`, `owasp` in the form `A00:YYYY`, and
  `references` as a list.
- **The rule:** a `languages` field that uses semgrep.dev's language names
  (`go`, not `golang`); a `message` that is present, not empty, on one line
  and without doubled spaces; ids that are unique in their file;
  `interfile: true` under `options` rather than `metadata`, and no unknown
  `options`.
- **Patterns:** duplicate clauses, a `pattern` and `pattern-not` that cancel
  out, a `patterns` or `pattern-either` with a single child, a
  `pattern-either` directly inside another, patterns so general that they
  are slow (a lone metavariable, `$X.$Y`, a leading `...`), and list items
  written `-key`, which YAML reads as one string.

**Changing the checks.** A project suite named `rule-lint` replaces the
built-in one, as for every built-in suite, and `gogrep lint` then runs it.
It cannot import the suite it replaces, which would be an import cycle, so
it repeats the built-in's lines and adds its own filters. To drop the
`technology` check:

```yaml
# opengrep/gogrep/suites/rule-lint.yaml
- description: Rule-quality checks, without the technology check
- rules: bundled
- include:
    id: /^opengrep-rules\.yaml\.semgrep\./
- exclude:
    id: /\.metadata-technology$/
```

```console
$ gogrep suites
SUITE                    SOURCE    RULES  DESCRIPTION
...
rule-lint                project   44     Rule-quality checks, without the technology check
...
```

A suite with another name can import `rule-lint` and filter it, for runs
with `gogrep lint --suite quick-lint`:

```yaml
# opengrep/gogrep/suites/quick-lint.yaml
- description: rule-lint without the slow-pattern checks
- import: rule-lint
- exclude:
    id: /\.slow-pattern-/
```

`rule-lint` is an ordinary suite otherwise: `gogrep scan --suite rule-lint
opengrep/gogrep/rules` runs the same checks as a plain scan, with
opengrep's output and options.

**In CI,** run it next to `gogrep test`:

```yaml
      - name: Lint custom rules
        run: gogrep lint
```

## How gogrep picks rules

- **No rules named:** with no `--config` or `-e`, gogrep runs the selected
  suite (default `code-scanning`) from its bundled rules. `--config bundled`
  does the same explicitly.
- **Your own `--config`:** `gogrep scan --config auto .` or
  `--config my-rules/` is passed to opengrep untouched. `--config auto`
  downloads rules from semgrep.dev and so needs internet. Adding `--suite`
  or `--rule` runs the selected bundled rules as well, as if you had also
  passed `--config bundled`.
- **Rule sets:**
  - `opengrep-rules`, `0xdea` and `semgrep-go`: third-party rules, each
    pinned to a git commit in [opengrep.json](opengrep.json).
  - `gogrep`: rules in this repository's [rules/](rules/README.md).
  - `project`: rules in `opengrep/gogrep/rules/` of the scanned project,
    except `test/` (in any letter case), which holds
    [rule test fixtures](#5-test-custom-rules) and is never loaded as rules.
    Scans that run gogrep's rules (no `--config`, `-e` or `$SEMGREP_RULES`,
    or `--config bundled`, `--suite` or `--rule`) skip it. A scan with only
    your own `--config` scans it like any other directory: opengrep's
    default ignores skip `test/`, but a project `.semgrepignore` replaces
    them, so add `opengrep/gogrep/rules/test/` to it. Point `--config` at single rule
    files rather than at `opengrep/gogrep/rules`, which would load YAML
    samples in fixtures as rules, or use `--gogrep-ruleset project`.
- **Rule ids** are stable (`<rule set>.<directory>.<rule id>`), so results
  keep their identity across machines and rule updates.
- **`gogrep opengrep <args>`** runs the wrapped opengrep with `<args>`
  verbatim: gogrep adds no rules, hands its own flags such as `--rule` to
  opengrep, and leaves SARIF as opengrep wrote it.

## Use as a Go library

Package [`github.com/odipar/gogrep`](https://pkg.go.dev/github.com/odipar/gogrep)
gives Go programs what the command does, with results as data: the SARIF
log and typed findings. It suits a tool that clones repositories and
delegates scanning to gogrep. It needs Go 1.26 and uses only the standard
library and `gopkg.in/yaml.v3`.

```sh
go get github.com/odipar/gogrep@latest
```

```go
eng, err := gogrep.New(gogrep.Config{})
if err != nil {
	return err
}
if _, err = eng.Opengrep(ctx); errors.Is(err, gogrep.ErrNoOpengrep) {
	_, err = eng.InstallOpengrep(ctx, nil) // the only network access; verified against opengrep.json
}
if err != nil {
	return err
}
res, err := eng.Scan(ctx, "/abs/clone", &gogrep.ScanOptions{
	Selection:      gogrep.Selection{Suites: []string{"security-extended"}},
	NoProjectRules: true, // an untrusted clone
	Jobs:           2,
})
if err != nil {
	return err
}
for _, f := range res.Findings {
	fmt.Println(f.RuleID, f.Path, f.StartLine, f.Level, f.Suppressed)
}
```

`Engine` also lists rules (`Rules`) and suites (`Suites`), runs and accepts
a repository's rule test fixtures (`Test`, `AcceptTests`), lints its rules
(`Lint`), and prunes its cache (`PruneCache`). Every method takes an
absolute directory, and the ones that run opengrep take a `context.Context`.
`Lint` is the library's [`gogrep lint`](#6-lint-custom-rules): a `Scan` of
`opengrep/gogrep/rules`, or of `LintOptions.Paths`, with the `rule-lint`
suite, whose findings are the problems:

```go
res, err := eng.Lint(ctx, "/abs/project", nil) // or &gogrep.LintOptions{Paths: []string{"rules"}}
if err != nil {
	return err
}
for _, f := range res.Findings {
	fmt.Printf("%s:%d:%d: %s\n", f.Path, f.StartLine, f.StartColumn, f.RuleID)
}
```

- **Getting opengrep.** The module contains the rule sets but not the
  opengrep binary. An engine runs `Config.Opengrep`, an opengrep the program
  embeds (`Config.EmbeddedOpengrep`), the verified copy in gogrep's cache, or
  an `opengrep` on `PATH` with the pinned SHA-256, in that order.
  `Engine.InstallOpengrep` downloads the pinned release into the cache and
  checks it against [opengrep.json](opengrep.json); `InstallOptions.From`
  installs a local copy of the release asset instead, and
  `gogrep install-opengrep` fills the same cache.
- **Offline.** Only `InstallOpengrep` uses the network. Scans pass
  `--disable-version-check` and remove `SEMGREP_*` and `OPENGREP_*` from
  opengrep's environment.
- **Concurrency and memory.** One `Engine` is safe for concurrent use; share
  it. Each scan takes about 250 to 360 MB, and the engine limits nothing
  itself: to scan N repositories at once, bound N yourself and set
  `ScanOptions.Jobs` so that N × Jobs is about the number of CPUs. A done
  context kills opengrep's whole process tree; the package handles no
  signals and never changes the working directory or the standard streams.
- **Untrusted repositories.** By default a repository's own
  `opengrep/gogrep` rules and suites take part, as with the command. Set
  `NoProjectRules` for clones you do not trust, and `TestOptions.ReadOnly`
  to run their fixtures without writing into them. Findings that `nosemgrep`
  suppresses are kept, with `Suppressed` set.
- **Stability.** The API is new in v0.4.0 and is v0: a minor release may
  change it and lists every change under "API changes" in its release
  notes; a patch release never does. `Command`, `CommandOptions` and `Cmd`
  are experimental. Rule ids stay stable; re-pinning opengrep or a rule set
  happens only in minor releases and can change findings.
- **Licensing.** Go links statically, so a program that imports gogrep
  contains it, and distributing that program as a binary means meeting
  LGPL-2.1's conditions for a work that uses the library: pass on the
  license and notices, gogrep's source, and a way to relink the program with
  a modified gogrep (such as its source or object files). The program also
  contains gopkg.in/yaml.v3 (MIT and Apache-2.0) and the rule sets:
  opengrep-rules carries the Commons Clause, which grants no right to sell a
  product or service whose value derives entirely or substantially from
  those rules. See [NOTICE.md](NOTICE.md).

The [package documentation](https://pkg.go.dev/github.com/odipar/gogrep)
has the details, and [testdata/consumer/main.go](testdata/consumer/main.go)
is a worked example: a command that scans many clones at once and prints
each finding as a JSON line. CI builds and runs it as a module that gets
gogrep with `go get`.

## Building

```sh
go run ./tools/fetch-opengrep                  # download the pinned opengrep
go build -tags gogrep_bundled ./cmd/gogrep     # build ./gogrep with it embedded
go test -tags gogrep_bundled ./...             # unit and integration tests
```

The pinned rule sets are committed in [internal/rulesets](internal/rulesets)
and embedded in every build, with or without `gogrep_bundled`.

On Linux, `-tags gogrep_bundled,gogrep_musl` embeds the musl (Alpine) build
of opengrep instead; fetch it with `go run ./tools/fetch-opengrep
linux/amd64/musl` (or `linux/arm64/musl`). Before v0.4.0 the tags were
`bundled` and `musl`; `-tags bundled` now fails to compile with an error
that names `gogrep_bundled`. On a platform that `opengrep.json` pins no
opengrep for, such as FreeBSD, `-tags gogrep_bundled` builds without one.

The integration tests run the bundled opengrep on the example fixtures in
[testdata/project](testdata/project) and compare the
output with [testdata/golden](testdata/golden). They are skipped with
`-short`, and when the build finds no opengrep of the version pinned in
`opengrep.json`.

`go install github.com/odipar/gogrep/cmd/gogrep@latest` builds gogrep
without the opengrep binary: it has the same bundled rule sets, and runs the
opengrep that `gogrep install-opengrep` puts in its cache, or else the
`opengrep` on your `PATH`. Before v0.4.0 the command was the module root,
`github.com/odipar/gogrep`, which is now a Go package; that path builds
only v0.3.x and older. To move to a newer opengrep, run
`go run ./tools/fetch-opengrep -pin <tag>` and commit `opengrep.json`. To
move a rule set to another commit, change its `commit` in `opengrep.json`,
run `go run ./tools/fetch-opengrep`, and commit `opengrep.json` with the
archive and stamp it writes to `internal/rulesets`; CI checks that each
stamp matches its pin. Pushing a `v*` tag builds and publishes every
platform as a GitHub release.

## License

gogrep is licensed under the GNU Lesser General Public License v2.1, like
opengrep. Every build, and every program that imports the Go package,
contains third-party rule sets and the YAML parser gopkg.in/yaml.v3 under
their own licenses, and release builds also contain opengrep; see
[NOTICE.md](NOTICE.md) and, for Go programs,
[Use as a Go library](#use-as-a-go-library).
