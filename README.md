# gogrep

gogrep is a single executable that wraps [opengrep](https://github.com/opengrep/opengrep)
for offline static analysis. Each release build embeds a pinned opengrep
binary and pinned rule sets (about 2,100 rules), so scans need no internet
access. On top of opengrep, gogrep adds query suites modelled on
[CodeQL's](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/creating-codeql-query-suites)
for choosing which rules run, and reports SARIF results under the name
`gogrep`.

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
Review the change to `expected.txt` like code.

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
the file is the same on macOS, Linux and Windows:

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
| `SETUP` | The fixture is malformed, e.g. it has no samples, its `rule.ref` is empty, or it has a misspelt `expected.text`. gogrep does not follow symlinks, so a symlink anywhere under `opengrep/gogrep/rules/test/` fails at `SETUP` too. |
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

Finding no tests exits 2, so a misconfigured CI job cannot pass without
testing anything. After a run of every fixture, gogrep warns on stderr about
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
  every OS.
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

## How gogrep picks rules

- **No rules named:** with no `--config` or `-e`, gogrep runs the selected
  suite (default `code-scanning`) from its bundled rules. `--config bundled`
  does the same explicitly.
- **Your own `--config`:** `gogrep scan --config auto .` or
  `--config my-rules/` is passed to opengrep untouched. `--config auto`
  downloads rules from semgrep.dev and so needs internet.
- **Rule sets:**
  - `opengrep-rules`, `0xdea` and `semgrep-go`: third-party rules, each
    pinned to a git commit in [opengrep.json](opengrep.json).
  - `gogrep`: rules in this repository's [rules/](rules/README.md).
  - `project`: rules in `opengrep/gogrep/rules/` of the scanned project,
    except `test/`, which holds [rule test fixtures](#5-test-custom-rules), is
    never loaded as rules, and is excluded from gogrep's scans.
- **Rule ids** are stable (`<rule set>.<directory>.<rule id>`), so results
  keep their identity across machines and rule updates.
- **`gogrep opengrep <args>`** runs the wrapped opengrep with `<args>`
  verbatim: gogrep adds no rules, hands its own flags such as `--rule` to
  opengrep, and leaves SARIF as opengrep wrote it.

## Building

```sh
go run ./tools/fetch-opengrep           # download the pinned opengrep and rule sets
go build -tags bundled -o gogrep .      # build with them embedded
go test -tags bundled ./...             # unit and integration tests
```

The integration tests run the bundled opengrep on the example fixtures in
[testdata/project](testdata/project) and compare the
output with [testdata/golden](testdata/golden). They are skipped with
`-short`, and when the build finds no opengrep of the version pinned in
`opengrep.json`.

`go install github.com/odipar/gogrep@latest` builds the plain wrapper instead.
It runs the `opengrep` on your `PATH` and has no bundled rules. To move to a
newer opengrep, run `go run ./tools/fetch-opengrep -pin <tag>` and commit
`opengrep.json`. Pushing a `v*` tag builds and publishes every platform as a
GitHub release.

## License

gogrep is licensed under the GNU Lesser General Public License v2.1, like
opengrep. Release builds bundle third-party components under their own
licenses; see [NOTICE.md](NOTICE.md).
