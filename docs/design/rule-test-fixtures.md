# Custom rule test fixtures

Design for #2.

> **Code layout since this design:** [library-api.md](library-api.md) (gogrep v0.4.0) turned gogrep into a Go library, and its §2 is the current layout. The module root is now package `gogrep`, the public API; the command is `cmd/gogrep`, still `package main`. Where this document names `main.go`'s `main()` or its dispatch, read `cmd/gogrep/main.go` (its tests: `cmd/gogrep/main_test.go`); `rulesargs.go`: the flags in `cmd/gogrep/flags.go`, the listings in `cmd/gogrep/list.go`, and the rule environment, suites and selection in the root's `engine.go` and `selection.go`; `sarif.go`: `cmd/gogrep/sarif.go` and `internal/sarif`; `testcmd.go`: `cmd/gogrep/testcmd.go` and `testreport.go` for the command, and the root's `test.go` (`Engine.Test`) for running fixtures; `procgroup_*.go`: `internal/opengrep` for the process tree and `cmd/gogrep/signals_*.go` for the signals. `internal/ruletest` no longer prints anything, and `Discover` takes the project directory explicitly. The statement in §6.5 that `gogrep scan` ignores SIGINT and SIGTERM is superseded by library-api.md §2.5 item 4: scans now run in a process group of their own, and an interrupted scan exits 130. Its "first run runs alone" gate is replaced by library-api.md §4.6: gogrep unpacks opengrep's runtime once, privately, and publishes it in its cache.

## 1. Summary

`gogrep test` adds regression tests for custom rules, modelled on CodeQL's `codeql test run` and `codeql test accept`.

- **Fixtures.** A fixture is one directory, `opengrep/gogrep/rules/test/<namespace>/<fixture>/`, and it is one test. It contains three things:
  - `rule.ref`, which names exactly one rule;
  - one or more code samples (every other file in the directory, subdirectories included);
  - `expected.txt`, the regression file.
- **What a run does.** gogrep resolves `rule.ref` against its qualified rule ids, such as `project.go.no-exec-command`. It then runs opengrep with only that rule, passing the samples as explicit targets, and reads **only opengrep's SARIF output**. The SARIF is rendered as a sorted CodeQL-style pipe table and compared line by line with `expected.txt`.
- **When a test fails.** gogrep prints a unified diff and writes `actual.txt`. `gogrep test accept` (or `gogrep test --learn`) turns the actual output into the new `expected.txt`.
- **Failure stages.** A failing test is classified as `SETUP` (the fixture is malformed), `RULE` (the reference does not resolve, or opengrep rejects the rule), `RUN` (opengrep failed, or its output cannot be trusted) or `RESULT` (the output differs). Exit codes are 0 when all pass, 1 when any test fails, 2 for usage or setup errors, and 130 when interrupted.
- **Same file on every OS.** The expected output is byte-identical on macOS, Linux and Windows, provided git checks the samples out byte for byte (`* -text`, §2.5):
  - paths are relative to the fixture and use `/`;
  - the sort order is defined explicitly;
  - CRLF in messages is normalised to LF;
  - snippets, fingerprints and tool metadata are left out.
- **Two other changes.** `gogrep test` takes over opengrep's own `test` subcommand, which stays reachable through a new verbatim pass-through, `gogrep opengrep test …`. The `project` rule set stops loading `opengrep/gogrep/rules/test/`, and scans that run gogrep's rules exclude that directory; a scan with the user's own `--config`, `-e` or `$SEMGREP_RULES` is passed on untouched (§7.1).

## 2. Layout and conventions

### 2.1 Directory layout

```
<project root>/                                  # cwd when running gogrep
└── opengrep/gogrep/rules/
    ├── go/
    │   └── no-exec-command.yaml                 # rule: project.go.no-exec-command
    └── test/                                    # test root: reserved, never loaded as rules
        ├── .gitattributes                       # "* -text" (needed for regex rules, §2.5)
        ├── go.mod                               # Go projects only (recommended, §2.5)
        └── go/                                  # <namespace>, mirrors rules/go/
            └── exec-command/                    # <fixture>: one test
                ├── rule.ref                     # which rule this fixture tests
                ├── expected.txt                 # expected results (committed)
                ├── actual.txt                   # written on a RESULT failure (gitignored)
                ├── actual.sarif                 # written only with --keep-sarif (gitignored)
                ├── sample.go                    # code samples ...
                ├── safe.go
                └── sub/runner_test.go           # ... including subdirectories
```

### 2.2 Terms

| Term | Definition |
|---|---|
| Test root | `opengrep/gogrep/rules/test/`, relative to the current directory. This is the same anchor the `project` rule set uses. The last element, `test`, is reserved in any letter case: rule loading skips a `Test/` too, and since scans exclude only `test/`, `gogrep test` refuses a test root whose last element is spelled otherwise (`opengrep/gogrep/rules/Test must be spelled opengrep/gogrep/rules/test`, exit 2), which a case-insensitive file system would otherwise accept. On a case-sensitive file system, a `Test/` directory next to `test/` is refused too (`opengrep/gogrep/rules/Test is reserved: rules in it do not load, and fixtures belong in opengrep/gogrep/rules/test`, exit 2), since nothing reads it. Only `test` is checked: like the `project` rule set itself, the anchor `opengrep/gogrep/rules` is whatever the file system resolves, so an `OpenGrep/` directory on a case-insensitive file system works for `gogrep test` and rule loading, but the scan exclusion, which opengrep matches case-sensitively, does not cover it. |
| Fixture | A directory under the test root that contains an entry named `rule.ref`. Each fixture is one test, and its name is its slash path relative to the cwd, for example `opengrep/gogrep/rules/test/go/exec-command`. |
| Namespace | The path between the test root and the fixture, one or more segments, for example `go` or `go/net`. It mirrors `opengrep/gogrep/rules/<namespace>/` and takes part in resolving the rule (§3.2). |
| Reserved files | At the fixture root: `rule.ref`, and every name that starts with `expected` or `actual`. gogrep reads `expected.txt` and writes `actual.txt` and `actual.sarif`. Any other `expected*` or `actual*` name at the fixture root (for example a misspelt `expected.text`) is a `SETUP` failure, so a typo cannot pass silently. So is a name that differs from `expected.txt`, `actual.txt` or `actual.sarif` only in case (`Expected.txt`), which a case-insensitive file system would read as `expected.txt` and others would not. |
| Ignored files | Anywhere in a fixture: `.DS_Store`, `Thumbs.db` and `desktop.ini` (case-insensitive). At the fixture root: gogrep's own temp files, `.gogrep-*.tmp`. |
| Samples | Every other regular file in the fixture, recursively. That includes hidden files (`.github/workflows/ci.yml`), `*_test.go`, and `vendor/`, `build/` and `test/` subdirectories. Files directly in the test root or in a namespace directory (such as `go.mod` and `.gitattributes`) are not samples. |

One fixture tests one rule, as the issue says ("a test fixture refers to a custom rule"). To test two rules on the same code, create two fixtures.

### 2.3 Fixture checks

Discovery runs these checks before any rule is loaded. Each broken check fails the fixture at `SETUP`, and opengrep is never started for it.

| Check | Message when it fails |
|---|---|
| The fixture lies at least two levels below the test root (`test/<ns>/<fixture>/rule.ref`) | `fixtures live in opengrep/gogrep/rules/test/<namespace>/<fixture>/` |
| `rule.ref` is a regular file, and so are `expected.txt`, `actual.txt` and `actual.sarif` when present | `<name> must be a regular file` |
| The fixture is not inside another fixture (both fail) | `fixture is nested inside <path>` / `fixture contains nested fixture <path>` |
| No other `expected*` or `actual*` files at the fixture root | `unknown regression file <name>; the expected file is expected.txt` |
| No symlinks or other non-regular files among the samples (git on Windows checks symlinks out as text files, so results would differ by OS). `<path>` is relative to the fixture. | `symlinks are not supported in fixtures: <path>`, or for a socket, pipe or device `special files are not supported in fixtures: <path>` |
| At least one sample (opengrep run with no targets scans `.`, verified) | `no code samples` |
| The target arguments total at most 30,000 bytes (Windows' command line limit is 32,767) | `too many sample files (<n>); split the fixture` |
| `rule.ref` syntax (§3.1) | see §3.1 |

A fixture reports the first check it fails, in this order. Discovery parses `rule.ref` too, so `Fixture.Ref` holds the reference; resolving it waits for the rules (§6.1).

**Orphans.** A directory outside every fixture that contains `expected.txt` or `actual.txt` but no `rule.ref` is reported as its own test and fails at `SETUP` with `expected.txt has no rule.ref next to it` (`actual.txt has …` when only that is there). This catches a lost or renamed reference.

**Symlinks outside fixtures.** Discovery does not follow symlinks, so a symlinked fixture or namespace directory would silently hide the fixtures behind it. Every symlink to a directory under the test root that lies outside every fixture is therefore reported as its own test and fails at `SETUP` with `symlinks to directories are not supported in the test root: <path>`, where `<path>` is relative to the test root. A symlink to a file (a shared `go.mod` or `.gitattributes`) or a dangling one hides no fixture and is ignored like any other file outside the fixtures. A test root that is itself a symlink is followed by discovery and skipped when loading rules. A path argument through it (§5.2) selects that test. gogrep never removes files through it. On Windows with `core.symlinks=false`, git checks the link out as a small text file, which lies outside every fixture and is ignored like `go.mod`.

A missing `expected.txt` is **not** a `SETUP` failure. It fails at `RESULT` with `Cannot find expected.txt.`, followed by the diff against an empty file. `actual.txt` is written, as in CodeQL.

### 2.4 Worked example

The rule is the README's rule, with `$CMD` added to the message so the example also exercises metavariable interpolation:

```yaml
# opengrep/gogrep/rules/go/no-exec-command.yaml
rules:
  - id: no-exec-command
    languages: [go]
    severity: WARNING
    message: Avoid running $CMD with exec.Command
    pattern: exec.Command($CMD, ...)
```

`opengrep/gogrep/rules/test/go/exec-command/rule.ref`:

```
# Tests project.go.no-exec-command (resolved within namespace "go").
no-exec-command
```

`sample.go` (indented with a tab):

```go
package sample

import "os/exec"

func run(name string) {
	exec.Command(name, "-v")
	_ = exec.Command("ls")
}
```

`sub/runner_test.go`. A normal scan skips this file because of opengrep's default `*_test.go` and `test/` ignores. As an explicit target it is scanned (§6.2).

```go
package sub

import "os/exec"

func TestRun() { exec.Command("go", "test") }
```

`safe.go`, a negative sample:

```go
package safe

import "os"

func ok() { os.Getenv("HOME") }
```

`expected.txt`. These are the exact values opengrep 1.30.2 reports for these files with the argv from §6.2 (verified):

```
| sample.go:6:2:6:26 | Avoid running name with exec.Command |
| sample.go:7:6:7:24 | Avoid running "ls" with exec.Command |
| sub/runner_test.go:5:18:5:44 | Avoid running "go" with exec.Command |
```

```console
$ gogrep test
Executing 1 tests.
[1/1] PASSED opengrep/gogrep/rules/test/go/exec-command
All 1 tests passed.
```

**A regression.** Change the pattern to `exec.Command($CMD)`. Only the `"ls"` call still matches (verified):

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
$ gogrep test accept          # only if the change was intended
Accepted opengrep/gogrep/rules/test/go/exec-command
```

**A sample with a syntax error.** Add `sub/broken.go`:

```go
package sample

import "os/exec"

func f() {
	exec.Command("a")
	x := := 1
	exec.Command("b")
}
```

opengrep still exits 0 and still reports both parseable matches. It adds a warning notification that has no structured location, with the text `Syntax error at line sub/broken.go:7:\n `:=` was unexpected` (verified). gogrep records the notification, so a sample that stops parsing shows up in review:

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

### 2.5 Project hygiene (documented, not enforced)

- **Go projects** should add `opengrep/gogrep/rules/test/go.mod` (`module fixtures`). Without it, `go build/vet/test ./...` compiles the `.go` samples, and samples are often deliberately bad code. A nested module drops out of `./...`. The file is outside every fixture, so it is neither a sample nor a rule.
- **`opengrep/gogrep/rules/test/.gitattributes`** with `* -text` stops git from converting line endings in samples and expected files, so samples are byte-identical on every OS. Fixtures of rules that use `pattern-regex` (in any language, `regex` included) need it to give the same output everywhere: Git for Windows checks text files out with CRLF by default (`core.autocrlf=true`), and a regex match that reaches the end of a line then includes the CR. Its end column is one higher and a capture ends in `\r`: `| crlf.txt:2:3:2:15 | found [fix it\r] |` against `| lf.txt:2:3:2:14 | found [fix it] |` (verified). Structural patterns, generic ones included, gave the same positions and messages for CRLF and LF samples (verified for Go, YAML and generic rules), so for them gogrep's normalisation of CRLF inside messages (§4.4) is enough. gogrep does not check the attribute: a CRLF sample may be deliberate, and only git knows how it was checked out.
- **`.gitignore`** should contain:
  ```
  **/opengrep/gogrep/rules/test/**/actual.txt
  **/opengrep/gogrep/rules/test/**/actual.sarif
  ```
- **Every fixture needs at least one positive sample.** opengrep silently skips an explicit target whose extension does not fit the rule's language: a Go rule on `x.gotmpl` gives `results: []` and no notification, and SARIF has no `artifacts` list (verified). An empty `expected.txt` on its own therefore proves nothing.
- **The fixture directory is the root for the rule's `paths:` filters.** Rule-level `paths.exclude: ["*_test.go"]` applies to explicit targets (verified). A rule with `paths.include: ["src/**"]` needs its samples under `<fixture>/src/`.

## 3. How a fixture refers to a rule

### 3.1 The `rule.ref` format

- UTF-8. A leading BOM is stripped, and CRLF is accepted.
- Blank lines are ignored, and so are lines whose first non-space character is `#`.
- Exactly one line must remain. Its trimmed text is the reference.

Each of these is a `SETUP` failure:

| Content | Message |
|---|---|
| UTF-16: a UTF-16 byte order mark or a NUL byte, as Windows PowerShell 5.1 writes for `echo no-exec-command > rule.ref` | `rule.ref must be UTF-8 text (found UTF-16)` |
| Other bytes that are not UTF-8 | `rule.ref must be UTF-8 text` |
| Nothing left | `rule.ref is empty` |
| Two or more lines | `rule.ref has <n> references; a fixture tests exactly one rule` |
| `/regex/` | `a fixture must name one rule, not a /regex/` |
| A line containing `: ` | `unsupported option "<line>" in rule.ref` (reserved for a future `key: value` form) |

### 3.2 Resolution

References resolve against the same `loadEnv()` that `gogrep scan` uses: the bundled sets (in bundled builds), `gogrep`, and `project` with `test/` skipped (§7.1). Qualified ids are `<set>.<dir with / replaced by .>.<id>`. When two rules in a directory share an id, the second becomes `<set>.<dir>.<file>.<id>`.

Given reference `R` and the fixture's namespace `ns`, written with dots (`go/net` becomes `go.net`), gogrep evaluates **all three** steps and collects the distinct rules they find:

| Step | Matches | Purpose |
|---|---|---|
| 1 | a rule in any loaded set whose id is exactly `R` | Full ids. This is also the only way to test `gogrep` or bundled rules, such as `opengrep-rules.go.lang.security.audit.dangerous-exec-command`. |
| 2 | `project.<ns>.<R>` | Relative to the fixture's namespace: the usual short form. |
| 3 | `project.<R>` | Relative to the project set root, the way a `.qlref` path is relative to its pack root. |

Ids are compared exactly and case-sensitively. **There is no suffix matching.** `--rule` accepts any id suffix, but a fixture does not, so it can never quietly start testing a different rule after a rename or move.

| Rules found | Outcome |
|---|---|
| exactly one | That rule is tested. |
| two or more | `RULE`: `rule reference "<R>" is ambiguous: <id1>, <id2>; write the full id` |
| none | `RULE`: `rule reference "<R>" matches no rule`, then `; did you mean <id>, …?` listing up to five rules whose id ends in `.<R>` (case-insensitive, sorted), then `; list candidates with: gogrep rules --rule '/<R>/'`. When the build has no bundled sets (no loaded rule outside `project` and `gogrep`), `; this gogrep build has no bundled rule sets` is added. |

Examples, given the project rules `project.go.no-exec-command`, `project.go.net.dial` and `project.net.dial`:

| Fixture | `rule.ref` | Result |
|---|---|---|
| `test/go/exec-command` | `no-exec-command` | step 2 → `project.go.no-exec-command` |
| `test/misc/x` | `go.no-exec-command` | step 3 → `project.go.no-exec-command` |
| any | `project.go.no-exec-command` | step 1 |
| `test/go/net/dial-basic` | `dial` | step 2 → `project.go.net.dial` |
| `test/go/y` | `net.dial` | steps 2 and 3 → ambiguous (`project.go.net.dial`, `project.net.dial`) |
| `test/misc/z` | `no-exec-command` | none → did you mean `project.go.no-exec-command`? |

### 3.3 Load failures

- **gogrep cannot parse a rule YAML file.** This aborts `loadEnv()` for every set, which is existing behaviour shared with `scan`, `rules` and `suites`. `gogrep test` then exits **2** with the existing message, for example `gogrep: project/go/x.yaml: yaml: …`. That is a setup error, not N test failures.
- **gogrep parses the rule but opengrep rejects it.** Examples are a schema error, an unknown language, an invalid pattern, an unknown `options:` key or a `min-version` above the binary's. The fixture fails at `RULE`, showing opengrep's notifications (§6.3).

## 4. The expected-file format

### 4.1 Source data: SARIF only

Every value comes from the single run in the SARIF document that opengrep writes to stdout. opengrep's native `--json` is never requested or read.

| Column | SARIF field |
|---|---|
| path | `results[].locations[0].physicalLocation.artifactLocation.uri`, normalised (§4.3) |
| `sl:sc:el:ec` | `region.startLine`, `startColumn`, `endLine`, `endColumn`, copied unchanged |
| message | `results[].message.text` (opengrep has already interpolated the metavariables) |
| diagnostics | `invocations[].toolExecutionNotifications[]` whose level is not `error`: `level`, `descriptor.id`, `message.text` |

These fields are deliberately left out:

| Field | Reason |
|---|---|
| `ruleId` | Every row of a fixture belongs to one rule, so the column would be redundant, and moving the rule to another namespace would rewrite every row. gogrep still checks it (§6.3). |
| `snippet.text` | It depends on the locale: without a UTF-8 locale, non-ASCII bytes become U+FFFD. It also repeats whole sample lines. |
| `fingerprints` | They change when the uri changes, and nobody can read them. |
| `tool.driver.*`, `properties`, `fixes`, severity | Rule or tool metadata, not results. `fixes` only appear with `--autofix --dryrun`, which v1 does not use. |

### 4.2 Grammar

```
file         = plain / sectioned
plain        = *( result-row LF )                     ; no diagnostics; an empty file means nothing reported
sectioned    = "#select" LF *( result-row LF )
               "diagnostics" LF 1*( diag-row LF )
result-row   = "| " location " | " cell " |"           ; location | message
location     = cell ":" num ":" num ":" num ":" num   ; path:startLine:startColumn:endLine:endColumn
diag-row     = "| " level " | " cell " | " cell " |"  ; level | descriptor.id | message
level        = "warning" / "note" / "none"            ; a missing level is written as "warning" (SARIF's default)
num          = %x31-39 *DIGIT                          ; positive decimal, no leading zeros
cell         = *( plain-char / escape )
plain-char   = any valid UTF-8 character except "\", "|", %x00-1F, %x7F
escape       = "\\" / "\|" / "\n" / "\r" / "\t" / "\u00" 2HEXUP / "\x" 2HEXUP
```

- **Headers.** As in CodeQL, a section header is printed only when there is more than one result set. The sets come in the fixed order `#select`, then `diagnostics`. When there are diagnostics, `#select` is printed even if it has no rows.
- **Empty versus missing.** An empty `expected.txt` (0 bytes) is a valid "no findings, no diagnostics" test. A missing `expected.txt` is a `RESULT` failure.
- **Not parsed.** gogrep never parses the file; it only compares it (§4.6). A path that contains `:` is therefore harmless.

### 4.3 Positions and paths

- **Positions are copied exactly as opengrep reports them.**
  - They are 1-based, and `endColumn` is **exclusive**. They match what `gogrep scan --sarif` shows.
  - Columns count **UTF-8 bytes**: after `"héllo→"` a match starts at byte column 32, not character column 29 (verified).
  - CRLF and LF samples give the same positions for structural patterns, generic ones included (verified). A `pattern-regex` match that reaches the end of a line includes the CR, which makes its end column one higher (§2.5).
  - Treat positions as opaque numbers that the fixture pins down.
  - A result with a region field that is missing or 0 fails at `RUN` (§6.3).
- **Paths are relative to the fixture directory and use `/`**, because opengrep runs with the fixture as its working directory and relative targets (§6.2). The uri is normalised in this order:
  1. On Windows only, replace `\` with `/`. This is defensive: Windows output is unverified, and CI covers it. On macOS and Linux `\` is an ordinary file name character, so a sample `a\b.txt` stays distinct from `a/b.txt`.
  2. Strip a leading `./`. opengrep already strips it from `./sub/broken.go` (verified).
  3. Clean the path (`path.Clean`).
  4. Never percent-decode. opengrep writes `sub dir/a b.go` raw (verified).

  The result must be exactly one of the fixture's samples. Any other uri (absolute, outside the fixture, a URL, or a file gogrep did not pass) fails the fixture at `RUN`. Comparing with the samples needs no drive-letter or URL heuristics, so a sample in a Unix directory named `c:` works.
- **Paths inside diagnostic messages.** On Windows only, each occurrence of a sample's native path (`sub\broken.go`, with or without a leading `.\`) is replaced by its slash form, so that expected files stay identical across operating systems. On macOS and Linux this is a no-op: the message already reads `sub/broken.go` (verified).

### 4.4 Escaping

Every cell is escaped: path, message, descriptor id and diagnostic message. First, `\r\n` in the raw string is normalised to `\n`. Then each character is written as follows:

| Input | Written as |
|---|---|
| `\` | `\\` |
| `\|` | `\|` |
| LF | `\n` |
| CR | `\r` |
| TAB | `\t` |
| any other C0 control (U+0000–U+001F) or DEL | `\u00XX` (uppercase hex) |
| a byte that is not valid UTF-8 | `\xHH` (uppercase hex) |
| any other character | itself |

- **Why `\` is escaped.** Escaping it gives every row exactly one reading. CodeQL's handling of `\` was not established, but gogrep needs this either way.
- **Why CRLF is normalised first.** A multi-line metavariable binding taken from a sample that git checked out with CRLF would otherwise give different expected text on Windows. opengrep keeps the CR in such a binding (verified). This covers CR LF pairs only: a regex capture that ends at a line's CR keeps it as `\r`, and its end column differs as well, so regex fixtures need samples checked out byte for byte (§2.5).
- **`\xHH` is defensive.** opengrep 1.30.2 writes U+FFFD for bytes in a sample that are not UTF-8 (verified), and Go's JSON decoder does the same, so decoded SARIF never contains them.

Example: the message `bad a|b` followed by a newline, a tab and `c` is written `bad a\|b\n\tc`.

### 4.5 Sorting

- **Result rows** sort by:
  1. the normalised, unescaped path, bytewise;
  2. then `startLine`, `startColumn`, `endLine` and `endColumn`, numerically;
  3. then the normalised, unescaped message, bytewise.

  Duplicate rows are kept, because a rule that suddenly matches twice is a regression.
- **Diagnostic rows** sort bytewise by the whole rendered row.
- **Why gogrep defines its own order.** opengrep's own order is deterministic (uri, line, column, ruleId, and identical for any `-j`), but gogrep does not rely on it. CodeQL's order is internal and undocumented (`a2.js` sorts before `a.js`), so gogrep defines its own.

### 4.6 Writing, reading, comparing

- **Writer.** UTF-8 with no BOM, LF line endings, and a trailing LF on every row. No rows and no diagnostics give a 0-byte file.
- **Reader.** Applied to `expected.txt`:
  1. Strip a UTF-8 BOM.
  2. Replace CRLF with LF.
  3. Split on LF.
  4. Drop trailing empty lines.

  A missing final newline therefore does not matter, as in CodeQL.
- **Comparison.** The lines must be equal and in the same order. A hand-edited row in the wrong order is a mismatch, and `accept` fixes it.
- **Diff.** On a mismatch gogrep prints a unified line diff:
  - headers `--- expected` and `+++ actual`, then hunks `@@ -a,b +c,d @@`;
  - counts are always printed, and an empty range starts at the line before it, as GNU diff does (an empty file gives `-0,0`);
  - 3 lines of context, and hunks less than 7 unchanged lines apart are merged, as GNU diff does;
  - within a change, the deleted lines come before the inserted ones;
  - a Myers diff (the linear-space variant) implemented with the standard library only.

### 4.7 Why a table

A SARIF expected file would carry fingerprints, driver metadata, the opengrep version and whole-line snippets. Those change for reasons unrelated to the rule and make review diffs unreadable. The table keeps only what the rule decides (where it matches and what it says) plus everything opengrep reported about the samples.

## 5. CLI

### 5.1 The `test` name and opengrep's own `test`

Today `gogrep test …` is forwarded to `opengrep test`, minus any `--suite` or `--rule`. With this change, `gogrep test` becomes gogrep's runner, which mirrors `codeql test run` and `codeql test accept`. This is reasonable because opengrep's runner does not fit gogrep (§9.1):

- its machine-readable output is native `--json` only;
- `opengrep test --sarif` is an unknown option;
- its text report is unfinished.

opengrep's runner stays reachable through a new pass-through:

```
gogrep opengrep <args...>                        # the resolved opengrep binary, args verbatim
gogrep opengrep test --config ./rules ./tests    # opengrep's annotation-based runner
```

The pass-through is handled in `main.go` **before** `gogrepFlags`. Nothing is stripped, no config is injected, and no SARIF is rebranded. stdio is passed through, `utf8Env` applies, and the exit code is the child's. `gogrep scan --test --config ./rules ./tests` also reaches opengrep's runner, because gogrep passes a user's own `--config` on untouched (verified). It is not the documented route, though: the runner needs a directory config, and when gogrep adds its own config (no `--config`, `--config bundled`, `--rule` or `--suite`), that config is a file, with which the runner crashes with an `IndexError` (verified). With the target `.` instead of a test directory it prints "No unit tests found" (verified). The pass-through runs it with nothing added.

### 5.2 Synopsis and paths

```
gogrep test [run] [flags] [path...]
gogrep test accept [path...]
```

- `run` is the default subcommand. `run` and `accept` are subcommands only as the first argument after `test`.
- **Path arguments.** Paths may be relative or absolute, written with `/` or `\`. Each must lie inside `opengrep/gogrep/rules/test` relative to the cwd after cleaning:
  - a directory selects every fixture under it, searched recursively, or the fixture that contains it;
  - a file (`rule.ref`, `expected.txt`, a sample) selects the fixture that contains it.

  With no paths, the whole test root is used. A path that does not lie inside the test root as written is still accepted when a leading part of it is the test root's directory, reached through symlinks: on macOS `/tmp` and `/var` are symlinks into `/private`, so the cwd `/tmp/p` and an editor's resolved path `/private/tmp/p/…` name the same directory. gogrep compares directories (`os.SameFile`), takes the shortest such leading part, and so never follows a symlink below the test root.
- **Usage errors (exit 2):**
  - a path outside the test root: `<path> is not under opengrep/gogrep/rules/test`;
  - a nonexistent path: `<path> does not exist`;
  - a missing test root: `no opengrep/gogrep/rules/test directory here; run gogrep test from the project root`;
  - a path that selects no test, even next to paths that do: `no tests found under <path>, …`, listing each such path. With no paths, an empty test root gives `no tests found under opengrep/gogrep/rules/test`. A CI step that silently ran nothing would be a false green, and so would one that silently dropped a mistyped path: on a case-insensitive file system `…/test/GO/exec-command` exists but names no fixture.
- **The display name** of each fixture is its clean slash path relative to the cwd.

### 5.3 Flags for `run`

| Flag | Meaning |
|---|---|
| `--learn` | For a `RESULT` failure (including a missing `expected.txt`), write the actual output to `expected.txt`, delete `actual.txt`, and report `LEARNED` followed by the diff, so the change shows in CI logs. Learned tests count as passed. Failures at other stages still fail. When `expected.txt` cannot be read or written, the test still fails at `RESULT` and writes `actual.txt`, as without `--learn`, so `accept` never promotes an earlier run's output in its place. |
| `-j N`, `--threads N` (also `=N`) | Number of opengrep processes at once. The default and `0` both mean `runtime.NumCPU()`. `-N` means NumCPU − N, at least 1. Each process peaks at about 265 MB RSS (measured), so small CI runners can pass `-j 2`. |
| `--keep-sarif` | Write each fixture's raw opengrep stdout to `<fixture>/actual.sarif`, not rebranded, mode 0o600. This is the counterpart of CodeQL's `--keep-databases`. Without the flag, a stale `actual.sarif` is deleted. |
| `--show-opengrep-output` | After each fixture's report, print its opengrep command line with the directory it ran in (`  $ (cd <fixture> && <opengrep binary> scan …)`, quoted for a POSIX shell, so that pasting it where `gogrep test` ran repeats the run) and its captured stderr, each line prefixed with `  > `, without blank lines at the start or end. Output is buffered per fixture, so parallel runs never interleave. CodeQL warns that its own equivalent interleaves. |
| `--rule`, `--suite`, `--gogrep-lang`, `--gogrep-category`, `--gogrep-ruleset` | These are parsed by the existing `gogrepFlags`, wherever they appear, and choose fixtures by their **resolved** rule. The selection is the union of `--suite` and `--rule` (all rules if neither is given; **no default suite**), narrowed by the `--gogrep-*` filters. A fixture is left out only when its rule resolved to a rule outside the selection. Fixtures that fail at `SETUP` or `RULE` always run, so a typo is never hidden. A selection that matches no rules exits 2 with the existing message. A selection that keeps no fixtures exits 2: `no tests match the selection`. |
| `-h`, `--help` | Print usage and exit 0. |

- **Flag syntax.** Flags may come before or after paths, as `--x v` or `--x=v`.
- **Unknown flags.** An unknown flag exits 2 with `unknown flag <f>; gogrep test does not forward flags to opengrep`. Every argument that starts with `-` is a flag; `-j` and `--threads` take the next argument as their value even when it starts with `-`.
- **`accept`.** It takes paths only, plus `-h`. Any other flag given to `accept`, a selection flag included, exits 2.

Usage text:

```
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

### 5.4 Text output

The report goes to stdout. gogrep errors and warnings go to stderr.

- **Order.** Fixtures are reported in sorted order whatever `-j` is. A fixture is printed once it and every earlier fixture have finished.
- **No timings**, so CI logs can be diffed between runs.

```
Executing 4 tests.
[1/4] PASSED opengrep/gogrep/rules/test/go/exec-command
[2/4] FAILED(RESULT) opengrep/gogrep/rules/test/go/exec-command-args
--- expected
+++ actual
@@ -1,2 +1,2 @@
 | a.go:5:2:5:20 | Avoid running "ls" with exec.Command |
-| a.go:6:2:6:24 | Avoid running cmd with exec.Command |
+| a.go:6:2:6:30 | Avoid running cmd with exec.Command |
[3/4] FAILED(RULE) opengrep/gogrep/rules/test/db/raw-sql
  rule reference "no-raw-sql" matches no rule; did you mean project.sql.no-raw-sql?; list candidates with: gogrep rules --rule '/no-raw-sql/'
[4/4] LEARNED opengrep/gogrep/rules/test/yaml/privileged
--- expected
+++ actual
@@ -0,0 +1,1 @@
+| pod.yaml:7:9:7:25 | Container runs privileged |
2 tests passed; 2 tests failed:
  FAILED: opengrep/gogrep/rules/test/db/raw-sql
  FAILED: opengrep/gogrep/rules/test/go/exec-command-args
```

- **Status lines.** Each status line is `[i/n] PASSED|LEARNED|FAILED(SETUP|RULE|RUN|RESULT) <fixture>`.
- **Details.** A `RESULT` failure or a `LEARNED` test is followed by its diff. Other failures are followed by their description, indented two spaces.
- **Missing `expected.txt`.** It prints `Cannot find expected.txt.`, then the diff against an empty file. A test that `--learn` learned prints only the diff.
- **Final line.**
  - When all tests pass: `All N tests passed.`, or `All N tests passed (L learned).` when some were learned.
  - Otherwise: `P tests passed; F tests failed:`, followed by the sorted `  FAILED: <fixture>` lines.
  - The word "tests" is always plural, as in CodeQL.
- **Untested rules.** After a **full** run, meaning no path arguments, no selection flags and no interrupt, gogrep lists the `project` rules that no fixture resolves to. The list goes to stderr and does not change the exit code:
  ```
  gogrep: warning: 1 project rule has no test fixture:
    project.go.no-os-exit
  ```

| Stage | Meaning |
|---|---|
| `SETUP` | The fixture is malformed (§2.3, §3.1). |
| `RULE` | The reference is missing or ambiguous (§3.2), or opengrep did not load the rule (§6.3). |
| `RUN` | opengrep failed, or its output cannot be trusted (§6.3). |
| `RESULT` | `expected.txt` is missing or differs. |

### 5.5 `gogrep test accept`

- For each selected fixture that has `actual.txt`, gogrep renames it to `expected.txt` (replacing the old file), sets the mode to 0o600, and prints `Accepted <fixture>`.
- Fixtures without `actual.txt` are skipped silently, as in CodeQL. So are fixtures that fail at `SETUP`: `gogrep test` deletes their `actual.txt`, so any left is stale.
- `accept` does not check which run wrote an `actual.txt`. A run deletes `actual.txt` only in the fixtures it includes (§6.4), so after `gogrep test a` and then `gogrep test b`, `gogrep test accept` still promotes the `actual.txt` that the first run left in `a`. Pass `accept` the paths of the run whose results were reviewed.
- It never loads rules and never runs opengrep.
- It exits 0, or 2 on a usage error or a failed rename.

### 5.6 Exit codes

| Code | When |
|---|---|
| 0 | Every selected test passed or was learned, or `accept` finished. |
| 1 | At least one test failed, at any stage. |
| 2 | gogrep could not run the tests: a usage error, no tests found or selected, a missing test root, rule sets that fail to load, the opengrep binary not found, or an I/O error writing `actual.txt`, `expected.txt` or `actual.sarif` (the remaining tests still run and report). This follows gogrep's existing convention that a `gogrep: …` error exits 2. A missing binary is 2 here, although `scan` returns 1, because for `test` the code 1 must mean only "a test failed". |
| 130 | Interrupted by SIGINT or SIGTERM, or on Unix by SIGHUP or SIGQUIT (§6.5). |

## 6. Execution

### 6.1 Pipeline

1. **Discover.** Parse the arguments (selection flags are already stripped by `gogrepFlags`). Find fixtures under the selected paths, sort them bytewise by slash path, and run the §2.3 checks, which include parsing `rule.ref`. Sample lists are slash paths relative to the fixture, sorted bytewise.
2. **Load.** Call `loadEnv()` once. A failure exits 2.
3. **Resolve, sequentially.** Resolve every parsed `rule.ref` (§3.2), then apply the selection filter (§5.3). `SETUP` and `RULE` failures found here never start opengrep.
4. **Prepare, sequentially.** When at least one test reaches opengrep, call `opengrepBin()` once, which may extract the bundled binary. Resolve its result with `exec.LookPath` and `filepath.Abs`, and check that it is a regular file: every run has its fixture as working directory, where a relative `$OPENGREP_BIN` would name another file. An error, a missing binary included, exits 2. A run in which every test fails at `SETUP` or `RULE` needs no opengrep. Then call `rules.Write([]*rules.Rule{r})` once for each distinct resolved rule. This produces an absolute, content-addressed, 0o600 config in which `id` is already the qualified id. An error exits 2.
5. **Run.** A pool of `-j` workers runs one opengrep process per fixture (§6.2) and classifies each result (§6.3).
6. **Report, sequentially and in sorted order.** Render the table, compare it, write or delete `actual.txt`, `expected.txt` and `actual.sarif` (§6.4), and print each fixture's report. Then print the summary and the untested-rules warning, and exit.

### 6.2 The opengrep invocation

```
cmd.Dir   = <fixture directory>                     (OS path)
cmd.Env   = utf8Env(os.Environ())
cmd.Stdin = none; stdout and stderr captured in buffers
argv      = <opengrep> scan
              --config <absolute path from rules.Write>
              --no-rewrite-rule-ids
              --sarif
              --disable-version-check
              --timeout 0
              -j 1
              --
              ./<sample> ./<sample> ...              ("." + os.PathSeparator + filepath.FromSlash(p), sorted)
```

| Choice | Reason |
|---|---|
| cwd = fixture | Result uris and the paths in syntax-error messages come out relative to the fixture, and the rule's `paths:` filters see fixture-relative paths (verified). |
| Explicit sample targets | Explicit targets are scanned whatever the default `.semgrepignore` says (`test/`, `*_test.go`, `vendor/`, `build/`), whatever a project or fixture `.semgrepignore` or `.gitignore` says, and whether or not git tracks the file (all verified). This avoids `--x-ignore-semgrepignore-files` ("[INTERNAL] … MAY CHANGE OR DISAPPEAR", with a warning on every run) and `--no-git-ignore`. Reserved files are never targets, so `generic` and `regex` rules cannot match `expected.txt`; with a directory target they do (verified). |
| `--` and `./` | A sample named `-x.go` is never read as a flag. opengrep strips `./` from the uris (verified). |
| Absolute `--config` | A relative config starting with `r/`, `p/` or `s/` is read as a registry shorthand, and `p/…` makes a network request (verified). |
| `--no-rewrite-rule-ids` | Without it, opengrep prefixes the config file's directory to the rule id. |
| `--sarif` on stdout | `-o` creates the file with mode 0644, which breaks the owner-only rule. stdout carries the same JSON (verified). |
| `--disable-version-check` | Guarantees no version-check network call. The flag exists in 1.30.2 (verified). |
| `--timeout 0` | Turns off opengrep's wall-clock limit per rule and file (5 s by default). A run that hits it reports a warning-level `Timeout` notification and drops that file's results, so the expected output would depend on the machine's speed and load: a fixture learned on a fast laptop could fail on a slow CI runner (verified with a 3.6 MB sample). The cost is that a sample on which the rule never finishes hangs the run until it is interrupted. |
| `-j 1` | gogrep parallelises across fixtures. opengrep's results are identical for any `-j` (verified). |
| `utf8Env` | Messages and rule files stay UTF-8 (`LC_ALL=C.UTF-8` or `PYTHONUTF8=1`). |
| Never passed | `--autofix` (rewrites samples), `--strict` (turns syntax warnings into exit 3), `--error`, `-q` (stderr is useful in failure reports), `--scan-unknown-extensions` (fixtures should behave like a real scan), any `--x-*` flag, `-o`, `--json`. |

stderr is shown for failures and with `--show-opengrep-output`, but it is never parsed. It is unreliable anyway: opengrep's verbose log says `Ignoring sub/runner_test.go due to .semgrepignore` while still scanning that explicit target and reporting its match (verified).

### 6.3 Classifying a run

Opengrep reports `executionSuccessful: true` even on fatal config errors (verified), so gogrep never relies on it. The checks run in this order, and the first that applies decides the stage:

| # | Condition | Stage | Description shown |
|---|---|---|---|
| 1 | The process could not start or was killed. stdout is not JSON SARIF with `version` `2.1.0` and exactly one run. A result has no location, an incomplete region, or a uri that names no sample (§4.3). | `RUN` | The cause, the exit code, and the last 20 stderr lines. |
| 2 | The exit code is 7 (invalid YAML or schema) or 8 (unknown language), or the resolved id is not in `tool.driver.rules[].id` and no error-level `SemgrepError` notification starts with `File not found:`. An invalid pattern exits 2 with a `Rule parse error` notification and drops just that rule. An options key or a `metavariable-pattern` language that opengrep-core rejects exits 2 with an empty `driver.rules` and a `SemgrepError` that starts `Error while matching` and quotes opengrep-core's error and stack trace. A `min-version` above the binary's exits 7 with a note-level `Incompatible rule` notification next to a `SemgrepError` that says only `No config given` (all verified). A crash of opengrep-core while matching would read like a rejected rule and is labelled `RULE` too; its description shows the cause either way. | `RULE` | Each notification, of any level, in the order opengrep reports them, as `<descriptor.id>: <message>`. |
| 3 | Any other non-zero exit code, or any error-level notification. A missing target exits 2 and empties `driver.rules` too, but its `SemgrepError` reads `File not found: missing.go` (verified); gogrep passes only the samples it has just found, so this needs a sample removed during the run. | `RUN` | The error-level notifications, the exit code, and the stderr tail. |
| 4 | A result whose `ruleId` is not the resolved id. | `RUN` | `unexpected rule id <x>` |
| 5 | Otherwise: render the table (§4) and compare it with `expected.txt`. | `RESULT` on a mismatch | The diff, or the error when `expected.txt` exists but cannot be read. |

In descriptions, each line of stderr is prefixed with `> `, blank lines at the start and end are dropped, and the exit code reads `opengrep exited with code <n>`. When row 2 applies without error-level notifications, the description starts with `opengrep did not load rule <id>` and ends with the stderr tail.

**Warning- and note-level notifications become `diagnostics` rows, not failures.** Some samples are intentionally partial code. A sample that unexpectedly stops parsing, though, silently loses matches near the error. Recording the notification makes both cases visible and reviewable. The cost: an opengrep upgrade that rewords a parser message changes `expected.txt`, and that change is reviewed in the pin-bump PR.

### 6.4 Files written into fixtures

| File | When | How |
|---|---|---|
| `actual.txt` | The fixture fails at `RESULT`: without `--learn`, or with `--learn` when `expected.txt` could not be read or written. | Written atomically, 0o600. |
| `actual.txt` (stale) | Deleted whenever a run includes the fixture and it does **not** fail at `RESULT` (passed, learned, `SETUP`, `RULE`, `RUN`), so `accept` never promotes output older than the latest run that included the fixture. A run that leaves the fixture out (other paths, a selection flag, an interrupt before it) leaves its `actual.txt` alone (§5.5). | — |
| `expected.txt` | Written by `--learn` for a `RESULT` failure, or renamed from `actual.txt` by `accept`. | Atomic write or rename, then 0o600. |
| `actual.sarif` | Written with `--keep-sarif` for every fixture whose opengrep run produced output. A stale one is deleted otherwise. | Written atomically, 0o600. |

- **Atomic write.** `os.CreateTemp(fixtureDir, ".gogrep-*.tmp")`, write, close, `Chmod(0o600)`, then `Rename` over the target, removing the temp file on error. `os.Rename` replaces existing files on Windows too.
- **Ignored by discovery.** Discovery skips `.gogrep-*.tmp` files, so a leftover temp file never becomes a sample.
- **Only the reporter writes.** All writes happen in the sequential reporting phase.
- **Directories are left alone.** A directory named `actual.txt` or `actual.sarif` is never deleted; discovery already fails the fixture at `SETUP` for it (§2.3).

### 6.5 Parallelism and interrupts

- **Workers.** `-j` workers take fixtures in sorted order. Each worker runs `exec.CommandContext` with a short `WaitDelay`.
- **The first run runs alone.** On its first run, opengrep 1.30.2 unpacks its Python runtime (about 245 MB) into `~/.cache/opengrep/v1.30.2/`, and a run that starts meanwhile can crash with SIGBUS. With an empty cache, two of four parallel runs died this way (exit 138), while eight parallel runs with the cache in place all succeeded (verified). CI runners start with an empty cache, so the first fixture's run ends before any other starts. This costs one run's time when the cache is already there.
- **Interrupts.** `gogrep scan` ignores SIGINT and SIGTERM so that its single child gets Ctrl-C. `gogrep test` instead **catches** them with `signal.NotifyContext`, and on Unix also SIGHUP (a closed terminal or a dropped ssh session) and SIGQUIT (`Ctrl-\`). A signal that gogrep was started with ignored, such as SIGHUP under `nohup`, stays ignored. When a signal arrives:
  - gogrep cancels the context, so no new run starts and every running opengrep is killed together with the processes it started. opengrep's launcher passes no kill on to `opengrep-cli` and `opengrep-core`, which would otherwise scan on at full CPU after gogrep exits (verified). On Unix each opengrep leads a process group of its own (`Setpgid`) and cancelling sends SIGKILL to the group. The signals a terminal sends to its foreground group (Ctrl-C, `Ctrl-\`, a hangup) therefore reach only gogrep, which is why gogrep catches all three and kills the groups itself. On Windows cancelling runs `taskkill /T /F /PID <pid>`, and kills the launcher alone if that fails. After SIGINT, SIGTERM, SIGHUP or SIGQUIT, to gogrep alone or to its whole process group, no `opengrep-cli` or `opengrep-core` was left on macOS (verified);
  - results of interrupted runs are discarded, and no files are written for them;
  - the reporter prints the fixtures that completed, in order, up to the first incomplete one, then `gogrep: interrupted` on stderr, and exits **130**, whichever the signal.
- **Signals that do not reach opengrep.** SIGKILL cannot be caught, and gogrep does not catch Ctrl-Z (SIGTSTP); neither reaches the opengrep process groups. After SIGKILL to gogrep or to its process group (for example from `timeout -s KILL`), running `opengrep-cli` and `opengrep-core` processes scan on until they finish. After Ctrl-Z only gogrep stops: running scans go on, and no new run starts until gogrep continues (verified). A typical fixture's scan takes about a second.
- **Speed.** Each run costs about 1.2 s, of which 0.8 s is opengrep's startup. Ten fixtures take about 3.1 s with 8 workers on an M2, against 12.3 s sequentially (measured). Running the first run alone adds about one run: on a busier M2, the runner took 4.2 s with 8 workers against 3.2 s without that wait, and 18.0 s sequentially (measured).

### 6.6 Cache files and network

- **Cache files.** The only cache files are the existing `rules.Write` configs, `<UserCacheDir>/gogrep/selections/<sha256[:16]>.yaml` (directory 0o700, files 0o600, reused by content hash), plus the bundled binary extracted by `bundle.Path()`. SARIF stays in memory unless `--keep-sarif` is given.
- **No network.** The config path is absolute, the targets are local, and `--disable-version-check` is passed.

## 7. Required changes, new code and test strategy

### 7.1 Changes to existing code and repo files

| File | Change |
|---|---|
| `.gitignore` | Change `gogrep` to `/gogrep`. The unanchored entry ignores everything under `opengrep/gogrep/` (`git check-ignore` confirms), so fixtures could not be committed; it also hides fixtures from opengrep directory scans that run without `--no-git-ignore`. Add `**/opengrep/gogrep/rules/test/**/actual.txt` and `**/opengrep/gogrep/rules/test/**/actual.sarif`. Verified with `git check-ignore`: these ignore fixture output under both the project tree and `testdata/`, and keep `expected.txt` and rules tracked. |
| `.gitattributes` (new) | `**/testdata/** -text`, so CRLF samples and recorded SARIF stay byte-exact. The leading `**/` makes it cover `internal/ruletest/testdata/` too; a plain `testdata/**` matches only the top-level directory (`git check-attr`, verified). |
| `internal/rules/rules.go` | `FromFS(fsys fs.FS, skipDirs ...string) (Set, error)` returns `fs.SkipDir` for directories whose set-relative path is in `skipDirs`, in any letter case. Only top-level paths are skipped, never every directory named `test`, because bundled `opengrep-rules` has a real rule under `…/ncino/tests/`. |
| `rulesargs.go` `loadEnv` | Load `project` with `FromFS(os.DirFS(projectRulesDir), "test")` and `gogrep` with `FromFS(own, "test")`. YAML samples, including invalid YAML or YAML with a `rules:` key, can then no longer abort `scan`, `rules` and `suites`, nor become live `project.test.*` rules. **Behaviour change:** a top-level namespace named `test`, in any letter case (`Test`, `TEST`), is reserved, and `opengrep/gogrep/rules/test/*.yaml` rules stop loading. Add `projectTestsDir`. |
| `rulesargs.go` `withRules` | When gogrep injects its config, also pass `--exclude=opengrep/gogrep/rules/test`. A project `.semgrepignore` **replaces** opengrep's default `test/` exclusion, and with one present `scan .` reported fixture samples; this `--exclude` removed them, also for a nested `…/opengrep/gogrep/rules/test/` and for an absolute or parent-directory target (verified). gogrep's injected arguments (`--config <file> --no-rewrite-rule-ids --exclude=…`) go right after `scan` instead of being appended: appended after a user's `--`, opengrep read them as targets (`File not found: --no-rewrite-rule-ids`, verified). A user's own `--config` stays untouched. |
| `rulesargs.go` `selection` | Add `func (sel selection) filter(env *suite.Env) (ids map[string]bool, active bool, err error)` for §5.3. It reuses `resolve`'s pieces, does not apply the default suite, and uses all rules when only `--gogrep-*` filters are given. |
| `main.go` | Change `run(args []string, stdout, stderr io.Writer) int` so it can be tested, with `main` passing `os.Stdout` and `os.Stderr`. Route `args[0] == "opengrep"` to the pass-through **before** `gogrepFlags`. Add `case "test": return runTest(args[1:], sel, stdout, stderr)`, which returns directly, and fold the duplicated `rules`/`suites` early return into the switch. Factor the child-exec block into `execOpengrep(args, stdout, stderr) int`, shared by `scan` and the pass-through. |

The repo's own `gogrep` set (`rules/`, embedded, currently empty) gets **no** in-tree `rules/test/`, so the binary never embeds fixtures. Its rules are tested by full id from fixtures under `testdata/project/opengrep/gogrep/rules/test/`.

### 7.2 New code

**Package `internal/ruletest/`.** It uses only the standard library and `internal/rules`, with no new dependencies. opengrep sits behind an injected function:

```go
type Exec func(ctx context.Context, dir string, args []string) (stdout, stderr []byte, code int, err error)
```

`args[0]` is the opengrep binary. `err` is set when opengrep could not start or did not exit normally (for example, killed after an interrupt); otherwise `code` is its exit code.

| File | Contents |
|---|---|
| `doc.go` | Package comment. |
| `discover.go` | `Discover(root string, paths []string) ([]*Fixture, error)`. `Fixture{Name, Dir, Namespace, Ref string; Samples []string; Setup error}`. Implements the §2.3 checks, orphans, ignored files, the argument-length guard and the §5.2 path arguments and their usage errors. |
| `ref.go` | `ParseRef([]byte) (string, error)` (§3.1); `Resolve(ref, namespace string, all []*rules.Rule) (*rules.Rule, error)` (§3.2, including did-you-mean). |
| `sarif.go` | Typed decode of only `version`, `runs[].tool.driver.rules[].id`, `runs[].invocations[].toolExecutionNotifications[].{level, descriptor.id, message.text}` and `runs[].results[].{ruleId, message.text, locations[0].physicalLocation.{artifactLocation.uri, region.{startLine, startColumn, endLine, endColumn}}}`. |
| `table.go` | `Render(log *Log, samples []string) ([]byte, error)`: uri normalisation, escaping, sorting, headers and the Windows path rewrite in diagnostics. `Normalize([]byte) []string` for the reader. |
| `diff.go` | Myers line diff and unified output (§4.6). |
| `classify.go` | Rows 1 to 4 of the §6.3 decision table: `Classify(out Output, ruleID string, samples []string) (table []byte, stage Stage, desc []string)`, where `Output{Stdout, Stderr []byte; Code int; Err error}` is one run. Row 1 needs the raw stdout and `Render`'s errors, so it takes the output rather than a decoded log, and returns the table that row 5 compares. |
| `run.go` | `Test{*Fixture; Rule *rules.Rule; Err error; Config string}`, and `Plan(fixtures, all, keep func(*rules.Rule) bool) []*Test`, which resolves each reference and applies the selection. `Runner{Bin string; Exec Exec; Threads int; Learn, KeepSARIF, ShowOutput bool}` and `(*Runner).Run(ctx, tests, stdout, stderr) int`: the worker pool, interrupt handling (the caller cancels `ctx` on an interrupt, §6.5) and the ordered handoff to the reporter. |
| `files.go` | Atomic 0o600 writes, stale-file deletion, and `Accept(fixtures, stdout, stderr) int`. |
| `report.go` | Comparing with `expected.txt`, status lines, descriptions, the summary, computing the exit code, and `WarnUntested(w, project, tests)`, which the caller calls after a full run. |

**`testcmd.go` (package main).** `runTest` handles `run`/`accept` dispatch, flag parsing, usage text, `loadEnv`, `selection.filter`, `rules.Write`, `opengrepBin`, and wiring `Exec` to `exec.CommandContext` with `utf8Env`. `procgroup_unix.go` and `procgroup_windows.go` make cancelling a run kill opengrep's whole process tree (§6.5); `procgroup_other.go` kills the launcher alone, so that gogrep still builds for systems opengrep does not ship for.

### 7.3 Tests for gogrep itself

There are no `_test.go` files today. All new tests use the standard `testing` package.

**Unit tests (no opengrep needed):**

- `internal/rules`: `FromFS` skips top-level `test/` but keeps `go/tests/x.yaml` (via `fstest.MapFS`). Also the id scheme and clash rule, malformed YAML aborting, and non-rule YAML being ignored.
- `ruletest/ref`:
  - comments, BOM and CRLF in `rule.ref`, and UTF-16 or other bytes that are not UTF-8;
  - empty, multi-line, `/regex/` and `key: value` references;
  - each resolution step, nested namespaces, ambiguity across steps, not-found with did-you-mean, and the no-bundled-sets hint.
- `ruletest/table`:
  - every escape, including `\\`, `\|`, `\u001B`, `\xFF` and CRLF inside messages;
  - the sort (numeric positions, bytewise paths, duplicates kept);
  - the header rule; an empty file being 0 bytes; reader normalisation (BOM, CRLF, trailing newlines);
  - uri normalisation (`./`, cleaning, `\` on Windows only, tested as a pure function with an injected separator), rejection of every uri that names no sample, and samples named `a\b.txt` or under a directory `c:` on Unix;
  - the Windows diagnostic path rewrite, tested as a pure function with an injected separator.
- `ruletest/classify` and the golden `Render` tests: driven by SARIF recorded from opengrep 1.30.2 in `internal/ruletest/testdata/sarif/`, with a sibling `.exit` file holding the exit code, and for runs with results a sibling `.txt` file holding the table `Render` must make of it:

  | File | Run |
  |---|---|
  | `results.json` | the §2.4 run including `broken.go`; `results.txt` is the §2.4 table |
  | `invalid-schema.json` | exit 7, `InvalidRuleSchemaError` |
  | `bad-pattern.json` | exit 2, `Rule parse error`, rule missing from `driver.rules` |
  | `unknown-language.json` | exit 8, `UnknownLanguageError` |
  | `file-not-found.json` | exit 2, `SemgrepError`, rule missing from `driver.rules` too |
  | `multiline-message.json` | exit 0; messages with multi-line LF and CRLF bindings, `\|`, a tab, ESC, `\`, non-ASCII and U+FFFD |

  The exact recording script is kept in a comment in the test file. Three more runs are tested with synthetic logs that copy, shortened, what opengrep 1.30.2 reports: an unknown `options:` key and a `metavariable-pattern` in an unknown language (exit 2, `SemgrepError` `Error while matching …`), and `min-version: 99.0.0` (exit 7, `Incompatible rule`). Their messages hold paths on the recording machine, so they are not recorded.
- `ruletest/diff`: insert, delete, change, merged context, empty sides and hunk headers.
- `ruletest/discover`:
  - depth-1 `rule.ref`, nested fixtures, orphan `expected.txt`, unknown `expected*` files;
  - symlinks among the samples and symlinked fixture and namespace directories (skipped where they cannot be created), OS junk, hidden-file samples, `.gogrep-*.tmp`;
  - no samples, the argument-length guard, and path arguments (directory, file, outside the root, one path that selects nothing, a path in the wrong case, and absolute paths through a symlinked cwd).
- `ruletest/run`, using a fake `Exec`:
  - output order is independent of `-j`;
  - deleting a stale `actual.txt`; `--learn`; `--keep-sarif`;
  - `accept` skipping silently;
  - written files being 0o600 (skipped on Windows);
  - interrupts: no writes and exit 130.
- **package main:** cancelling a run kills a process that opengrep's stand-in started (Unix); SIGHUP and SIGQUIT interrupt `gogrep test` (Unix); routing of `test` and `opengrep` (the pass-through keeps `--rule`); test flag parsing (`-j 0`, `-j -2`, `--threads=3`, flags after paths, unknown flag → 2); `withRules` appending `--exclude`; `selection.filter`.

**Integration tests** (`testcmd_test.go`). They are skipped under `-short`, when `opengrepBin()` fails, or when `opengrep --version` is not the version `opengrep.json` pins (the golden files hold that version's output, so another opengrep on `$PATH` in an unbundled build skips rather than fails). They run in CI with `-tags bundled`.

- **Setup.** Each test copies `testdata/project/` to `t.TempDir()`, leaving out any `actual.txt` and `actual.sarif` from manual runs, and calls `t.Chdir` (not combinable with `t.Parallel`). It runs `run([]string{"test", …}, &out, &errb)` and compares stdout with golden files in `testdata/golden/`; a `-update` test flag rewrites them. The golden files hold a bundled build's output; in an unbundled build the test drops the `; this gogrep build has no bundled rule sets` hint before comparing.
- **Cache.** The tests use the real user cache directory. An isolated `HOME` would make opengrep unpack its runtime (about 245 MB, §6.5) again for every test.
- **Cases:**
  1. the tree as committed: exit 0;
  2. `expected.txt` removed: `RESULT`, `Cannot find expected.txt.`, and `actual.txt` written with mode 0o600;
  3. then `accept`: `expected.txt` equals the old `actual.txt`, and the rerun passes and deletes `actual.txt`;
  4. pattern narrowed: the §2.4 diff;
  5. `--learn`: `LEARNED`, then pass;
  6. a schema-error rule (exit 7) and a bad-pattern rule (exit 2): `RULE`, while the other fixtures still pass;
  7. unresolvable and ambiguous references: `RULE`;
  8. an empty fixture, a nested fixture, `expected.text` and an orphan: `SETUP`;
  9. `--rule no-exec-command` runs only matching fixtures plus broken ones; neither it nor a run limited to paths warns about untested rules, while a full run does;
  10. `-j 1` and `-j 8` give identical stdout;
  11. `gogrep rules --suite all` lists no fixture YAML;
  12. `gogrep scan .` with a project `.semgrepignore` reports no fixture samples;
  13. `gogrep opengrep --version` passes through.

### 7.4 Example fixtures (`testdata/project/`)

`testdata/` keeps the samples out of `./...` and out of `//go:embed`. The repo's own `gogrep scan .` skips them through opengrep's default `test/` ignore. Nothing is committed under the repo's real `opengrep/gogrep/rules/`: the `scan` job uploads code-scanning results, and `no-exec-command` would flag `main.go`'s own `exec.Command`.

```
testdata/project/opengrep/gogrep/rules/
├── go/no-exec-command.yaml            # §2.4 rule
├── go/no-exec-command-in-prod.yaml    # same pattern, paths: {exclude: ["*_test.go"]}
├── generic/todo-marker.yaml           # languages: [generic], pattern: TODO, non-ASCII message
└── test/
    ├── .gitattributes                 # * -text
    ├── go.mod                         # module fixtures
    ├── go/exec-command/               # §2.4 exactly: rule.ref, expected.txt, sample.go, safe.go, sub/runner_test.go
    ├── go/exec-command-partial/       # adds sub/broken.go: the diagnostics set
    ├── go/exec-command-layout/        # rule.ref = full id; vendor/v.go, .hidden/h.go, -dash.go, crlf.go (CRLF), lf.go (crlf.go with LF)
    ├── go/exec-command-in-prod/       # paths: rule; a.go matches, a_test.go excluded
    └── generic/todo-marker/           # notes.txt and notes.yaml (invalid YAML with a rules: key); expected.txt and rule.ref contain "TODO"
```

Together these fixtures prove the following:

- `*_test.go`, `vendor/`, hidden and `-`-prefixed samples are scanned;
- a Go rule gives the same positions for CRLF and LF samples;
- a rule's `paths:` sees fixture-relative paths;
- a full-id reference resolves;
- YAML under `test/` is never loaded as rules;
- a generic rule never matches `expected.txt` or `rule.ref`;
- non-ASCII messages survive, and columns count UTF-8 bytes (`notes.txt`).

`exec-command` doubles as the README demo.

`crlf.go` and `sub/broken.go` are deliberately not gofmt-clean (CRLF line ends, a syntax error), so `gofmt -l .` lists them; a formatting check must skip `testdata/`.

### 7.5 CI

Add a new workflow, `.github/workflows/test.yml`, with `permissions: contents: read`. It runs on a matrix of `ubuntu-latest`, `macos-latest` and `windows-latest`, with actions pinned by SHA as in `gogrep.yml` and `shell: bash` on every OS:

```yaml
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
    with: { go-version-file: go.mod }
  - run: go run ./tools/fetch-opengrep        # host asset: linux/amd64, darwin/arm64, windows/amd64
  - run: go vet ./... && go vet -tags bundled ./...
  - run: go test -tags bundled ./...
  - run: go build -tags bundled -o "$RUNNER_TEMP/bin/" .   # directory output adds .exe on Windows
  - run: cd testdata/project && "$RUNNER_TEMP/bin/gogrep" test
```

- This is the first workflow that runs `go vet` and `go test`.
- The Windows leg checks what the research could not verify there: uri separators, `.\`-prefixed targets, CRLF handling, the `--exclude` pattern and command-line length.
- Pin bumps in `opengrep.json` run through this job. Changed rule behaviour then shows up as `expected.txt` diffs, which are accepted with `gogrep test accept` and reviewed in the PR.

## 8. Documentation updates

- **`README.md`.**
  - New section **"5. Test custom rules"**, after "4. Run all rules". It covers:
    - the layout tree (§2.1) and the worked example (§2.4: rule, `rule.ref`, samples, `expected.txt`, passing and failing runs);
    - how references resolve (§3.2) and how to check them with `gogrep rules --rule <ref>`;
    - the table format: columns, raw exclusive end column, byte columns, escapes, the `diagnostics` set;
    - the workflow: write samples, run `gogrep test` (it fails with `Cannot find expected.txt.`), review the diff, then `gogrep test accept` or `--learn`, then commit;
    - the flags and exit codes;
    - the tips from §2.5 (`go.mod`, `.gitattributes`, `.gitignore`, a positive sample per fixture, `paths:` being relative to the fixture);
    - a CI snippet;
    - the note that `gogrep test` replaces opengrep's `test`, which stays available as `gogrep opengrep test --config <dir> <tests>`.
  - **"How gogrep picks rules":** the `project` bullet becomes "rules in `opengrep/gogrep/rules/` except `test/`, which holds rule test fixtures and is never loaded as rules", and says that scans that run gogrep's rules exclude `test/`, while a scan with your own `--config` scans it like any other directory. Add a bullet for `gogrep opengrep <args>`.
  - **"Building":** `go test -tags bundled ./...` runs the integration tests after `fetch-opengrep`.
- **`suites/README.md`.** In the `rules` table, the `project` entry becomes "`opengrep/gogrep/rules/` in the current directory, except `test/`".
- **`rules/README.md`.** One paragraph: `rules/test/` is reserved and never loaded. Rules in this set are tested from fixtures under `testdata/project/opengrep/gogrep/rules/test/` whose `rule.ref` holds the full id `gogrep.<dir>.<id>`.
- **Command help.** `gogrep test --help` prints the usage text from §5.3.

## 9. Alternatives considered and open questions

### 9.1 Alternatives

| Alternative | Decision |
|---|---|
| **opengrep's native runner**: `opengrep test` with `// ruleid:` and `// ok:` on the line before a match | Rejected. Its machine-readable output is native `--json` only, which the SARIF-only rule forbids, and `--sarif` is an unknown option (exit 2). Its text report prints literal `TODO: print(check_output_lines)`. It compares line numbers only, ignoring columns, messages and counts. It pairs rule and test by basename or a `--config` directory, which fits neither `test/<ns>/<fixture>` nor qualified ids. Its loader is stricter than `scan` (`message: y` exits 7). It remains reachable through `gogrep opengrep test`. |
| **`gogrep scan --test` as the escape hatch** | Not documented. It works with the user's own directory `--config` and a test directory, which gogrep passes on untouched, but crashes (`IndexError`) whenever gogrep adds its own file config, as it does without `--config`, with `--config bundled`, `--rule` or `--suite` (verified). The pass-through has no such cases. |
| **CodeQL naming**: `<name>.ruleref` plus `<name>.expected`, several tests sharing one sample set | Not chosen. The issue says a fixture refers to *a* rule and has an `expected*` file. Fixed names keep discovery and docs simple, and only `discover.go` would change to adopt this (open question 1). |
| **One combined opengrep run for many fixtures** (1.3 s against 3.1 s in parallel for 10 fixtures) | Deferred. A schema error in one rule blanks every fixture (exit 7). Rule `paths:` filters see prefixed paths and behave differently (verified). Syntax-error notifications can only be attributed by parsing message text. It is a follow-up, with an isolated fallback and a batched-versus-isolated equivalence test. |
| **Directory target** plus `--no-git-ignore --x-ignore-semgrepignore-files --exclude 'expected*'` | Rejected. It relies on an internal flag that may disappear and warns on every run, `generic` and `regex` rules would match the regression files, and `.gitignore` still applies. |
| **Raw SARIF as the expected file** | Rejected: fingerprints, driver and version metadata, and unreadable diffs. |
| **Snippet, element, ruleId or severity columns** | Rejected. Snippets depend on the locale and repeat whole lines, and an element column cut from them inherits that. ruleId is redundant and churns on renames. Severity is rule metadata. |
| **CodeQL's inclusive end column** (`endColumn − 1`) | Rejected. It is an extra transformation, it yields 0 for zero-width matches, and it differs from `gogrep scan --sarif`. |
| **Suffix matching in `rule.ref`** (like `--rule`) | Rejected: after a rename a fixture could silently test a different rule. |
| **Self-contained `path:…: message` rows, multiset comparison, no `actual.txt` or `accept`** | Rejected. It is further from CodeQL, leaves nothing on disk to inspect, and loses the accept loop. |
| **A rule copy inside the fixture** (the CodeQL library-test analogue) | Rejected. The issue says a fixture refers to a rule, and a stray `rules:` YAML could become a live rule. |
| **Failing on sample syntax errors** | Rejected in favour of `diagnostics` rows, which are visible and regression-checked but allow intentionally partial samples. |
| **`gogrep test-rules` or `gogrep rules test`** | Rejected. `test` matches CodeQL and is what users type, and `gogrep rules` ignores positional arguments today. |
| **CodeQL inline expectations** (`// $ Alert`, `SPURIOUS:`, `MISSING:`) | Deferred to a follow-up as a `rule.ref` option that adds a `testFailures` set while staying diff-based. The syntax choice (CodeQL's same-line `$ Alert` or opengrep's next-line `ruleid:`) is made there. |
| **More flags in v1**: `--format json`, `--slice N/M`, `--failing-exitcode`, a per-fixture `--timeout` (fixtures run without opengrep's, §6.2), `--require-tests` (fail on untested project rules) | Deferred to follow-ups, along with autofix tests (opengrep's SARIF `fixes` are inconsistent: `insertedContent` is the whole fixed line while `deletedRegion` covers only the match) and cleanup of the never-cleaned `selections/` cache. |

### 9.2 Open questions for the user

1. **File names and one rule per fixture.** The design uses fixed `rule.ref`, `expected.txt` and `actual.txt`, one rule per fixture. The alternative is CodeQL's `<name>.ruleref` with `<name>.expected`, allowing several rules to share one fixture's samples. **Default: fixed names, one rule per fixture.**
2. **Taking over `gogrep test`.** `gogrep test` stops reaching opengrep's annotation runner, which moves to `gogrep opengrep test …`. **Default: yes, announced in the release notes.**
3. **Reserving the `test` namespace.** Rules in `opengrep/gogrep/rules/test/*.yaml` (`project.test.*`, and likewise `Test/` in any letter case) stop loading. **Default: yes, announced in the release notes.**

## 10. Implementation plan

Each step is one commit. Each leaves `go vet ./...` and `go test ./...` green and ends with the `Co-Authored-By` trailer. The untracked local `opengrep/` experiment directory in the repo root becomes visible to `git status` after step 1 and is never committed.

| # | Commit | Files | Verification |
|---|---|---|---|
| 1 | Anchor the binary in .gitignore and keep testdata bytes exact | `.gitignore`, `.gitattributes` | `git check-ignore -v` ignores `gogrep` and fixture `actual.txt`/`actual.sarif`, and keeps `opengrep/gogrep/rules/go/x.yaml` and `…/expected.txt`. |
| 2 | Skip the test/ directory when loading rule sets | `internal/rules/rules.go`, `internal/rules/rules_test.go`, `rulesargs.go` (`loadEnv`) | `go test ./internal/rules`. By hand: a project with invalid YAML under `opengrep/gogrep/rules/test/` still runs `gogrep rules --suite all`. |
| 3 | Exclude rule test fixtures from gogrep's scans | `rulesargs.go` (`withRules`), `rulesargs_test.go` | Unit test on `withRules` output. By hand: with a project `.semgrepignore`, `gogrep scan .` reports no fixture samples. |
| 4 | Add the `gogrep opengrep` pass-through and make `run` testable | `main.go`, `main_test.go` | `gogrep opengrep --version` prints 1.30.2. `gogrep opengrep test --config ./rd ./td` runs opengrep's runner. A routing test checks that `--rule` survives the pass-through. |
| 5 | ruletest: parse and resolve rule.ref | `internal/ruletest/doc.go`, `ref.go`, `ref_test.go` | `go test ./internal/ruletest` covering §3.1 and the §3.2 example table. |
| 6 | ruletest: render opengrep SARIF as an expected table | `internal/ruletest/sarif.go`, `table.go`, `table_test.go`, `testdata/sarif/*` | Golden render of `results.json` equals the §2.4 syntax-error table byte for byte. Escape and sort tests. |
| 7 | ruletest: unified line diff | `internal/ruletest/diff.go`, `diff_test.go` | The §2.4 regression diff is reproduced exactly. Edge cases. |
| 8 | ruletest: discover fixtures | `internal/ruletest/discover.go`, `discover_test.go` | Every §2.3 check, orphans, ignored files, path arguments. |
| 9 | ruletest: run, classify and report fixtures | `internal/ruletest/classify.go`, `run.go`, `files.go`, `report.go` and their tests | The fake-`Exec` tests from §7.3, including every row of §6.3, file modes and interrupts. |
| 10 | Add `gogrep test` and `gogrep test accept` | `testcmd.go`, `main.go`, `rulesargs.go` (`selection.filter`), `testcmd_test.go`, `testdata/project/**`, `testdata/golden/*` | `go test -tags bundled ./...` with the integration cases from §7.3. `cd testdata/project && gogrep test` exits 0 and prints `All 5 tests passed.` |
| 11 | Run vet, tests and gogrep test in CI on Linux, macOS and Windows | `.github/workflows/test.yml` | All three matrix legs are green on the PR. Any Windows-only difference (uri separators, `.\` targets, `--exclude`) is fixed in this step before merge. |
| 12 | Document rule test fixtures | `README.md`, `suites/README.md`, `rules/README.md` | The README example matches `testdata/project/…/go/exec-command` and its golden output byte for byte. Links resolve. |
