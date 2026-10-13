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
  - `project`: rules in `opengrep/gogrep/rules/` of the scanned project.
- **Rule ids** are stable (`<rule set>.<directory>.<rule id>`), so results
  keep their identity across machines and rule updates.

## Building

```sh
go run ./tools/fetch-opengrep           # download the pinned opengrep and rule sets
go build -tags bundled -o gogrep .      # build with them embedded
```

`go install github.com/odipar/gogrep@latest` builds the plain wrapper instead.
It runs the `opengrep` on your `PATH` and has no bundled rules. To move to a
newer opengrep, run `go run ./tools/fetch-opengrep -pin <tag>` and commit
`opengrep.json`. Pushing a `v*` tag builds and publishes every platform as a
GitHub release.

## License

gogrep is licensed under the GNU Lesser General Public License v2.1, like
opengrep. Release builds bundle third-party components under their own
licenses; see [NOTICE.md](NOTICE.md).
