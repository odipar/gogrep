# gogrep query suites

A suite picks which rules a scan runs, modelled on
[CodeQL query suites](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/creating-codeql-query-suites).
The `.yaml` files here are gogrep's built-in suites, embedded in every build
and in the Go package. A project can add its own, or override a built-in
one, in `opengrep/gogrep/suites/<name>.yaml` of the scanned directory.

```sh
gogrep scan .                            # the default suite, code-scanning
gogrep scan --suite security-extended .  # another suite (name or file path)
gogrep scan --rule dangerous-exec-command .           # one rule
gogrep scan --rule '/sql-injection/' --suite all .    # union of rules and suites
gogrep scan --suite all --gogrep-lang go .            # narrow any selection
gogrep suites                            # list suites and their rule counts
gogrep rules --suite code-scanning       # list the rules a selection picks
gogrep lint                              # check opengrep/gogrep/rules with rule-lint
```

## Format

A suite is a YAML list of instructions, applied in order:

```yaml
- description: Likely vulnerabilities in our web code
- rules: bundled                # locate rule sets: a name or a list of names
- import: security-extended     # add the rules another suite selects
- include:                      # keep rules matching every key (AND)...
    subcategory: vuln
    confidence: [HIGH, MEDIUM]  # ...where a list matches any of its values
- include:                      # separate filters are alternatives (OR)
    impact: HIGH
- exclude:
    id: /\.audit\./             # /regex/ values are regular expressions
- rules: project                # rules located after the last filter all run
```

| Instruction | Meaning |
|---|---|
| `rules` | Add a rule set: `opengrep-rules`, `0xdea`, `semgrep-go` (pinned in `opengrep.json`), `gogrep` (this repo's `rules/`), `project` (`opengrep/gogrep/rules/` of the scanned directory, which for the gogrep command is the current directory, except `test/` in any letter case), or the groups `bundled` (all pinned sets) and `all`. |
| `import` | Add the rules another suite selects, by name or path. A path must name a regular file, or a symlink to one. A project suite that imports its own name gets the built-in suite it overrides, so it can extend it. |
| `include` / `exclude` | Filter the rules located so far on their fields. |

**Filter semantics** (as in CodeQL): the first filter that applies to a rule
sets its default. If that filter is an `include`, the rule is kept only if an
include matches it. If it is an `exclude`, the rule is kept unless an exclude
matches it. Later filters override earlier ones. An empty filter (`{}`)
matches every rule.

**Fields** a filter can match:

| Field | Value |
|---|---|
| `id` | The stable rule id `<set>.<dir>.<rule id>`, e.g. `opengrep-rules.go.lang.security.audit.dangerous-exec-command` (the rule file's directories, not its name). Use a regex for families of rules. |
| `ruleset`, `path` | The rule set name, and the rule file path within the set. |
| `severity`, `message`, `languages` | The rule's own fields. |
| any metadata key | `category`, `subcategory`, `confidence`, `likelihood`, `impact`, `cwe`, `owasp`, `technology`, `vulnerability_class`, ... (also as `metadata.<key>`). |

Values match case-insensitively. A field with several values (such as
`languages`, `cwe` or `technology`) matches if any of them matches. Write
`<field> contain all: [a, b]` to require all of them.

## Built-in suites

| Suite | Selects |
|---|---|
| `code-scanning` (default) | Security rules marked `subcategory: vuln` with HIGH or MEDIUM confidence, plus all `gogrep` and `project` rules. |
| `security-extended` | All security rules, including audit and low-confidence ones, plus `gogrep` and `project` rules. |
| `security-and-quality` | Security, correctness, best-practice, performance, maintainability, portability and compatibility rules, `semgrep-go`, and `gogrep` and `project` rules. |
| `all` | Every rule. |
| `rule-lint` | The 45 rule-quality checks of opengrep-rules (`opengrep-rules.yaml.semgrep.*`), for rule files rather than code; `gogrep lint` runs it. It adds no `gogrep` or `project` rules. |
