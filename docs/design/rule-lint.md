# Rule linter

Design for #8.

gogrep's query suites select rules by their metadata (`category`, `subcategory`, `confidence`, …). A custom rule without that metadata cannot be selected by a suite filter, and a rule with invalid values is silently left out. gogrep already bundles 45 rule-quality rules from opengrep-rules (`yaml.semgrep.*`). This design turns them into a linter.

## 1. The `rule-lint` suite

A new built-in suite, `suites/rule-lint.yaml`:

```yaml
- description: Rule-quality checks for opengrep rule files; gogrep lint runs it
- rules: bundled
- include:
    id: /^opengrep-rules\.yaml\.semgrep\./
```

- It selects exactly the 45 `yaml.semgrep.*` rules: missing `category` / `technology`; for `category: security` missing `subcategory`, `confidence`, `likelihood`, `impact`; invalid values of those; malformed `cwe`, `owasp`, `references`; missing `message` or `languages`; duplicate ids and patterns; slow or unsatisfiable patterns; and more.
- It ends with a filter, so no `gogrep` or `project` rules are added.
- A project can override it, like any built-in suite, with `opengrep/gogrep/suites/rule-lint.yaml`, for example to `import: rule-lint` and `exclude` checks it does not want.
- `gogrep scan --suite rule-lint <paths>` works as a plain scan too.

## 2. `gogrep lint`

```
gogrep lint [--suite NAME] [--sarif] [path...]
```

- **Paths** are files or directories relative to the current directory. With none, `opengrep/gogrep/rules` is linted; if it does not exist, `gogrep lint` exits 2 with `no opengrep/gogrep/rules here; name the rules to lint`.
- **Fixtures are never linted:** `opengrep/gogrep/rules/test/` (the rule test fixtures, whose samples may be YAML) is excluded, as in every scan that uses gogrep's rules.
- **`--suite NAME`** lints with another suite (default `rule-lint`, resolved like `--suite`, so a project's override applies).
- **Output:** one line per finding, sorted by path, line, column and rule id:
  ```
  opengrep/gogrep/rules/go/bare.yaml:2:5: opengrep-rules.yaml.semgrep.metadata-category (INFO): <message>
  ```
  then a summary on stderr: `2 problems in 1 of 2 rule files.` or `No problems in 2 rule files.` (rule files are the YAML files scanned). `--sarif` writes the rebranded SARIF log to stdout instead, with no summary.
- **Exit codes:** 0 no findings, 1 findings, 2 usage or setup errors (as `gogrep test`).
- Other flags are an error (exit 2); `gogrep lint` does not forward flags to opengrep.

## 3. `Engine.Lint`

```go
// LintOptions are the options of Lint. The zero value lints
// opengrep/gogrep/rules of dir with the rule-lint suite.
type LintOptions struct {
	// Paths are the files and directories to lint, relative to dir.
	// Empty means opengrep/gogrep/rules.
	Paths []string
	// Suite is the lint suite; "" means "rule-lint". A project suite of the
	// same name in dir overrides the built-in one.
	Suite string
	// Stderr, if not nil, receives a live copy of opengrep's stderr.
	Stderr io.Writer
}

// Lint runs the rule-quality checks of opts.Suite on the rule files under
// opts.Paths of dir, never on the rule test fixtures, and returns the
// result as Scan does: findings are not errors.
func (e *Engine) Lint(ctx context.Context, dir string, opts *LintOptions) (*Result, error)
```

- Lint is Scan with a fixed selection (`Selection{Suites: []string{suite}}`), `Targets` set to the paths, and project rules not added. Errors are Scan's, plus a plain error naming `opengrep/gogrep/rules` when no paths are given and it does not exist.
- The CLI's `gogrep lint` is a thin layer over `Lint`, as `scan` is over `Scan`.

## 4. CI and repository

- `test.yml` runs `gogrep lint` in `testdata/project` and `gogrep lint rules` at the repository root after the build; both must exit 0.
- The example rules in `testdata/project` already carry full metadata (#7).

## 5. Tests and docs

- Unit tests: flag parsing and usage errors, output formatting and sorting, summary and exit codes (fake opengrep), the default path and its missing-directory error, the fixture exclusion.
- Integration tests (real opengrep): a rule with no metadata gives `metadata-category` and `metadata-technology`; a security rule without `confidence` etc. gives those; the clean example rules give none; YAML samples under `test/` are not linted; `Engine.Lint` returns the same findings.
- Docs: README section "6. Lint custom rules", `suites/README.md` built-in table, `rules/README.md`, `doc.go`/godoc.

## 6. Implementation plan

| # | Commit | Verification |
|---|---|---|
| 1 | Add the rule-lint suite | `gogrep suites` lists it with 45 rules; `gogrep scan --suite rule-lint` on a bare rule reports both metadata findings |
| 2 | Engine.Lint | unit and integration tests above; `go test -race -short ./...` |
| 3 | gogrep lint | CLI tests; manual runs on testdata/project (exit 0) and a bare rule (exit 1) |
| 4 | Lint this repository's rules in CI | `test.yml` steps green on all three OSes |
| 5 | Document gogrep lint | README examples are real output |
