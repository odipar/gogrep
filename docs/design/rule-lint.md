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
- A project can override it, like any built-in suite, with `opengrep/gogrep/suites/rule-lint.yaml`, for example to `import: rule-lint` and `exclude` checks it does not want. A project suite that imports its own name gets the built-in suite it overrides (`suite.Env.Shadowed`), not itself; before this change that was an import cycle.
- `gogrep scan --suite rule-lint <paths>` works as a plain scan too.

## 2. `gogrep lint`

```
gogrep lint [--suite NAME] [--sarif] [path...]
```

- **Paths** are files or directories relative to, and inside, the current directory; another path, such as `../rules`, exits 2 with `../rules is not a relative path inside the current directory`. With none, `opengrep/gogrep/rules` is linted; if it does not exist, `gogrep lint` exits 2 with `no opengrep/gogrep/rules here; name the rules to lint`.
- **Rule files** are chosen by `Engine.Lint`, not by opengrep's directory walk: every `.yaml` and `.yml` file below the paths, a path that is such a file, and the symlinks among them that lead to such a file inside the current directory, which stand for that file (a symlink that leads outside is an error). It enters no symlinked directory below a path; a path that is one, the default `opengrep/gogrep/rules` included, is resolved the same way. The files go to opengrep as named targets, so `.semgrepignore`, `.gitignore` and opengrep's default ignores (`tests/`, `vendor/`, `node_modules/`, …), which apply only to directories it walks, hide none of them: a rule file that loads as a project rule is always linted. An unreadable directory below a path is an error that names it. More files than fit in 30,000 bytes of arguments (Windows' command line holds 32,767 characters) are an error: `too many rule files (N); lint fewer paths at once`. Without rule files opengrep does not run.
- **Fixtures are never linted:** `opengrep/gogrep/rules/test/` (the rule test fixtures, whose samples may be YAML) is skipped in any letter case, as when the project rules load, and a path inside it is an error.
- **`--suite NAME`** lints with another suite (default `rule-lint`, resolved like `--suite`, so a project's override applies).
- **Output:** one line per finding, sorted by path, line, column and rule id:
  ```
  opengrep/gogrep/rules/go/bare.yaml:2:5: opengrep-rules.yaml.semgrep.metadata-category (INFO): <message>
  ```
  A rule file that opengrep cannot parse gets no findings but a syntax-error notification (`Other syntax error at line <file>:<line>: …`, also `Syntax error` or `Lexical error`), which `Engine.Lint` leaves in `Result.Diagnostics`. `gogrep lint` counts each such notification that names a linted file as a problem of the check `syntax-error`, at that line (or line 1), with the rest of the message:
  ```
  rules/no-panic.yaml:3:1: syntax-error (ERROR): (approximate error location; error nearby after) error calling parser: …
  ```
  Its other notifications go to stderr as `gogrep: opengrep: <message>`. Then a summary on stderr: `2 problems in 1 of 2 rule files.` or `No problems in 2 rule files.` (rule files are those `Engine.Lint` scanned, `LintResult.Files`). `--sarif` writes the rebranded SARIF log to stdout instead, with no summary.
- **Exit codes:** 0 no problems, 1 problems (findings that nosemgrep does not suppress, or syntax errors), also with `--sarif`, 2 usage or setup errors (as `gogrep test`).
- Other flags are an error (exit 2); `gogrep lint` does not forward flags to opengrep.

## 3. `Engine.Lint`

```go
// LintOptions are the options of Lint. The zero value lints
// opengrep/gogrep/rules of dir with the rule-lint suite.
type LintOptions struct {
	// Paths are the files and directories to lint, relative to dir and
	// inside it (filepath.IsLocal). Empty means opengrep/gogrep/rules.
	Paths []string
	// Suite is the lint suite; "" means "rule-lint". A project suite of the
	// same name in dir overrides the built-in one.
	Suite string
	// Stderr, if not nil, receives a live copy of opengrep's stderr.
	Stderr io.Writer
}

// A LintResult is what one lint found: the Result of its scan, and the rule
// files it scanned.
type LintResult struct {
	*Result
	// Files are the rule files that the lint scanned, as slash paths
	// relative to dir, sorted bytewise. A symlinked rule file is listed by
	// the path it leads to, which opengrep scans and the findings name.
	Files []string
}

// Lint runs the rule-quality checks of opts.Suite on the rule files under
// opts.Paths of dir, never on the rule test fixtures, and returns the
// result as Scan does: findings are not errors.
func (e *Engine) Lint(ctx context.Context, dir string, opts *LintOptions) (*LintResult, error)
```

- Its findings include those that `nosemgrep` suppresses, with `Suppressed` set, as Scan's do; `gogrep lint` does not count them as problems.
- Lint is Scan with a fixed selection (`Selection{Suites: []string{suite}}`) and `Targets` set to the rule files of §2, which it returns as `Files`. Without rule files it runs no opengrep and returns a complete `Result` without findings, whose SARIF log has no rules. Errors are Scan's, plus plain errors for a path that is not a relative path inside dir (`lint path "../x" is not a relative path inside the directory`) does not exist, lies in the fixtures or is a file but not a rule file, for an unreadable directory, a symlink that leads outside dir and too many rule files, and one naming `opengrep/gogrep/rules` when no paths are given and it does not exist.
- A project rule file that does not parse stops Scan, Rules and Test with an error that names it (`opengrep/gogrep/rules/go/x.yaml: yaml: …`), but not Lint: an unexported `ScanOptions` field that Lint sets makes the project rules load without such files, and opengrep reports the file as a syntax error (§2).
- The CLI's `gogrep lint` is a thin layer over `Lint`, as `scan` is over `Scan`.

## 4. CI and repository

- `test.yml` runs `gogrep lint` in `testdata/project` and `gogrep lint rules` at the repository root after the build; both must exit 0.
- The example rules in `testdata/project` already carry full metadata (#7).

## 5. Tests and docs

- Unit tests: flag parsing and usage errors, output formatting and sorting, summary and exit codes (fake opengrep), the default path and its missing-directory error, the fixture exclusion in any letter case; the rule files and `Files` exactly, with ignored directories, symlinked files and directories, a symlink outside the directory, an unreadable directory, the argument limit, and no rule files (opengrep not run).
- Integration tests (real opengrep): a rule with no metadata gives `metadata-category` and `metadata-technology`; a security rule without `confidence` etc. gives those; the clean example rules give none; YAML samples under `test/` are not linted; rule files that the default ignores, `.gitignore` or `.semgrepignore` hide from a scan are linted, and so are symlinked ones; `Engine.Lint` returns the same findings.
- Docs: README section "6. Lint custom rules", `suites/README.md` built-in table, `rules/README.md`, `doc.go`/godoc.

## 6. Implementation plan

| # | Commit | Verification |
|---|---|---|
| 1 | Add the rule-lint suite | `gogrep suites` lists it with 45 rules; `gogrep scan --suite rule-lint` on a bare rule reports both metadata findings |
| 2 | Engine.Lint | unit and integration tests above; `go test -race -short ./...` |
| 3 | gogrep lint | CLI tests; manual runs on testdata/project (exit 0) and a bare rule (exit 1) |
| 4 | Lint this repository's rules in CI | `test.yml` steps green on all three OSes |
| 5 | Document gogrep lint | README examples are real output |
