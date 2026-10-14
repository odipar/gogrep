# gogrep rules

Opengrep rules in this directory are embedded in every gogrep build, and in
every program that imports the Go package, as the `gogrep` rule set, and run
by default next to the rule sets pinned in `opengrep.json`. Rules of the
scanned directory's own `opengrep/gogrep/rules/` form the `project` rule
set instead.

Each rule gets the stable id `gogrep.<dir>.<rule id>`. Give rules the usual
metadata (`category`, `confidence`, `subcategory`, ...) so query suites can
select them; see [../suites/README.md](../suites/README.md). The built-in
suites, except `rule-lint`, run every `gogrep` rule. Check the rules here
with `gogrep lint rules` from the repository root, as CI does; see
[Lint custom rules](../README.md#6-lint-custom-rules).

`rules/test/`, in any letter case, is reserved for rule test fixtures and never
loaded as rules. Test the rules here from fixtures under
[../testdata/project/opengrep/gogrep/rules/test/](../testdata/project/opengrep/gogrep/rules/test/)
whose `rule.ref` holds the full id `gogrep.<dir>.<rule id>`; see
[Test custom rules](../README.md#5-test-custom-rules).
