# gogrep rules

Opengrep rules in this directory are embedded in every gogrep build as the
`gogrep` rule set and run by default, next to the rule sets pinned in
`opengrep.json`.

Each rule gets the stable id `gogrep.<dir>.<rule id>`. Give rules the usual
metadata (`category`, `confidence`, `subcategory`, ...) so query suites can
select them; see [../suites/README.md](../suites/README.md). The built-in
suites run every `gogrep` rule.

`rules/test/`, in any letter case, is reserved for rule test fixtures and never
loaded as rules. Test the rules here from fixtures under
[../testdata/project/opengrep/gogrep/rules/test/](../testdata/project/opengrep/gogrep/rules/test/)
whose `rule.ref` holds the full id `gogrep.<dir>.<rule id>`; see
[Test custom rules](../README.md#5-test-custom-rules).
