# gogrep rules

Opengrep rules in this directory are embedded in every gogrep build as the
`gogrep` rule set and run by default, next to the rule sets pinned in
`opengrep.json`.

Each rule gets the stable id `gogrep.<dir>.<rule id>`. Give rules the usual
metadata (`category`, `confidence`, `subcategory`, ...) so query suites can
select them; see [../suites/README.md](../suites/README.md). The built-in
suites run every `gogrep` rule.
