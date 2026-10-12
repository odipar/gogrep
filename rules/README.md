# gogrep rules

Opengrep rules in this directory are embedded in every gogrep build as the
`gogrep` rule set and run by default, next to the rule sets pinned in
`opengrep.json`.

Lay them out like opengrep-rules, so `--gogrep-lang` and `--gogrep-category`
can filter them:

    rules/<language>/<anything>/<rule>.yaml

where `<language>` is the top-level directory (`go`, `python`, `generic`, ...)
and each rule sets `metadata.category` (`security`, `correctness`,
`best-practice`, ...).
