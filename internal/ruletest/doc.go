// Package ruletest runs gogrep's rule test fixtures. A fixture is a
// directory under opengrep/gogrep/rules/test/ whose rule.ref names one rule,
// whose other files are code samples, and whose expected.txt holds the
// results opengrep reports for that rule on those samples, as a table
// rendered from opengrep's SARIF output. docs/design/rule-test-fixtures.md
// describes the format and the runner.
package ruletest
