package ruletest

import (
	"testing"

	"github.com/odipar/gogrep/internal/rules"
)

func TestParseRef(t *testing.T) {
	tests := []struct {
		name, data, want, err string
	}{
		{"plain", "no-exec-command\n", "no-exec-command", ""},
		{"no final newline", "no-exec-command", "no-exec-command", ""},
		{"comments and blank lines", "# Tests project.go.no-exec-command.\n\n  # indented\nno-exec-command\n\n", "no-exec-command", ""},
		{"BOM and CRLF", "\uFEFF# comment\r\n\r\nno-exec-command\r\n", "no-exec-command", ""},
		{"trimmed", " \tproject.go.no-exec-command \t\n", "project.go.no-exec-command", ""},
		{"# after the first character", "a#b\n", "a#b", ""},
		{"colon without space", "a:b\n", "a:b", ""},
		{"empty", "", "", "rule.ref is empty"},
		{"BOM only", "\uFEFF", "", "rule.ref is empty"},
		{"only comments", "# no-exec-command\n\n", "", "rule.ref is empty"},
		{"two references", "a\nb\n", "", "rule.ref has 2 references; a fixture tests exactly one rule"},
		{"three references", "a\r\n# b\r\nc\r\nd", "", "rule.ref has 3 references; a fixture tests exactly one rule"},
		{"regex", "/exec/\n", "", "a fixture must name one rule, not a /regex/"},
		{"option", "no-exec-command\nseverity: ERROR\n", "", `unsupported option "severity: ERROR" in rule.ref`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRef([]byte(tt.data))
			if got != tt.want || errText(err) != tt.err {
				t.Errorf("ParseRef(%q) = %q, %q; want %q, %q", tt.data, got, errText(err), tt.want, tt.err)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	project := ruleSet("project", "project.go.no-exec-command", "project.go.net.dial", "project.net.dial", "project.gogrep.x")
	all := append(ruleSet("gogrep", "gogrep.go.y", "gogrep.x"), project...)
	all = append(all, ruleSet("opengrep-rules", "opengrep-rules.go.lang.security.audit.dangerous-exec-command")...)
	many := ruleSet("project", "project.f.dial", "project.e.dial", "project.d.dial", "project.c.dial", "project.b.dial", "project.a.Dial")

	tests := []struct {
		name, ref, namespace string
		all                  []*rules.Rule
		want, err            string
	}{
		// The design's examples (§3.2).
		{"namespace relative", "no-exec-command", "go", all, "project.go.no-exec-command", ""},
		{"project relative", "go.no-exec-command", "misc", all, "project.go.no-exec-command", ""},
		{"full id", "project.go.no-exec-command", "misc", all, "project.go.no-exec-command", ""},
		{"nested namespace", "dial", "go/net", all, "project.go.net.dial", ""},
		{"ambiguous across steps 2 and 3", "net.dial", "go", all, "",
			`rule reference "net.dial" is ambiguous: project.go.net.dial, project.net.dial; write the full id`},
		{"did you mean", "no-exec-command", "misc", all, "",
			`rule reference "no-exec-command" matches no rule; did you mean project.go.no-exec-command?; list candidates with: gogrep rules --rule '/no-exec-command/'`},

		{"bundled full id", "opengrep-rules.go.lang.security.audit.dangerous-exec-command", "go", all,
			"opengrep-rules.go.lang.security.audit.dangerous-exec-command", ""},
		{"gogrep full id", "gogrep.go.y", "go", all, "gogrep.go.y", ""},
		{"ambiguous across steps 1 and 3", "gogrep.x", "go", all, "",
			`rule reference "gogrep.x" is ambiguous: gogrep.x, project.gogrep.x; write the full id`},
		{"no suffix match", "exec-command", "go", all, "",
			`rule reference "exec-command" matches no rule; list candidates with: gogrep rules --rule '/exec-command/'`},
		{"case-sensitive", "No-Exec-Command", "go", all, "",
			`rule reference "No-Exec-Command" matches no rule; did you mean project.go.no-exec-command?; list candidates with: gogrep rules --rule '/No-Exec-Command/'`},
		{"five suggestions, sorted", "dial", "go", append(many, all...), "",
			`rule reference "dial" matches no rule; did you mean project.a.Dial, project.b.dial, project.c.dial, project.d.dial, project.e.dial?; list candidates with: gogrep rules --rule '/dial/'`},
		{"no bundled rule sets", "no-exec-command", "misc", project, "",
			`rule reference "no-exec-command" matches no rule; did you mean project.go.no-exec-command?; list candidates with: gogrep rules --rule '/no-exec-command/'; this gogrep build has no bundled rule sets`},
		{"no rules", "x", "go", nil, "",
			`rule reference "x" matches no rule; list candidates with: gogrep rules --rule '/x/'; this gogrep build has no bundled rule sets`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Resolve(tt.ref, tt.namespace, tt.all)
			got := ""
			if r != nil {
				got = r.ID
			}
			if got != tt.want || errText(err) != tt.err {
				t.Errorf("Resolve(%q, %q) = %q, %q; want %q, %q", tt.ref, tt.namespace, got, errText(err), tt.want, tt.err)
			}
		})
	}
}

// ruleSet returns rules with the given qualified ids in set.
func ruleSet(set string, ids ...string) []*rules.Rule {
	var rs []*rules.Rule
	for _, id := range ids {
		rs = append(rs, &rules.Rule{ID: id, Set: set})
	}
	return rs
}

// errText returns err's message, or "" for nil.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
