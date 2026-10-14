package sarif

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// describe returns findings as text, a line each, without fingerprints.
func describe(findings []Finding) string {
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "%s %s %s:%d:%d:%d:%d %q %q", f.Level, f.RuleID, f.Path, f.StartLine, f.StartColumn, f.EndLine, f.EndColumn, f.Message, f.Snippet)
		if f.Suppressed {
			b.WriteString(" suppressed")
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func TestFindingsRecorded(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, want string }{
		// opengrep maps CRITICAL and HIGH to error, MEDIUM to warning and
		// LOW to note, in the rule's default level only.
		{"levels", `error project.generic.error a.txt:1:1:1:3 "error severity" "E1"
warning project.generic.warning a.txt:2:1:2:3 "warning severity" "W1"
note project.generic.info a.txt:3:1:3:3 "info severity" "I1"
error project.generic.critical a.txt:4:1:4:3 "critical severity" "C1"
error project.generic.high a.txt:5:1:5:3 "high severity" "H1"
warning project.generic.medium a.txt:6:1:6:3 "medium severity" "M1"
note project.generic.low a.txt:7:1:7:3 "low severity" "L1"
`},
		// A nosemgrep comment for another rule suppresses nothing.
		{"suppressed", `warning project.go.no-exec-command a.go:6:2:6:19 "Avoid running \"a\" with exec.Command" "\texec.Command(\"a\")"
warning project.go.no-exec-command a.go:7:2:7:19 "Avoid running \"b\" with exec.Command" "\texec.Command(\"b\") // nosemgrep" suppressed
warning project.go.no-exec-command a.go:8:2:8:19 "Avoid running \"c\" with exec.Command" "\texec.Command(\"c\") // nosemgrep: project.go.no-exec-command" suppressed
warning project.go.no-exec-command a.go:9:2:9:19 "Avoid running \"d\" with exec.Command" "\texec.Command(\"d\") // nosemgrep: project.go.other"
warning project.go.no-exec-command a.go:11:2:11:19 "Avoid running \"e\" with exec.Command" "\texec.Command(\"e\")" suppressed
`},
		{"raw-uri", `warning project.go.no-exec-command B.go:5:12:5:33 "Avoid running \"upper\" with exec.Command" "func u() { exec.Command(\"upper\") }"
warning project.go.no-exec-command a.go:6:2:8:3 "Avoid running \"multi\" with exec.Command" "\texec.Command(\n\t\t\"multi\",\n\t)"
warning project.go.no-exec-command a.go:9:2:9:19 "Avoid running \"a\" with exec.Command" "\texec.Command(\"a\")"
warning project.go.no-exec-command b c%41.go:5:12:5:34 "Avoid running \"b c%41\" with exec.Command" "func f() { exec.Command(\"b c%41\") }"
warning project.go.no-exec-command sub/z.go:5:12:5:31 "Avoid running \"sub\" with exec.Command" "func h() { exec.Command(\"sub\") }"
`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := decodeRecorded(t, tt.name).Findings()
			if got := describe(fs); got != tt.want {
				t.Errorf("Findings(%s.json) =\n%s\nwant\n%s", tt.name, got, tt.want)
			}
		})
	}

	fingerprint := regexp.MustCompile(`^[0-9a-f]{128}_[0-9]+$`)
	for _, name := range recordings(t) {
		fs := decodeRecorded(t, name).Findings()
		for _, f := range fs {
			if !fingerprint.MatchString(f.Fingerprint) {
				t.Errorf("%s: %s:%d has fingerprint %q", name, f.Path, f.StartLine, f.Fingerprint)
			}
		}
		if !slices.IsSortedFunc(fs, compareFindings) {
			t.Errorf("%s: findings not sorted:\n%s", name, describe(fs))
		}
	}
}

// compareFindings orders findings as Findings sorts them.
func compareFindings(a, b Finding) int {
	ka := fmt.Sprintf("%s\x00%010d%010d%010d%010d%s\x00%s", a.Path, a.StartLine, a.StartColumn, a.EndLine, a.EndColumn, a.RuleID, a.Fingerprint)
	kb := fmt.Sprintf("%s\x00%010d%010d%010d%010d%s\x00%s", b.Path, b.StartLine, b.StartColumn, b.EndLine, b.EndColumn, b.RuleID, b.Fingerprint)
	return strings.Compare(ka, kb)
}

// logJSON returns a one-run SARIF log with the rules, each an id and a
// default level, and results.
func logJSON(rules [][2]string, results []any, invocations []any) []byte {
	var descs []any
	for _, r := range rules {
		descs = append(descs, map[string]any{"id": r[0], "defaultConfiguration": map[string]any{"level": r[1]}})
	}
	data, err := json.Marshal(map[string]any{
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":        map[string]any{"driver": map[string]any{"name": "Opengrep OSS", "rules": descs}},
			"invocations": invocations,
			"results":     results,
		}},
	})
	if err != nil {
		panic(err)
	}
	return data
}

// result returns a SARIF result of rule at uri and region, with fields
// added or replaced by extra.
func result(rule, uri string, region [4]int, extra map[string]any) map[string]any {
	r := map[string]any{
		"ruleId":       rule,
		"message":      map[string]any{"text": "m"},
		"fingerprints": map[string]any{fingerprintKey: "fp", "other/v1": "x"},
		"locations": []any{map[string]any{"physicalLocation": map[string]any{
			"artifactLocation": map[string]any{"uri": uri},
			"region": map[string]any{
				"startLine": region[0], "startColumn": region[1], "endLine": region[2], "endColumn": region[3],
				"snippet": map[string]any{"text": "s"},
			},
		}}},
	}
	for k, v := range extra {
		r[k] = v
	}
	return r
}

func decode(t *testing.T, data []byte) *Log {
	t.Helper()
	log, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode(%s): %v", data, err)
	}
	return log
}

func TestFindings(t *testing.T) {
	t.Parallel()
	rules := [][2]string{{"r.error", "error"}, {"r.note", "note"}, {"r.none", ""}, {"r.note", "error"}}
	inSource := func(status string) map[string]any {
		s := map[string]any{"kind": "inSource"}
		if status != "" {
			s["status"] = status
		}
		return s
	}
	at := [4]int{1, 1, 1, 2}
	results := []any{
		result("r.error", "levels.go", at, nil),
		result("r.note", "levels.go", at, nil),
		result("r.none", "levels.go", at, nil),
		result("r.unlisted", "levels.go", at, nil),
		result("r.note", "levels.go", at, map[string]any{"level": "warning", "fingerprints": map[string]any{fingerprintKey: "own level"}}),
		result("r.error", "suppressions.go", [4]int{1, 1, 1, 2}, map[string]any{"suppressions": []any{inSource("")}}),
		result("r.error", "suppressions.go", [4]int{2, 1, 2, 2}, map[string]any{"suppressions": []any{inSource("accepted")}}),
		result("r.error", "suppressions.go", [4]int{3, 1, 3, 2}, map[string]any{"suppressions": []any{inSource("underReview")}}),
		result("r.error", "suppressions.go", [4]int{4, 1, 4, 2}, map[string]any{"suppressions": []any{inSource("rejected")}}),
		result("r.error", "suppressions.go", [4]int{5, 1, 5, 2}, map[string]any{"suppressions": []any{map[string]any{"kind": "external"}}}),
		result("r.error", "suppressions.go", [4]int{6, 1, 6, 2}, map[string]any{"suppressions": []any{map[string]any{"kind": "external"}, inSource("")}}),
		result("r.error", "suppressions.go", [4]int{7, 1, 7, 2}, map[string]any{"suppressions": []any{}}),
		result("r.error", "./dot.go", at, map[string]any{"message": map[string]any{"text": "a leading ./ goes"}}),
		result("r.error", "sub/./x%20y.go", at, map[string]any{"message": map[string]any{"text": "kept as written"}}),
		map[string]any{"ruleId": "r.error", "message": map[string]any{"text": "no location"}},
	}
	got := decode(t, logJSON(rules, results, nil)).Findings()
	const want = `error r.error :0:0:0:0 "no location" ""
error r.error dot.go:1:1:1:2 "a leading ./ goes" "s"
error r.error levels.go:1:1:1:2 "m" "s"
warning r.none levels.go:1:1:1:2 "m" "s"
note r.note levels.go:1:1:1:2 "m" "s"
warning r.note levels.go:1:1:1:2 "m" "s"
warning r.unlisted levels.go:1:1:1:2 "m" "s"
error r.error sub/./x%20y.go:1:1:1:2 "kept as written" "s"
error r.error suppressions.go:1:1:1:2 "m" "s" suppressed
error r.error suppressions.go:2:1:2:2 "m" "s" suppressed
error r.error suppressions.go:3:1:3:2 "m" "s"
error r.error suppressions.go:4:1:4:2 "m" "s"
error r.error suppressions.go:5:1:5:2 "m" "s"
error r.error suppressions.go:6:1:6:2 "m" "s" suppressed
error r.error suppressions.go:7:1:7:2 "m" "s"
`
	if describe(got) != want {
		t.Errorf("Findings =\n%s\nwant\n%s", describe(got), want)
	}
	if got[0].Fingerprint != "" || got[1].Fingerprint != "fp" || got[4].Fingerprint != "fp" || got[5].Fingerprint != "own level" {
		t.Errorf("fingerprints %q, %q, %q, %q; want \"\", fp, fp, own level", got[0].Fingerprint, got[1].Fingerprint, got[4].Fingerprint, got[5].Fingerprint)
	}
}

// Findings sort by path bytewise, then numerically by region, then by rule
// id and fingerprint; findings equal in all of these keep the log's order.
func TestFindingsOrder(t *testing.T) {
	t.Parallel()
	fp := func(s string) map[string]any {
		return map[string]any{"fingerprints": map[string]any{fingerprintKey: s}, "message": map[string]any{"text": s}}
	}
	results := []any{
		result("r", "b.go", [4]int{10, 1, 10, 5}, nil),
		result("r", "b.go", [4]int{9, 12, 9, 15}, nil),
		result("r", "b.go", [4]int{9, 2, 10, 1}, nil),
		result("r", "b.go", [4]int{9, 2, 9, 30}, nil),
		result("r", "b.go", [4]int{9, 2, 9, 4}, fp("z")),
		result("r", "b.go", [4]int{9, 2, 9, 4}, fp("a")),
		result("r", "b.go", [4]int{9, 2, 9, 4}, fp("a2")),
		result("q", "b.go", [4]int{9, 2, 9, 4}, fp("z")),
		result("r", "b.go", [4]int{9, 2, 9, 4}, fp("a")),
		result("r", "a2.go", [4]int{1, 1, 1, 2}, nil),
		result("r", "a.go", [4]int{1, 1, 1, 2}, nil),
		result("r", "B.go", [4]int{1, 1, 1, 2}, nil),
		result("r", "a/b.go", [4]int{1, 1, 1, 2}, nil),
	}
	got := decode(t, logJSON(nil, results, nil)).Findings()
	const want = `warning r B.go:1:1:1:2 "m" "s"
warning r a.go:1:1:1:2 "m" "s"
warning r a/b.go:1:1:1:2 "m" "s"
warning r a2.go:1:1:1:2 "m" "s"
warning q b.go:9:2:9:4 "z" "s"
warning r b.go:9:2:9:4 "a" "s"
warning r b.go:9:2:9:4 "a" "s"
warning r b.go:9:2:9:4 "a2" "s"
warning r b.go:9:2:9:4 "z" "s"
warning r b.go:9:2:9:30 "m" "s"
warning r b.go:9:2:10:1 "m" "s"
warning r b.go:9:12:9:15 "m" "s"
warning r b.go:10:1:10:5 "m" "s"
`
	if describe(got) != want {
		t.Errorf("Findings =\n%s\nwant\n%s", describe(got), want)
	}
	if !slices.IsSortedFunc(got, compareFindings) {
		t.Error("compareFindings disagrees with Findings")
	}
}

func TestFindingPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		uri  string
		sep  byte
		want string
	}{
		{"a.go", '/', "a.go"},
		{"./a.go", '/', "a.go"},
		{"././a.go", '/', "./a.go"},
		{"sub/a.go", '/', "sub/a.go"},
		{"b c%41.go", '/', "b c%41.go"},
		{`a\b.go`, '/', `a\b.go`},
		{`.\a.go`, '/', `.\a.go`},
		{"", '/', ""},
		{`sub\a.go`, '\\', "sub/a.go"},
		{`.\sub\a.go`, '\\', "sub/a.go"},
		{"./sub/a.go", '\\', "sub/a.go"},
		{"b c%41.go", '\\', "b c%41.go"},
	}
	for _, tt := range tests {
		if got := findingPath(tt.uri, tt.sep); got != tt.want {
			t.Errorf("findingPath(%q, %q) = %q, want %q", tt.uri, tt.sep, got, tt.want)
		}
	}
}

func TestDiagnostics(t *testing.T) {
	t.Parallel()
	want := []Diagnostic{{Level: "warning", ID: "Syntax error", Message: "Syntax error at line sub/broken.go:7:\n `:=` was unexpected"}}
	if got := decodeRecorded(t, "results").Diagnostics(); !slices.Equal(got, want) {
		t.Errorf("Diagnostics(results.json) = %q, want %q", got, want)
	}
	note := func(level, id, msg string) map[string]any {
		n := map[string]any{"descriptor": map[string]any{"id": id}, "message": map[string]any{"text": msg}}
		if level != "" {
			n["level"] = level
		}
		return n
	}
	invocations := []any{
		map[string]any{"executionSuccessful": false, "toolExecutionNotifications": []any{note("error", "E", "e"), note("", "D", "default")}},
		map[string]any{"toolExecutionNotifications": []any{note("none", "N", "n")}},
	}
	log := decode(t, logJSON(nil, nil, invocations))
	want = []Diagnostic{{"error", "E", "e"}, {"warning", "D", "default"}, {"none", "N", "n"}}
	if got := log.Diagnostics(); !slices.Equal(got, want) {
		t.Errorf("Diagnostics = %q, want %q", got, want)
	}
	if log.Complete() {
		t.Error("Complete() = true for a run whose first invocation failed")
	}
}

func TestComplete(t *testing.T) {
	t.Parallel()
	tests := []struct {
		invocations []any
		want        bool
	}{
		{nil, false},
		{[]any{map[string]any{}}, false},
		{[]any{map[string]any{"executionSuccessful": true}}, true},
		{[]any{map[string]any{"executionSuccessful": false}, map[string]any{"executionSuccessful": true}}, false},
	}
	for _, tt := range tests {
		if got := decode(t, logJSON(nil, nil, tt.invocations)).Complete(); got != tt.want {
			t.Errorf("Complete() with invocations %v = %v, want %v", tt.invocations, got, tt.want)
		}
	}
}
