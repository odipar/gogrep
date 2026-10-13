package ruletest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The SARIF logs in testdata/sarif are opengrep 1.30.2's stdout for the argv
// of docs/design/rule-test-fixtures.md §6.2, and each .exit file holds the
// exit code. They were recorded by running this bash script in an empty
// directory with opengrep 1.30.2 on $PATH and LC_ALL=C.UTF-8, as gogrep runs
// it. fx holds the samples of the design's §2.4 worked example and rule.yaml
// its rule as rules.Write writes it; the ml samples have matches with
// multi-line messages and characters that need escaping. Each .txt file is
// the table that Render must make of the log with the same name; results.txt
// is copied from §2.4.
//
//	mkdir -p fx/sub ml
//	printf 'package sample\n\nimport "os/exec"\n\nfunc run(name string) {\n\texec.Command(name, "-v")\n\t_ = exec.Command("ls")\n}\n' >fx/sample.go
//	printf 'package safe\n\nimport "os"\n\nfunc ok() { os.Getenv("HOME") }\n' >fx/safe.go
//	printf 'package sub\n\nimport "os/exec"\n\nfunc TestRun() { exec.Command("go", "test") }\n' >fx/sub/runner_test.go
//	printf 'package sample\n\nimport "os/exec"\n\nfunc f() {\n\texec.Command("a")\n\tx := := 1\n\texec.Command("b")\n}\n' >fx/sub/broken.go
//	p='package ml\n\nimport (\n\t"fmt"\n\t"os/exec"\n)\n\nfunc run(x, y int) {\n\texec.Command(fmt.Sprint(x|\n\t\ty), "-v")\n}\n'
//	printf "$p" >ml/lf.go
//	printf "${p//\\n/\\r\\n}" >ml/crlf.go
//	printf 'package ml\n\nimport "os/exec"\n\nfunc ctl() {\n\texec.Command(`\033[31m`)\n\texec.Command(`a\\b`)\n\texec.Command("h\303\251llo\342\206\222")\n}\n' >ml/ctl.go
//	printf 'package ml\n\nimport "os/exec"\n\nfunc bad() {\n\texec.Command(`\377\376`)\n}\n' >ml/invalid.go
//	rule() { printf 'rules:\n    - id: project.go.no-exec-command\n      languages: [%s]\n      severity: WARNING\n%b      pattern: %s\n' "$@"; }
//	m='      message: Avoid running $CMD with exec.Command\n'
//	rule go "$m" 'exec.Command($CMD, ...)' >rule.yaml
//	rule go '' 'exec.Command($CMD, ...)' >no-message.yaml
//	rule go "$m" 'exec.Command($CMD, ...' >unclosed.yaml
//	rule golang-ish "$m" 'exec.Command($CMD, ...)' >golang-ish.yaml
//	rec() { (cd "$1" && opengrep scan --config "$OLDPWD/$3" --no-rewrite-rule-ids --sarif --disable-version-check -j 1 -- "${@:4}" >"$OLDPWD/$2.json"; echo $? >"$OLDPWD/$2.exit"); }
//	rec fx results rule.yaml ./safe.go ./sample.go ./sub/broken.go ./sub/runner_test.go
//	rec fx invalid-schema no-message.yaml ./safe.go ./sample.go ./sub/runner_test.go
//	rec fx bad-pattern unclosed.yaml ./safe.go ./sample.go ./sub/runner_test.go
//	rec fx unknown-language golang-ish.yaml ./safe.go ./sample.go ./sub/runner_test.go
//	rec fx file-not-found rule.yaml ./missing.go ./sample.go
//	rec ml multiline-message rule.yaml ./crlf.go ./ctl.go ./invalid.go ./lf.go

const testRuleID = "project.go.no-exec-command"

// recorded returns the SARIF log and exit code recorded as name.
func recorded(t *testing.T, name string) (*Log, int) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "sarif", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	log, err := DecodeSARIF(data)
	if err != nil {
		t.Fatalf("DecodeSARIF(%s.json): %v", name, err)
	}
	exit, err := os.ReadFile(filepath.Join("testdata", "sarif", name+".exit"))
	if err != nil {
		t.Fatal(err)
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(exit)))
	if err != nil {
		t.Fatalf("%s.exit: %v", name, err)
	}
	return log, code
}

// TestDecodeSARIFRecorded pins down what opengrep reports in each recorded
// run, which classifying a run relies on.
func TestDecodeSARIFRecorded(t *testing.T) {
	tests := []struct {
		name    string
		code    int
		rules   []string
		results int
		notes   []string // level and descriptor id of each notification
	}{
		{"results", 0, []string{testRuleID}, 5, []string{"warning Syntax error"}},
		{"multiline-message", 0, []string{testRuleID}, 6, nil},
		{"invalid-schema", 7, nil, 0, []string{"error InvalidRuleSchemaError", "error SemgrepError"}},
		{"bad-pattern", 2, nil, 0, []string{"error Rule parse error"}},
		{"unknown-language", 8, nil, 0, []string{"error UnknownLanguageError"}},
		{"file-not-found", 2, nil, 0, []string{"error SemgrepError"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, code := recorded(t, tt.name)
			run := log.Runs[0]
			var rules, notes []string
			for _, r := range run.Tool.Driver.Rules {
				rules = append(rules, r.ID)
			}
			for _, inv := range run.Invocations {
				for _, n := range inv.ToolExecutionNotifications {
					notes = append(notes, n.Level+" "+n.Descriptor.ID)
				}
			}
			if code != tt.code || !slices.Equal(rules, tt.rules) || len(run.Results) != tt.results || !slices.Equal(notes, tt.notes) {
				t.Errorf("%s: exit %d, rules %q, %d results, notifications %q; want exit %d, rules %q, %d results, notifications %q",
					tt.name, code, rules, len(run.Results), notes, tt.code, tt.rules, tt.results, tt.notes)
			}
			for _, r := range run.Results {
				if r.RuleID != testRuleID {
					t.Errorf("%s: result rule id %q, want %q", tt.name, r.RuleID, testRuleID)
				}
			}
		})
	}
}

func TestRenderRecorded(t *testing.T) {
	tests := []struct {
		name    string
		samples []string
	}{
		{"results", []string{"safe.go", "sample.go", "sub/broken.go", "sub/runner_test.go"}},
		{"multiline-message", []string{"crlf.go", "ctl.go", "invalid.go", "lf.go"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, _ := recorded(t, tt.name)
			want, err := os.ReadFile(filepath.Join("testdata", "sarif", tt.name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Render(log, tt.samples)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("Render(%s.json) =\n%s\nwant\n%s", tt.name, got, want)
			}
		})
	}

	// Without sub/broken.go, the §2.4 run gives the plain expected.txt.
	log, _ := recorded(t, "results")
	run := &log.Runs[0]
	run.Results = slices.DeleteFunc(run.Results, func(r Result) bool {
		return r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "sub/broken.go"
	})
	run.Invocations = nil
	const want = `| sample.go:6:2:6:26 | Avoid running name with exec.Command |
| sample.go:7:6:7:24 | Avoid running "ls" with exec.Command |
| sub/runner_test.go:5:18:5:44 | Avoid running "go" with exec.Command |
`
	if got, err := Render(log, []string{"safe.go", "sample.go", "sub/runner_test.go"}); string(got) != want || err != nil {
		t.Errorf("Render(results.json without sub/broken.go) = %q, %v; want %q", got, err, want)
	}
}

// result returns a SARIF result of testRuleID at uri and region.
func result(uri string, region [4]int, msg string) map[string]any {
	return map[string]any{
		"ruleId":  testRuleID,
		"message": map[string]any{"text": msg},
		"locations": []any{map[string]any{"physicalLocation": map[string]any{
			"artifactLocation": map[string]any{"uri": uri},
			"region": map[string]any{
				"startLine": region[0], "startColumn": region[1], "endLine": region[2], "endColumn": region[3],
			},
		}}},
	}
}

// note returns a SARIF notification; an empty level is left out.
func note(level, id, msg string) map[string]any {
	n := map[string]any{"descriptor": map[string]any{"id": id}, "message": map[string]any{"text": msg}}
	if level != "" {
		n["level"] = level
	}
	return n
}

// sarifLog returns the JSON of a one-run SARIF log.
func sarifLog(results []any, notes []any) []byte {
	data, err := json.Marshal(map[string]any{
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":        map[string]any{"driver": map[string]any{"name": "Opengrep OSS", "rules": []any{map[string]any{"id": testRuleID}}}},
			"invocations": []any{map[string]any{"executionSuccessful": true, "toolExecutionNotifications": notes}},
			"results":     results,
		}},
	})
	if err != nil {
		panic(err)
	}
	return data
}

func TestRender(t *testing.T) {
	tests := []struct {
		name           string
		results, notes []any
		want           string
	}{
		{"empty", nil, nil, ""},
		{"sorted by path bytewise, then numerically by position, then by message",
			[]any{
				result("b.go", [4]int{10, 1, 10, 5}, "m"),
				result("b.go", [4]int{9, 12, 9, 15}, "m"),
				result("b.go", [4]int{9, 2, 10, 1}, "m"),
				result("b.go", [4]int{9, 2, 9, 30}, "m"),
				result("b.go", [4]int{9, 2, 9, 4}, "z"),
				result("b.go", [4]int{9, 2, 9, 4}, "a"),
				result("a2.go", [4]int{1, 1, 1, 2}, "m"),
				result("a.go", [4]int{1, 1, 1, 2}, "m"),
				result("B.go", [4]int{1, 1, 1, 2}, "m"),
				result("a/b.go", [4]int{1, 1, 1, 2}, "m"),
			}, nil,
			"| B.go:1:1:1:2 | m |\n" +
				"| a.go:1:1:1:2 | m |\n" +
				"| a/b.go:1:1:1:2 | m |\n" +
				"| a2.go:1:1:1:2 | m |\n" +
				"| b.go:9:2:9:4 | a |\n" +
				"| b.go:9:2:9:4 | z |\n" +
				"| b.go:9:2:9:30 | m |\n" +
				"| b.go:9:2:10:1 | m |\n" +
				"| b.go:9:12:9:15 | m |\n" +
				"| b.go:10:1:10:5 | m |\n"},
		{"duplicates kept",
			[]any{result("a.go", [4]int{1, 1, 1, 2}, "m"), result("a.go", [4]int{1, 1, 1, 2}, "m")}, nil,
			"| a.go:1:1:1:2 | m |\n| a.go:1:1:1:2 | m |\n"},
		{"messages sort and render with CRLF as LF",
			[]any{result("a.go", [4]int{1, 1, 1, 2}, "x\r\ny"), result("a.go", [4]int{1, 1, 1, 2}, "x\nx")}, nil,
			"| a.go:1:1:1:2 | x\\nx |\n| a.go:1:1:1:2 | x\\ny |\n"},
		{"uris made relative and slashed, never decoded",
			[]any{
				result(`.\sub\a.go`, [4]int{1, 1, 1, 2}, "m"),
				result("./b.go", [4]int{1, 1, 1, 2}, "m"),
				result("sub dir/a%20b|c.go", [4]int{1, 1, 1, 2}, "m"),
			}, nil,
			"| b.go:1:1:1:2 | m |\n" +
				"| sub dir/a%20b\\|c.go:1:1:1:2 | m |\n" +
				"| sub/a.go:1:1:1:2 | m |\n"},
		{"diagnostics only",
			nil, []any{note("warning", "Syntax error", "Syntax error at line a.go:1:\n `)` was unexpected")},
			"#select\ndiagnostics\n| warning | Syntax error | Syntax error at line a.go:1:\\n `)` was unexpected |\n"},
		{"diagnostics below error level, sorted, warning by default",
			[]any{result("a.go", [4]int{1, 1, 1, 2}, "m")},
			[]any{
				note("warning", "W", "b"),
				note("error", "SemgrepError", "File not found: x.go"),
				note("", "Missing", "a"),
				note("note", "N|x", "c\td"),
				note("none", "None", "e"),
				note("warning", "W", "a"),
			},
			"#select\n" +
				"| a.go:1:1:1:2 | m |\n" +
				"diagnostics\n" +
				"| none | None | e |\n" +
				"| note | N\\|x | c\\td |\n" +
				"| warning | Missing | a |\n" +
				"| warning | W | a |\n" +
				"| warning | W | b |\n"},
		{"error notifications only",
			nil, []any{note("error", "Rule parse error", "x")}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := DecodeSARIF(sarifLog(tt.results, tt.notes))
			if err != nil {
				t.Fatalf("DecodeSARIF: %v", err)
			}
			got, err := Render(log, []string{"a.go"})
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("Render =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

func TestRenderErrors(t *testing.T) {
	region := `"region":{"startLine":1,"startColumn":1,"endLine":1,"endColumn":2}`
	tests := []struct {
		name, result, err string
	}{
		{"no location", `{"ruleId":"r","message":{"text":"m"}}`, "result 1 has no location"},
		{"no region", `{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"}}}]}`,
			"result 1 in a.go has an incomplete region 0:0:0:0"},
		{"zero column", `{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1,"startColumn":0,"endLine":1,"endColumn":2}}}]}`,
			"result 1 in a.go has an incomplete region 1:0:1:2"},
		{"no end line", `{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1,"startColumn":1,"endColumn":2}}}]}`,
			"result 1 in a.go has an incomplete region 1:1:0:2"},
	}
	for _, uri := range []string{"", "./", "/tmp/a.go", `C:\x\a.go`, "c:/x/a.go", "..", "../a.go", `..\a.go`, `.\..\a.go`, "file:///tmp/a.go"} {
		uriJSON, _ := json.Marshal(uri)
		tests = append(tests, struct{ name, result, err string }{
			"uri " + uri,
			`{"locations":[{"physicalLocation":{"artifactLocation":{"uri":` + string(uriJSON) + `},` + region + `}}]}`,
			"result 1 has uri " + strconv.Quote(uri) + ", which is not a path in the fixture",
		})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := `{"version":"2.1.0","runs":[{"results":[` + tt.result + `]}]}`
			log, err := DecodeSARIF([]byte(data))
			if err != nil {
				t.Fatalf("DecodeSARIF(%s): %v", data, err)
			}
			got, err := Render(log, nil)
			if got != nil || errText(err) != tt.err {
				t.Errorf("Render(%s) = %q, %q; want nil, %q", data, got, errText(err), tt.err)
			}
		})
	}
}

func TestDecodeSARIFErrors(t *testing.T) {
	tests := []struct {
		name, data, err string // err is a prefix of the error
	}{
		{"empty", "", "output is not a SARIF log: "},
		{"text", "Opengrep crashed\n", "output is not a SARIF log: "},
		{"two documents", `{"version":"2.1.0","runs":[{}]}{}`, "output is not a SARIF log: "},
		{"wrong type", `{"version":"2.1.0","runs":[{"results":[{"locations":[{"physicalLocation":{"region":{"startLine":"1"}}}]}]}]}`,
			"output is not a SARIF log: "},
		{"no version", `{"runs":[{}]}`, `output is not a SARIF 2.1.0 log (version "")`},
		{"old version", `{"version":"2.0.0","runs":[{}]}`, `output is not a SARIF 2.1.0 log (version "2.0.0")`},
		{"no runs", `{"version":"2.1.0","runs":[]}`, "SARIF log has 0 runs, want 1"},
		{"two runs", `{"version":"2.1.0","runs":[{},{}]}`, "SARIF log has 2 runs, want 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := DecodeSARIF([]byte(tt.data))
			if log != nil || err == nil || !strings.HasPrefix(err.Error(), tt.err) {
				t.Errorf("DecodeSARIF(%q) = %v, %q; want nil, %q...", tt.data, log, errText(err), tt.err)
			}
		})
	}
}

func TestEscape(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain text", "plain text"},
		{"bad a|b\n\tc", `bad a\|b\n\tc`},
		{`C:\dir\file`, `C:\\dir\\file`},
		{`\|`, `\\\|`},
		{"a\r\nb", `a\nb`},
		{"a\rb", `a\rb`},
		{"a\r\r\nb", `a\r\nb`},
		{"\x00\x01\x1b\x1f\x7f", `\u0000\u0001\u001B\u001F\u007F`},
		{"\xff", `\xFF`},
		{"a\xe2\x86b", `a\xE2\x86b`},
		{"héllo→ \uFFFD \u0085 \u2028", "héllo→ \uFFFD \u0085 \u2028"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := escape(tt.in); got != tt.want {
			t.Errorf("escape(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSlashPaths(t *testing.T) {
	samples := []string{"a.go", "sub/broken.go", "x/a.go", "y/x/a.go"}
	tests := []struct {
		name, msg string
		sep       byte
		want      string
	}{
		{"slash separator", `Syntax error at line sub/broken.go:7: and sub\broken.go`, '/', `Syntax error at line sub/broken.go:7: and sub\broken.go`},
		{"native path", `Syntax error at line sub\broken.go:7:`, '\\', "Syntax error at line sub/broken.go:7:"},
		{"leading dot", `Syntax error at line .\sub\broken.go:7:`, '\\', "Syntax error at line sub/broken.go:7:"},
		{"leading dot, no directory", `in .\a.go and a.go`, '\\', "in a.go and a.go"},
		{"longest path wins", `y\x\a.go, x\a.go, .\y\x\a.go`, '\\', "y/x/a.go, x/a.go, y/x/a.go"},
		{"other paths untouched", `C:\other\b.go`, '\\', `C:\other\b.go`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := slashPaths(tt.msg, samples, tt.sep); got != tt.want {
				t.Errorf("slashPaths(%q, %q) = %q, want %q", tt.msg, tt.sep, got, tt.want)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"\n\n", nil},
		{"\uFEFF", nil},
		{"a\nb\n", []string{"a", "b"}},
		{"a\nb", []string{"a", "b"}},
		{"\uFEFFa\r\nb\r\n\r\n\n", []string{"a", "b"}},
		{"a\n\nb\n", []string{"a", "", "b"}},
		{"a\rb\n", []string{"a\rb"}},
		{" a \n", []string{" a "}},
	}
	for _, tt := range tests {
		if got := Normalize([]byte(tt.in)); !slices.Equal(got, tt.want) {
			t.Errorf("Normalize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
