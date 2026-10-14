package ruletest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// recordedOutput returns the output of the opengrep run recorded as name.
func recordedOutput(t *testing.T, name string) Output {
	t.Helper()
	stdout, err := os.ReadFile(filepath.Join("testdata", "sarif", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	exit, err := os.ReadFile(filepath.Join("testdata", "sarif", name+".exit"))
	if err != nil {
		t.Fatal(err)
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(exit)))
	if err != nil {
		t.Fatalf("%s.exit: %v", name, err)
	}
	return Output{Stdout: stdout, Code: code}
}

// runLog returns the JSON of a one-run SARIF log of opengrep with rules
// loaded.
func runLog(rules []string, results, notes []any) []byte {
	var descs []any
	for _, id := range rules {
		descs = append(descs, map[string]any{"id": id})
	}
	data, err := json.Marshal(map[string]any{
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":        map[string]any{"driver": map[string]any{"name": "Opengrep OSS", "rules": descs}},
			"invocations": []any{map[string]any{"executionSuccessful": true, "toolExecutionNotifications": notes}},
			"results":     results,
		}},
	})
	if err != nil {
		panic(err)
	}
	return data
}

// rejected returns the message of the SemgrepError with which opengrep
// reports that opengrep-core rejected a rule for cause, shortened.
func rejected(cause string) string {
	return "Error while matching: non-zero exit status with one or more errors in json response\n" +
		"opengrep-core exit code: 2\n" +
		"unexpected errors in json output after invoking opengrep-core:\n" +
		"   Fatal error :\n" +
		" " + cause
}

// Each row of the design's §6.3, on the recorded runs.
func TestClassifyRecorded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		samples []string
		stage   Stage
		desc    string // the description's lines, joined; a prefix when it ends in "..."
	}{
		{"results", []string{"safe.go", "sample.go", "sub/broken.go", "sub/runner_test.go"}, "", ""},
		{"multiline-message", []string{"crlf.go", "ctl.go", "invalid.go", "lf.go"}, "", ""},
		{"invalid-schema", nil, StageRule, "InvalidRuleSchemaError: One of these properties is missing: 'message'\n" +
			"SemgrepError: invalid configuration file found (1 configs were invalid)"},
		{"bad-pattern", nil, StageRule, "Rule parse error: Rule parse error in rule project.go.no-exec-command:\n" +
			` Invalid pattern for Go: Parsing_error.Lexical_error (look_close_paren, _NOT_A_FILE_:1:12 "(")` + "\n" +
			"----- pattern -----\nexec.Command($CMD, ...\n----- end pattern -----"},
		{"unknown-language", nil, StageRule, "UnknownLanguageError: unsupported language: golang-ish. supported languages are: apex, ..."},
		{"file-not-found", nil, StageRun, "SemgrepError: File not found: missing.go\nopengrep exited with code 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table, stage, desc := Classify(recordedOutput(t, tt.name), testRuleID, tt.samples)
			got := strings.Join(desc, "\n")
			if want, ok := strings.CutSuffix(tt.desc, "..."); ok && strings.HasPrefix(got, want) {
				got = tt.desc
			}
			if stage != tt.stage || got != tt.desc {
				t.Errorf("Classify(%s) = %q, %q; want %q, %q", tt.name, stage, got, tt.stage, tt.desc)
			}
			if tt.stage != "" {
				if table != nil {
					t.Errorf("Classify(%s) table = %q, want none", tt.name, table)
				}
				return
			}
			want, err := os.ReadFile(filepath.Join("testdata", "sarif", tt.name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			if string(table) != string(want) {
				t.Errorf("Classify(%s) table =\n%s\nwant\n%s", tt.name, table, want)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()
	ok := result("a.go", [4]int{1, 1, 1, 2}, "m")
	other := result("a.go", [4]int{1, 1, 1, 2}, "m")
	other["ruleId"] = "project.go.other"
	noLocation := map[string]any{"ruleId": testRuleID, "message": map[string]any{"text": "m"}}
	// 25 lines of stderr, the 10th blank, of which the last 20 show.
	var long, last []string
	for i := 1; i <= 25; i++ {
		l, q := fmt.Sprintf("line %d  ", i), fmt.Sprintf("> line %d", i)
		if i == 10 {
			l, q = " ", ">"
		}
		long = append(long, l)
		if i > 5 {
			last = append(last, q)
		}
	}
	tests := []struct {
		name  string
		out   Output
		stage Stage
		desc  string // the description's lines, joined
		table string
	}{
		{"passes", Output{Stdout: sarifLog([]any{ok}, nil)}, "", "", "| a.go:1:1:1:2 | m |\n"},
		{"passes with warnings",
			Output{Stdout: sarifLog([]any{ok}, []any{note("warning", "Syntax error", "at a.go:3")}), Stderr: []byte("noise\n")},
			"", "", "#select\n| a.go:1:1:1:2 | m |\ndiagnostics\n| warning | Syntax error | at a.go:3 |\n"},

		// Row 1: the run cannot be trusted.
		{"not started", Output{Err: errors.New(`exec: "opengrep": executable file not found in $PATH`), Code: -1},
			StageRun, `running opengrep: exec: "opengrep": executable file not found in $PATH`, ""},
		{"killed", Output{Stdout: []byte(`{"version":`), Stderr: []byte("Scanning...\n"), Err: errors.New("signal: killed"), Code: -1},
			StageRun, "running opengrep: signal: killed\n> Scanning...", ""},
		{"not JSON", Output{Stdout: []byte("Fatal error\n"), Stderr: []byte("boom\r\n"), Code: 2},
			StageRun, "output is not a SARIF log: invalid character 'F' looking for beginning of value\nopengrep exited with code 2\n> boom", ""},
		{"no output", Output{}, StageRun, "output is not a SARIF log: unexpected end of JSON input\nopengrep exited with code 0", ""},
		{"stderr tail", Output{Stderr: []byte(strings.Join(long, "\r\n") + "\n\n \n")}, StageRun,
			"output is not a SARIF log: unexpected end of JSON input\nopengrep exited with code 0\n" + strings.Join(last, "\n"), ""},
		{"stderr blank lines", Output{Stderr: []byte("\n  \n\tline\n\n \n")}, StageRun,
			"output is not a SARIF log: unexpected end of JSON input\nopengrep exited with code 0\n> \tline", ""},
		{"no location before a rule error", Output{Stdout: runLog(nil, []any{noLocation}, []any{note("error", "InvalidRuleSchemaError", "x")}), Code: 7},
			StageRun, "result 1 has no location\nopengrep exited with code 7", ""},

		// Row 2: opengrep did not load the rule.
		{"exit 7 with the rule listed", Output{Stdout: sarifLog(nil, []any{note("error", "InvalidRuleSchemaError", "bad\n")}), Code: 7},
			StageRule, "InvalidRuleSchemaError: bad", ""},
		{"exit 8 without notifications", Output{Stdout: sarifLog(nil, nil), Stderr: []byte("unknown language\n"), Code: 8},
			StageRule, "opengrep did not load rule project.go.no-exec-command\n> unknown language", ""},
		{"rule missing, exit 0", Output{Stdout: runLog(nil, nil, []any{note("warning", "W", "w")}), Stderr: []byte("oops\n")},
			StageRule, "opengrep did not load rule project.go.no-exec-command\nW: w\n> oops", ""},
		{"other rule loaded", Output{Stdout: runLog([]string{"project.go.other"}, []any{other}, nil)},
			StageRule, "opengrep did not load rule project.go.no-exec-command", ""},
		// What opengrep 1.30.2 reports, shortened, for an unknown key under
		// options:, a metavariable-pattern in an unknown language, and
		// min-version: 99.0.0 (verified). Their messages hold paths on the
		// machine that ran them, so they are not recorded.
		{"options rejected by opengrep-core", Output{Stdout: runLog(nil, nil, []any{note("error", "SemgrepError", rejected("Failure: Found unknown JSON field nonexistent_option"))}), Code: 2},
			StageRule, "SemgrepError: " + rejected("Failure: Found unknown JSON field nonexistent_option"), ""},
		{"language rejected by opengrep-core", Output{Stdout: runLog(nil, nil, []any{note("error", "SemgrepError", rejected(`Xlang.InternalInvalidLanguage("project.go.no-exec-command", "unsupported language: nosuchlang")`))}), Code: 2},
			StageRule, "SemgrepError: " + rejected(`Xlang.InternalInvalidLanguage("project.go.no-exec-command", "unsupported language: nosuchlang")`), ""},
		{"min-version", Output{Stdout: runLog(nil, nil, []any{
			note("note", "Incompatible rule", "Incompatible rule cache.project.go.no-exec-command:\n This rule requires upgrading Opengrep from version 1.30.2 (Semgrep 1.100.0) to a version compatible with Semgrep 99.0.0 or higher"),
			note("error", "SemgrepError", "No config given. Run with `--config auto` or see https://semgrep.dev/docs/running-rules/ for instructions on running with a specific config\n"),
		}), Stderr: []byte("oops\n"), Code: 7},
			StageRule, "Incompatible rule: Incompatible rule cache.project.go.no-exec-command:\n" +
				" This rule requires upgrading Opengrep from version 1.30.2 (Semgrep 1.100.0) to a version compatible with Semgrep 99.0.0 or higher\n" +
				"SemgrepError: No config given. Run with `--config auto` or see https://semgrep.dev/docs/running-rules/ for instructions on running with a specific config", ""},

		// Row 3: opengrep failed.
		{"exit 1", Output{Stdout: sarifLog([]any{ok}, nil), Stderr: []byte("oops\n"), Code: 1},
			StageRun, "opengrep exited with code 1\n> oops", ""},
		{"error notification, exit 0", Output{Stdout: sarifLog([]any{ok}, []any{note("error", "Fatal", "a\r\nb"), note("warning", "W", "w")})},
			StageRun, "Fatal: a\nb\nopengrep exited with code 0", ""},
		{"missing target", Output{Stdout: runLog(nil, nil, []any{note("error", "SemgrepError", "File not found: x.go"), note("warning", "W", "w")}), Code: 2},
			StageRun, "SemgrepError: File not found: x.go\nopengrep exited with code 2", ""},

		// Row 4: a result of another rule.
		{"other rule id", Output{Stdout: runLog([]string{testRuleID, "project.go.other"}, []any{ok, other}, nil)},
			StageRun, "unexpected rule id project.go.other", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table, stage, desc := Classify(tt.out, testRuleID, []string{"a.go"})
			if got := strings.Join(desc, "\n"); stage != tt.stage || got != tt.desc || string(table) != tt.table {
				t.Errorf("Classify = %q, %q, %q; want %q, %q, %q", table, stage, got, tt.table, tt.stage, tt.desc)
			}
		})
	}
}
