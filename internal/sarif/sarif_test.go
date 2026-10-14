package sarif

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The SARIF logs in testdata are opengrep 1.30.2's stdout for the argv of a
// scan that gogrep supplies rules to, and each .exit file holds the exit
// code. They were recorded by running this bash script in an empty directory
// with opengrep 1.30.2 on $PATH and LC_ALL=C.UTF-8, as gogrep runs it. levels
// has a rule of each severity, suppressed has nosemgrep comments, and
// raw-uri has a file name that percent-decoding would change, a multi-line
// match and a directory. The logs in ../ruletest/testdata/sarif are recorded
// by the script in ../ruletest/table_test.go.
//
//	mkdir -p levels raw-uri/sub suppressed
//	sev() { printf '    - id: project.generic.%s\n      languages: [generic]\n      severity: %s\n      message: %s severity\n      pattern: %s\n' "$1" "$2" "$1" "$3"; }
//	{ echo rules:; sev error ERROR E1; sev warning WARNING W1; sev info INFO I1; sev critical CRITICAL C1; sev high HIGH H1; sev medium MEDIUM M1; sev low LOW L1; } >levels.yaml
//	printf 'E1\nW1\nI1\nC1\nH1\nM1\nL1\n' >levels/a.txt
//	printf 'rules:\n    - id: project.go.no-exec-command\n      languages: [go]\n      severity: WARNING\n      message: Avoid running $CMD with exec.Command\n      pattern: exec.Command($CMD, ...)\n' >rule.yaml
//	printf 'package sup\n\nimport "os/exec"\n\nfunc run() {\n\texec.Command("a")\n\texec.Command("b") // nosemgrep\n\texec.Command("c") // nosemgrep: project.go.no-exec-command\n\texec.Command("d") // nosemgrep: project.go.other\n\t// nosemgrep\n\texec.Command("e")\n}\n' >suppressed/a.go
//	printf 'package raw\n\nimport "os/exec"\n\nfunc g() {\n\texec.Command(\n\t\t"multi",\n\t)\n\texec.Command("a")\n}\n' >raw-uri/a.go
//	printf 'package raw\n\nimport "os/exec"\n\nfunc u() { exec.Command("upper") }\n' >raw-uri/B.go
//	printf 'package raw\n\nimport "os/exec"\n\nfunc f() { exec.Command("b c%%41") }\n' >'raw-uri/b c%41.go'
//	printf 'package sub\n\nimport "os/exec"\n\nfunc h() { exec.Command("sub") }\n' >raw-uri/sub/z.go
//	rec() { (cd "$1" && opengrep scan --config "$OLDPWD/$2" --no-rewrite-rule-ids --disable-version-check --sarif -- . >"$OLDPWD/$1.json"; echo $? >"$OLDPWD/$1.exit"); }
//	rec levels levels.yaml
//	rec suppressed rule.yaml
//	rec raw-uri rule.yaml

// recordingDirs hold the recorded SARIF logs.
var recordingDirs = []string{"testdata", filepath.Join("..", "ruletest", "testdata", "sarif")}

// recordings returns the names of the recorded SARIF logs.
func recordings(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, dir := range recordingDirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			names = append(names, strings.TrimSuffix(filepath.Base(f), ".json"))
		}
	}
	return names
}

// recorded returns the SARIF log recorded as name and opengrep's exit code.
func recorded(t *testing.T, name string) ([]byte, int) {
	t.Helper()
	for _, dir := range recordingDirs {
		data, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			t.Fatal(err)
		}
		exit, err := os.ReadFile(filepath.Join(dir, name+".exit"))
		if err != nil {
			t.Fatal(err)
		}
		code, err := strconv.Atoi(strings.TrimSpace(string(exit)))
		if err != nil {
			t.Fatalf("%s.exit: %v", name, err)
		}
		return data, code
	}
	t.Fatalf("no recording %s", name)
	return nil, 0
}

// decodeRecorded returns the SARIF log recorded as name, decoded.
func decodeRecorded(t *testing.T, name string) *Log {
	t.Helper()
	data, _ := recorded(t, name)
	log, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode(%s.json): %v", name, err)
	}
	return log
}

const testRuleID = "project.go.no-exec-command"

// TestDecodeRecorded pins down what opengrep reports in each recorded run,
// which classifying a rule test's run and reading a scan's findings rely on.
func TestDecodeRecorded(t *testing.T) {
	t.Parallel()
	levels := []string{"critical", "error", "high", "info", "low", "medium", "warning"}
	for i, l := range levels {
		levels[i] = "project.generic." + l
	}
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
		{"levels", 0, levels, 7, nil},
		{"suppressed", 0, []string{testRuleID}, 5, nil},
		{"raw-uri", 0, []string{testRuleID}, 5, nil},
	}
	var names []string
	for _, tt := range tests {
		names = append(names, tt.name)
		t.Run(tt.name, func(t *testing.T) {
			data, code := recorded(t, tt.name)
			log, err := Decode(data)
			if err != nil {
				t.Fatalf("Decode(%s.json): %v", tt.name, err)
			}
			if err := Check(data); err != nil {
				t.Errorf("Check(%s.json) = %v, want nil", tt.name, err)
			}
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
			// opengrep 1.30.2 calls every run successful, even one that
			// exits 2, 7 or 8 after reporting errors.
			if !log.Complete() {
				t.Errorf("%s: Complete() = false, want true", tt.name)
			}
			// It sets no level on results, and gives each a location, a
			// snippet and a fingerprint.
			for i, r := range run.Results {
				if r.Level != "" || len(r.Locations) != 1 || r.Locations[0].PhysicalLocation.Region.Snippet.Text == "" || r.Fingerprints[fingerprintKey] == "" {
					t.Errorf("%s: result %d has level %q, %d locations, fingerprints %q", tt.name, i+1, r.Level, len(r.Locations), r.Fingerprints)
				}
			}
		})
	}
	slices.Sort(names)
	if got := recordings(t); !slices.Equal(slices.Sorted(slices.Values(got)), names) {
		t.Errorf("recordings %q, want %q", got, names)
	}
}

func TestDecodeErrors(t *testing.T) {
	t.Parallel()
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
			log, err := Decode([]byte(tt.data))
			if log != nil || err == nil || !strings.HasPrefix(err.Error(), tt.err) {
				t.Errorf("Decode(%q) = %v, %v; want nil, %q...", tt.data, log, err, tt.err)
			}
			if err := Check([]byte(tt.data)); err == nil || !strings.HasPrefix(err.Error(), tt.err) {
				t.Errorf("Check(%q) = %v, want %q...", tt.data, err, tt.err)
			}
		})
	}
	if err := Check([]byte(`{"version":"2.1.0","runs":[{}]}` + "\n")); err != nil {
		t.Errorf("Check of a minimal log = %v, want nil", err)
	}
}
