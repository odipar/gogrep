package sarif

import (
	"bytes"
	"encoding/json"
	"testing"
)

// rebrandBefore is how gogrep rebranded SARIF before Rebrand existed
// (cmd/gogrep/sarif.go at 822e34a). Rebrand's output must stay byte for
// byte the same, since users diff and archive gogrep scan --sarif output.
func rebrandBefore(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var log map[string]any
	if err := dec.Decode(&log); err != nil {
		return nil, err
	}
	runs, _ := log["runs"].([]any)
	for _, r := range runs {
		run, _ := r.(map[string]any)
		tool, _ := run["tool"].(map[string]any)
		if driver, ok := tool["driver"].(map[string]any); ok {
			driver["name"] = "gogrep"
		}
	}
	return json.Marshal(log)
}

func TestRebrandRecorded(t *testing.T) {
	t.Parallel()
	for _, name := range recordings(t) {
		data, _ := recorded(t, name)
		got, err := Rebrand(data)
		want, wantErr := rebrandBefore(data)
		if err != nil || wantErr != nil || !bytes.Equal(got, want) {
			t.Errorf("Rebrand(%s.json) = %v, %s\nwant %v, %s", name, err, got, wantErr, want)
			continue
		}
		log := decodeRecorded(t, name)
		rebranded, err := Decode(got)
		if err != nil {
			t.Fatalf("Decode(Rebrand(%s.json)): %v", name, err)
		}
		if n := rebranded.Runs[0]; len(n.Results) != len(log.Runs[0].Results) || describe(rebranded.Findings()) != describe(log.Findings()) {
			t.Errorf("Rebrand(%s.json) changed the results", name)
		}
	}
}

func TestRebrand(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, in, want string }{
		{"every run's driver; sorted keys; <, > and & escaped; numbers as written",
			`{"version":"2.1.0","$schema":"s","runs":[` +
				`{"tool":{"driver":{"name":"Opengrep OSS","rules":[{"id":"a<b>&c","x":1.50e3}]}},"results":[]},` +
				`{"tool":{"driver":{"version":"1"}}},` +
				`{"tool":{}},{"tool":"x"},{}]}` + "\n",
			`{"$schema":"s","runs":[` +
				`{"results":[],"tool":{"driver":{"name":"gogrep","rules":[{"id":"a\u003cb\u003e\u0026c","x":1.50e3}]}}},` +
				`{"tool":{"driver":{"name":"gogrep","version":"1"}}},` +
				`{"tool":{}},{"tool":"x"},{}],"version":"2.1.0"}`},
		{"no runs", `{"version":"2.1.0"}`, `{"version":"2.1.0"}`},
		{"runs not a list", `{"runs":{"tool":{"driver":{}}}}`, `{"runs":{"tool":{"driver":{}}}}`},
		{"what follows the first value is dropped", `{"runs":[]} trailing`, `{"runs":[]}`},
		{"null", `null`, `null`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Rebrand([]byte(tt.in))
			if err != nil || string(got) != tt.want {
				t.Errorf("Rebrand(%s) = %s, %v; want %s", tt.in, got, err, tt.want)
			}
			if before, _ := rebrandBefore([]byte(tt.in)); !bytes.Equal(got, before) {
				t.Errorf("Rebrand(%s) = %s, but before it was %s", tt.in, got, before)
			}
		})
	}
	for _, in := range []string{"", "Opengrep crashed\n", "[]", `"x"`, `{"runs":[}`} {
		if got, err := Rebrand([]byte(in)); err == nil {
			t.Errorf("Rebrand(%q) = %s, want an error", in, got)
		}
	}
}
